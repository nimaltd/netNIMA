//! The session commands the UI calls, for UDP, TCP clients and servers, and
//! recordings played back; the sessions they run; and the log file and
//! recording each can write.
//!
//! What a session receives goes to the UI on a channel of its own, as binary
//! frames: one byte of flags (1 for bytes this end sent, which a recording
//! played back has), the peer's number as 4 bytes, the time as an 8-byte
//! float of ms since 1970, all little-endian, then the bytes. Everything
//! else goes as events.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use netnima_core::lines::{self, LineSplitter};
use netnima_core::logfile::{LogSetup, Logger};
use netnima_core::net::{
    self, Agreed, DtlsOptions, DtlsSession, Event, NetState, Peer, PeerId, Target, TcpClient,
    TcpClientConfig, TcpServer, TcpServerConfig, Timing, UdpConfig, UdpSession,
};
use netnima_core::proto::{self, ProtocolHelp, ProtocolSession, SocketSetup};
use netnima_core::record::{self, Direction, Recorder};
use netnima_core::replay::{self, Player};
use netnima_core::send::{self, Pace, Stopped};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Manager, State};

/// A running session of any kind.
enum Running {
    Udp(UdpSession),
    Dtls(DtlsSession),
    Client(TcpClient),
    Server(TcpServer),
    /// A protocol tab: what is typed are its commands.
    Protocol(ProtocolSession),
    Replay(Player),
}

impl Running {
    /// Whether bytes can be sent: not to a recording.
    fn takes_input(&self) -> bool {
        !matches!(self, Running::Replay(_))
    }

    fn write(&self, target: Target, data: Vec<u8>) {
        match self {
            Running::Udp(session) => session.send(target, data),
            Running::Dtls(session) => session.send(target, data),
            Running::Client(client) => client.write(data),
            Running::Server(server) => server.write(target, data),
            Running::Protocol(session) => session.typed(data),
            Running::Replay(_) => {}
        }
    }
}

/// A session's log and recording, and what they need to know of its peers,
/// shared between its thread and the commands.
#[derive(Default)]
struct LogState {
    logger: Option<Logger>,
    recorder: Option<Recorder>,
    /// What the session is connected to now, for the first line of a log
    /// turned on while it runs.
    connected_to: Option<String>,
    /// The address of each peer, by its number.
    peers: HashMap<PeerId, String>,
    /// Whether the session's data comes in datagrams, each its own line in a text log.
    datagrams: bool,
    /// Whether the log and the recording name the peer of each piece: on a
    /// server and a UDP tab, which hear from many.
    many_peers: bool,
}

type SharedLog = Arc<Mutex<LogState>>;

fn lock_log(log: &SharedLog) -> MutexGuard<'_, LogState> {
    log.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running session and its log.
struct Entry {
    running: Running,
    log: SharedLog,
    /// Set while a file is being sent; setting the flag stops it.
    sending: Option<Arc<AtomicBool>>,
}

/// The running sessions, by the number the UI gave each.
#[derive(Default)]
pub struct Sessions(Mutex<HashMap<u32, Entry>>);

impl Sessions {
    fn lock(&self) -> MutexGuard<'_, HashMap<u32, Entry>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `action` on a session, if it is running.
    fn with(&self, id: u32, action: impl FnOnce(&Running)) {
        if let Some(entry) = self.lock().get(&id) {
            action(&entry.running);
        }
    }

    /// Sends bytes through a session, and records them if it records. False
    /// when it is not running, or only plays back.
    fn write(&self, id: u32, target: Target, data: Vec<u8>) -> bool {
        let all = self.lock();
        let Some(entry) = all.get(&id).filter(|entry| entry.running.takes_input()) else {
            return false;
        };
        let mut state = lock_log(&entry.log);
        let peer = match target {
            Target::Peer(peer) if state.many_peers => {
                state.peers.get(&peer).cloned().unwrap_or_default()
            }
            Target::All if state.many_peers => "all".into(),
            _ => String::new(),
        };
        // A recording that cannot be written stops.
        if let Some(recorder) = &mut state.recorder
            && recorder.data(Direction::Sent, &peer, &data).is_err()
        {
            state.recorder = None;
        }
        drop(state);
        entry.running.write(target, data);
        true
    }

    /// Closes the session with this number, if one runs, before a new one
    /// takes it: the new one may want the same port. Closing can take a
    /// moment, so it happens after the lock is let go.
    fn close_before(&self, id: u32) {
        let old = self.lock().remove(&id);
        drop(old);
    }

    /// Adds a session. One with the same number is replaced; closing it can
    /// take a moment, so it happens after the lock is let go.
    fn insert(&self, id: u32, running: Running, log: SharedLog) {
        let entry = Entry {
            running,
            log,
            sending: None,
        };
        let old = self.lock().insert(id, entry);
        drop(old);
    }
}

/// What a session tells the UI, apart from the data it receives.
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEvent {
    State(NetState),
    PeerJoined(Peer),
    PeerLeft {
        peer: PeerId,
    },
    /// Something went wrong that does not end the session, such as a
    /// datagram that could not be sent.
    Problem {
        problem: String,
    },
    /// A peer's TLS handshake ended well: what the two ends agreed.
    Secure {
        peer: PeerId,
        agreed: Agreed,
    },
    /// The lines of text the last bytes from a peer finished, for the Lines
    /// view and the plot, with when those bytes were read: ms since 1970.
    TextLines {
        peer: PeerId,
        lines: Vec<lines::Line>,
        at: f64,
        /// Whether this end sent them, as a recording played back has.
        sent: bool,
    },
    /// A recording plays from the start again: what it showed goes.
    Restarted,
    ReplayState(replay::PlayState),
    /// Writing the recording failed, so it stopped.
    RecordingStopped {
        problem: String,
    },
    /// Writing the log failed, so it was turned off.
    LogStopped {
        problem: String,
    },
    /// What a protocol's engine tells its view, such as an MQTT message
    /// that came: an object with a `type`.
    Report {
        report: serde_json::Value,
    },
}

/// Whether a log is being written, and where; or why it could not start.
/// The same for a recording.
#[derive(Clone, Default, Serialize)]
pub struct LogStatus {
    path: Option<String>,
    problem: Option<String>,
}

/// Now, in ms since 1970, as the page keeps time.
fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |since| since.as_secs_f64() * 1000.0)
}

/// One piece of data as the UI's data channel carries it.
fn frame(sent: bool, peer: PeerId, at: f64, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(13 + bytes.len());
    out.push(u8::from(sent));
    out.extend_from_slice(&peer.to_le_bytes());
    out.extend_from_slice(&at.to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

/// The folder logs go to when the settings leave it empty: "netNIMA logs" in Documents.
fn default_folder(app: &AppHandle) -> PathBuf {
    let documents = app
        .path()
        .document_dir()
        .or_else(|_| app.path().home_dir())
        .unwrap_or_else(|_| PathBuf::from("."));
    documents.join("netNIMA logs")
}

/// Starts a log for a session, if the UI asked for one.
fn start_log(
    app: &AppHandle,
    setup: Option<LogSetup>,
    connected_to: Option<&str>,
) -> (Option<Logger>, LogStatus) {
    let Some(mut setup) = setup else {
        return (None, LogStatus::default());
    };
    if setup.folder.as_os_str().is_empty() {
        setup.folder = default_folder(app);
    }
    let started = Logger::create(&setup).and_then(|mut logger| {
        if let Some(what) = connected_to {
            logger.connected(what)?;
        }
        Ok(logger)
    });
    match started {
        Ok(logger) => {
            let path = Some(logger.path().display().to_string());
            (
                Some(logger),
                LogStatus {
                    path,
                    problem: None,
                },
            )
        }
        Err(error) => (
            None,
            LogStatus {
                path: None,
                problem: Some(format!(
                    "Could not start a log in {}: {error}",
                    setup.folder.display()
                )),
            },
        ),
    }
}

/// Writes to a session's log. A failed write turns the log off and tells the UI why.
fn write_log(
    log: &SharedLog,
    events: &Channel<SessionEvent>,
    write: impl FnOnce(&mut LogState) -> io::Result<()>,
) {
    let mut state = lock_log(log);
    if let Err(error) = write(&mut state) {
        let path = state
            .logger
            .as_ref()
            .map(|logger| logger.path().display().to_string())
            .unwrap_or_default();
        state.logger = None;
        let _ = events.send(SessionEvent::LogStopped {
            problem: format!("Logging stopped: could not write {path}: {error}"),
        });
    }
}

/// Writes to a session's recording. A failed write stops it and tells the UI why.
fn write_record(
    log: &SharedLog,
    events: &Channel<SessionEvent>,
    write: impl FnOnce(&mut Recorder) -> io::Result<()>,
) {
    let mut state = lock_log(log);
    let Some(recorder) = &mut state.recorder else {
        return;
    };
    if let Err(error) = write(recorder) {
        let path = recorder.path().display().to_string();
        state.recorder = None;
        let _ = events.send(SessionEvent::RecordingStopped {
            problem: format!("Recording stopped: could not write {path}: {error}"),
        });
    }
}

/// A new session's shared log, started if the UI asked for one.
fn new_log(
    app: &AppHandle,
    setup: Option<LogSetup>,
    datagrams: bool,
    many_peers: bool,
) -> (SharedLog, LogStatus) {
    let (logger, status) = start_log(app, setup, None);
    let state = LogState {
        logger,
        datagrams,
        many_peers,
        ..LogState::default()
    };
    (Arc::new(Mutex::new(state)), status)
}

/// What a session does with what its socket tells: keeps its log and
/// recording, cuts lines, and passes it all on to the UI.
struct Handler {
    log: SharedLog,
    data: Channel<InvokeResponseBody>,
    events: Channel<SessionEvent>,
    /// Each peer's lines, cut from its own stream.
    splitters: HashMap<PeerId, LineSplitter>,
}

impl Handler {
    fn new(
        log: SharedLog,
        data: Channel<InvokeResponseBody>,
        events: Channel<SessionEvent>,
    ) -> Self {
        Self {
            log,
            data,
            events,
            splitters: HashMap::new(),
        }
    }

    fn handle(&mut self, event: Event) {
        // A send only fails when the window is gone, and then nobody is listening.
        let _ = match event {
            Event::Data { peer, bytes } => {
                self.received(peer, &bytes);
                Ok(())
            }
            Event::State(state) => {
                let connected_to = match &state {
                    NetState::Connected { address, .. } => Some(address.clone()),
                    NetState::Listening { local } => Some(format!("listening on {local}")),
                    NetState::Waiting { .. } | NetState::Ended { .. } => None,
                };
                let note = match &connected_to {
                    Some(what) => format!("connected to {what}"),
                    None => "disconnected".to_string(),
                };
                write_record(&self.log, &self.events, |recorder| recorder.note(&note));
                write_log(&self.log, &self.events, |state| {
                    state.connected_to = connected_to.clone();
                    match (&mut state.logger, connected_to) {
                        (Some(logger), Some(what)) => logger.connected(&what),
                        (Some(logger), None) => logger.disconnected(),
                        (None, _) => Ok(()),
                    }
                });
                self.events.send(SessionEvent::State(state))
            }
            Event::PeerJoined(peer) => {
                lock_log(&self.log)
                    .peers
                    .insert(peer.id, peer.address.clone());
                let note = format!("{} came", peer.address);
                write_record(&self.log, &self.events, |recorder| recorder.note(&note));
                self.events.send(SessionEvent::PeerJoined(peer))
            }
            Event::PeerLeft(peer) => {
                self.splitters.remove(&peer);
                let address = lock_log(&self.log).peers.remove(&peer).unwrap_or_default();
                let note = format!("{address} went");
                write_record(&self.log, &self.events, |recorder| recorder.note(&note));
                self.events.send(SessionEvent::PeerLeft { peer })
            }
            Event::Secure { peer, agreed } => {
                let note = format!(
                    "{} {}, {}",
                    lock_log(&self.log)
                        .peers
                        .get(&peer)
                        .cloned()
                        .unwrap_or_default(),
                    agreed.version,
                    agreed.suite
                );
                write_record(&self.log, &self.events, |recorder| {
                    recorder.note(note.trim())
                });
                self.events.send(SessionEvent::Secure { peer, agreed })
            }
            Event::Problem(problem) => self.events.send(SessionEvent::Problem { problem }),
            Event::Report(report) => self.events.send(SessionEvent::Report { report }),
        };
    }

    /// Received bytes: to the log, the recording, the lines and the UI.
    fn received(&mut self, peer: PeerId, bytes: &[u8]) {
        let at = now_ms();
        let (address, datagrams, many) = {
            let state = lock_log(&self.log);
            (
                state.peers.get(&peer).cloned().unwrap_or_default(),
                state.datagrams,
                state.many_peers,
            )
        };
        let shown = if many { address.as_str() } else { "" };
        write_log(&self.log, &self.events, |state| match &mut state.logger {
            Some(logger) if datagrams => logger.datagram(&address, bytes),
            Some(logger) if many => logger.data_from(&address, bytes),
            Some(logger) => logger.data(bytes),
            None => Ok(()),
        });
        write_record(&self.log, &self.events, |recorder| {
            recorder.data(Direction::Received, shown, bytes)
        });
        let splitter = self.splitters.entry(peer).or_default();
        let mut found = splitter.feed(bytes);
        // A datagram is a message of its own: its last line ends with it.
        if datagrams {
            found.extend(splitter.feed(b"\n"));
        }
        if !found.is_empty() {
            let _ = self.events.send(SessionEvent::TextLines {
                peer,
                lines: found,
                at,
                sent: false,
            });
        }
        let _ = self
            .data
            .send(InvokeResponseBody::Raw(frame(false, peer, at, bytes)));
    }
}

/// The computer's network interfaces with their addresses, for the setup dialogs.
#[tauri::command(async)]
pub fn list_interfaces() -> Vec<net::InterfaceInfo> {
    net::interfaces()
}

/// The folder logs go to when the settings leave it empty.
#[tauri::command]
pub fn default_log_folder(app: AppHandle) -> String {
    default_folder(&app).display().to_string()
}

/// Opens a UDP tab's socket. Received datagrams go to `data` as frames, and
/// to the log if `log` asks for one; everything else goes to `events`.
#[tauri::command(async)]
pub fn open_udp_session(
    id: u32,
    config: UdpConfig,
    log: Option<LogSetup>,
    data: Channel<InvokeResponseBody>,
    events: Channel<SessionEvent>,
    app: AppHandle,
    sessions: State<Sessions>,
) -> LogStatus {
    sessions.close_before(id);
    let (shared, status) = new_log(&app, log, true, true);
    let mut handler = Handler::new(shared.clone(), data, events);
    let session = UdpSession::start(config, move |event| handler.handle(event));
    sessions.insert(id, Running::Udp(session), shared);
    status
}

/// Starts a DTLS client, which handshakes with the UDP config's remote
/// address, or a DTLS server, with the same channels and log as the others.
#[tauri::command(async)]
#[allow(clippy::too_many_arguments)]
pub fn open_dtls_session(
    id: u32,
    config: UdpConfig,
    dtls: DtlsOptions,
    client: bool,
    log: Option<LogSetup>,
    data: Channel<InvokeResponseBody>,
    events: Channel<SessionEvent>,
    app: AppHandle,
    sessions: State<Sessions>,
) -> LogStatus {
    sessions.close_before(id);
    let (shared, status) = new_log(&app, log, true, !client);
    let mut handler = Handler::new(shared.clone(), data, events);
    let session = DtlsSession::start(config, dtls, client, move |event| handler.handle(event));
    sessions.insert(id, Running::Dtls(session), shared);
    status
}

/// Starts a TCP or Telnet client, with the same channels and log as the others.
/// `at_once` passes what comes on as it comes, not gathered for the screen,
/// for a view that times it, as the Modbus view does.
#[tauri::command(async)]
#[allow(clippy::too_many_arguments)]
pub fn open_tcp_client_session(
    id: u32,
    config: TcpClientConfig,
    log: Option<LogSetup>,
    at_once: Option<bool>,
    data: Channel<InvokeResponseBody>,
    events: Channel<SessionEvent>,
    app: AppHandle,
    sessions: State<Sessions>,
) -> LogStatus {
    sessions.close_before(id);
    let (shared, status) = new_log(&app, log, false, false);
    let mut handler = Handler::new(shared.clone(), data, events);
    let timing = Timing::of_tab(at_once.unwrap_or(false));
    let client =
        TcpClient::start_with(config, Box::new(move |event| handler.handle(event)), timing);
    sessions.insert(id, Running::Client(client), shared);
    status
}

/// Starts a TCP or Telnet server, with the same channels and log as the others,
/// and `at_once` as a client has it.
#[tauri::command(async)]
#[allow(clippy::too_many_arguments)]
pub fn open_tcp_server_session(
    id: u32,
    config: TcpServerConfig,
    log: Option<LogSetup>,
    at_once: Option<bool>,
    data: Channel<InvokeResponseBody>,
    events: Channel<SessionEvent>,
    app: AppHandle,
    sessions: State<Sessions>,
) -> LogStatus {
    sessions.close_before(id);
    let (shared, status) = new_log(&app, log, false, true);
    let mut handler = Handler::new(shared.clone(), data, events);
    let timing = Timing::of_tab(at_once.unwrap_or(false));
    let server =
        TcpServer::start_with(config, Box::new(move |event| handler.handle(event)), timing);
    sessions.insert(id, Running::Server(server), shared);
    status
}

/// Starts a protocol tab, such as an MQTT client or broker: its socket from
/// `socket`, its engine from `kind` and `options`. What is written to it is
/// taken as commands, a line at a time; every message shows as a line of
/// text, as data from its peer.
#[tauri::command(async)]
#[allow(clippy::too_many_arguments)]
pub fn open_protocol_session(
    id: u32,
    kind: String,
    options: serde_json::Value,
    socket: SocketSetup,
    log: Option<LogSetup>,
    data: Channel<InvokeResponseBody>,
    events: Channel<SessionEvent>,
    app: AppHandle,
    sessions: State<Sessions>,
) -> Result<LogStatus, String> {
    sessions.close_before(id);
    let many_peers = kind.ends_with("_server");
    let (shared, status) = new_log(&app, log, false, many_peers);
    let mut handler = Handler::new(shared.clone(), data, events);
    let session =
        ProtocolSession::start(&kind, options, socket, move |event| handler.handle(event))?;
    sessions.insert(id, Running::Protocol(session), shared);
    Ok(status)
}

/// The commands a kind of protocol tab takes, for its send box to offer;
/// none for a tab with no protocol, such as a plain TCP tab.
#[tauri::command]
pub fn protocol_help(kind: String) -> ProtocolHelp {
    proto::help_for(&kind).unwrap_or_default()
}

#[tauri::command]
pub fn reconfigure_udp_session(id: u32, config: UdpConfig, sessions: State<Sessions>) {
    sessions.with(id, |running| {
        if let Running::Udp(session) = running {
            session.reconfigure(config);
        }
    });
}

#[tauri::command]
pub fn reconfigure_tcp_client_session(id: u32, config: TcpClientConfig, sessions: State<Sessions>) {
    sessions.with(id, |running| {
        if let Running::Client(client) = running {
            client.reconfigure(config);
        }
    });
}

#[tauri::command]
pub fn reconfigure_tcp_server_session(id: u32, config: TcpServerConfig, sessions: State<Sessions>) {
    sessions.with(id, |running| {
        if let Running::Server(server) = running {
            server.reconfigure(config);
        }
    });
}

/// Sends bytes through a session: to a client's server, a UDP tab's remote
/// address, one peer, or all. Not async, so key presses go out in the order typed.
#[tauri::command]
pub fn write_session(id: u32, target: Target, data: Vec<u8>, sessions: State<Sessions>) -> bool {
    sessions.write(id, target, data)
}

/// Ends one peer's connection on a server, with a reset when `reset`; a
/// client's own connection, by its reset, with no peer.
#[tauri::command]
pub fn drop_peer(id: u32, peer: Option<PeerId>, reset: bool, sessions: State<Sessions>) {
    sessions.with(id, |running| match (running, peer) {
        (Running::Server(server), Some(peer)) => server.drop_peer(peer, reset),
        (Running::Client(client), _) => client.reset(),
        _ => {}
    });
}

#[tauri::command(async)]
pub fn close_session(id: u32, sessions: State<Sessions>) {
    let old = sessions.lock().remove(&id);
    drop(old);
}

/// Closes every session. The UI calls it when it loads, so a reload never
/// leaves a session holding its port.
#[tauri::command(async)]
pub fn close_all_sessions(sessions: State<Sessions>) {
    let old = std::mem::take(&mut *sessions.lock());
    drop(old);
}

/// Closes every session as the app ends.
pub fn close_all(app: &AppHandle) {
    let old = std::mem::take(&mut *app.state::<Sessions>().lock());
    drop(old);
}

/// Turns a running session's log on with `log`, or off without it. A log
/// turned on starts a new file.
#[tauri::command(async)]
pub fn set_log(
    id: u32,
    log: Option<LogSetup>,
    app: AppHandle,
    sessions: State<Sessions>,
) -> LogStatus {
    let Some(shared) = sessions.lock().get(&id).map(|entry| entry.log.clone()) else {
        return LogStatus::default();
    };
    let connected_to = lock_log(&shared).connected_to.clone();
    let (logger, status) = start_log(&app, log, connected_to.as_deref());
    lock_log(&shared).logger = logger;
    status
}

/// Starts recording a running session to a new file in `folder` (empty for
/// the log folder), or stops it without a folder. A recording keeps every
/// byte received and sent with its time and peer, to play back later.
#[tauri::command(async)]
pub fn set_recording(
    id: u32,
    folder: Option<String>,
    name: String,
    app: AppHandle,
    sessions: State<Sessions>,
) -> LogStatus {
    let Some(shared) = sessions.lock().get(&id).map(|entry| entry.log.clone()) else {
        return LogStatus {
            path: None,
            problem: Some("Connect first, then record.".into()),
        };
    };
    let Some(folder) = folder else {
        lock_log(&shared).recorder = None;
        return LogStatus::default();
    };
    let folder = if folder.is_empty() {
        default_folder(&app)
    } else {
        PathBuf::from(folder)
    };
    let connected_to = lock_log(&shared).connected_to.clone();
    let started = Recorder::create(&folder, &name).and_then(|mut recorder| {
        if let Some(what) = connected_to {
            recorder.note(&format!("connected to {what}"))?;
        }
        Ok(recorder)
    });
    match started {
        Ok(recorder) => {
            let path = Some(recorder.path().display().to_string());
            lock_log(&shared).recorder = Some(recorder);
            LogStatus {
                path,
                problem: None,
            }
        }
        Err(error) => LogStatus {
            path: None,
            problem: Some(format!(
                "Could not start a recording in {}: {error}",
                folder.display()
            )),
        },
    }
}

/// What the UI learns of a recording it opens.
#[derive(Clone, Serialize)]
pub struct ReplayInfo {
    /// The name of the tab it was recorded from.
    name: String,
    /// How long it plays, in seconds.
    length: f64,
}

/// Opens a recording to play back, paused at its start. What it received
/// and sent comes to `data` as frames, with its peers and lines to
/// `events`, as a live session's do.
#[tauri::command(async)]
pub fn open_replay_session(
    id: u32,
    path: String,
    speed: f64,
    data: Channel<InvokeResponseBody>,
    events: Channel<SessionEvent>,
    sessions: State<Sessions>,
) -> Result<ReplayInfo, String> {
    let recording = record::read(std::path::Path::new(&path))?;
    let info = ReplayInfo {
        name: recording.name.clone(),
        length: recording.length(),
    };
    // Pieces keep the time they were recorded at, so the plot shows it, at any speed.
    let started = recording.started_ms.unwrap_or_else(now_ms);
    let mut peers: HashMap<String, PeerId> = HashMap::new();
    let mut splitters: HashMap<(PeerId, bool), LineSplitter> = HashMap::new();
    let player = Player::start(recording, speed, move |event| {
        let _ = match event {
            replay::Event::Chunks(chunks) => {
                for chunk in chunks {
                    let sent = chunk.direction == Direction::Sent;
                    let at = started + chunk.at * 1000.0;
                    let next = peers.len() as PeerId + 1;
                    let peer = *peers.entry(chunk.peer.clone()).or_insert_with(|| {
                        let address = if chunk.peer.is_empty() {
                            "the other end".to_string()
                        } else {
                            chunk.peer.clone()
                        };
                        let _ = events.send(SessionEvent::PeerJoined(Peer { id: next, address }));
                        next
                    });
                    let found = splitters
                        .entry((peer, sent))
                        .or_default()
                        .feed(&chunk.bytes);
                    if !found.is_empty() {
                        let _ = events.send(SessionEvent::TextLines {
                            peer,
                            lines: found,
                            at,
                            sent,
                        });
                    }
                    let _ = data.send(InvokeResponseBody::Raw(frame(sent, peer, at, &chunk.bytes)));
                }
                Ok(())
            }
            replay::Event::Restarted => {
                splitters.clear();
                events.send(SessionEvent::Restarted)
            }
            replay::Event::State(state) => events.send(SessionEvent::ReplayState(state)),
        };
    });
    sessions.insert(id, Running::Replay(player), Arc::default());
    Ok(info)
}

/// What the UI asks of a recording being played.
#[derive(Clone, Copy, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplayCommand {
    Play,
    Pause,
    Speed { speed: f64 },
    Seek { position: f64 },
}

#[tauri::command]
pub fn control_replay(id: u32, command: ReplayCommand, sessions: State<Sessions>) {
    sessions.with(id, |running| {
        if let Running::Replay(player) = running {
            match command {
                ReplayCommand::Play => player.play(),
                ReplayCommand::Pause => player.pause(),
                ReplayCommand::Speed { speed } => player.set_speed(speed),
                ReplayCommand::Seek { position } => player.seek(position),
            }
        }
    });
}

/// Writes text to a file the user chose, such as the lines as CSV.
#[tauri::command(async)]
pub fn save_text(path: String, text: String) -> Result<(), String> {
    std::fs::write(&path, text).map_err(|error| format!("Could not save {path}: {error}"))
}

/// Writes bytes to a file the user chose, such as a chart as a PNG.
#[tauri::command(async)]
pub fn save_bytes(path: String, data: Vec<u8>) -> Result<(), String> {
    std::fs::write(&path, data).map_err(|error| format!("Could not save {path}: {error}"))
}

/// Turns what the send box or a macro holds into bytes: hex digits, or text
/// with escapes such as `\r`. An error says what is wrong in plain words.
#[tauri::command]
pub fn encode_input(text: String, hex: bool) -> Result<Vec<u8>, String> {
    send::encode(&text, hex)
}

/// How sending a file goes, as the UI sees it.
#[derive(Clone, Serialize)]
pub struct FileProgress {
    sent: u64,
    total: u64,
    /// Set on the last report, when sending has ended one way or another.
    done: bool,
    cancelled: bool,
    problem: Option<String>,
}

/// Starts sending a file through a running session, to `target`, and returns
/// its size. On a stream it goes in pieces paced for `bytes_per_second` (0
/// for as fast as it takes them); on UDP in datagrams of `datagram` bytes.
/// How it goes is reported to `progress`, a few times a second.
#[tauri::command(async)]
#[allow(clippy::too_many_arguments)]
pub fn send_file(
    id: u32,
    target: Target,
    path: String,
    bytes_per_second: u32,
    datagram: u32,
    progress: Channel<FileProgress>,
    app: AppHandle,
    sessions: State<Sessions>,
) -> Result<u64, String> {
    let data = std::fs::read(&path).map_err(|error| format!("Could not read {path}: {error}"))?;
    let total = data.len() as u64;
    let cancel = Arc::new(AtomicBool::new(false));
    let pace = {
        let mut all = sessions.lock();
        let entry = all.get_mut(&id).ok_or("The tab is not open.")?;
        if !entry.running.takes_input() {
            return Err("A recording being played cannot send.".into());
        }
        if entry.sending.is_some() {
            return Err("A file is being sent already.".into());
        }
        entry.sending = Some(cancel.clone());
        if matches!(entry.running, Running::Udp(_) | Running::Dtls(_)) {
            Pace::for_datagrams(datagram as usize, bytes_per_second)
        } else {
            Pace::for_rate(bytes_per_second)
        }
    };

    thread::Builder::new()
        .name("netnima-send-file".into())
        .spawn(move || {
            let sessions = app.state::<Sessions>();
            let mut sent = 0;
            let mut reported = Instant::now();
            let result = send::send_paced(
                &data,
                pace,
                &cancel,
                |piece| sessions.write(id, target, piece.to_vec()),
                |now| {
                    sent = now as u64;
                    if reported.elapsed() >= Duration::from_millis(100) {
                        reported = Instant::now();
                        let _ = progress.send(FileProgress {
                            sent,
                            total,
                            done: false,
                            cancelled: false,
                            problem: None,
                        });
                    }
                },
            );
            if let Some(entry) = sessions.lock().get_mut(&id)
                && entry
                    .sending
                    .as_ref()
                    .is_some_and(|flag| Arc::ptr_eq(flag, &cancel))
            {
                entry.sending = None;
            }
            let _ = progress.send(FileProgress {
                sent,
                total,
                done: true,
                cancelled: result == Err(Stopped::Cancelled),
                problem: (result == Err(Stopped::Gone))
                    .then(|| "The tab closed before the whole file was sent.".into()),
            });
        })
        .map_err(|error| format!("Could not start sending: {error}"))?;
    Ok(total)
}

/// Stops sending a file, between two pieces.
#[tauri::command]
pub fn cancel_send(id: u32, sessions: State<Sessions>) {
    if let Some(flag) = sessions
        .lock()
        .get(&id)
        .and_then(|entry| entry.sending.as_ref())
    {
        flag.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_carries_its_flags_peer_and_time_before_the_bytes() {
        let bytes = frame(true, 0x0102_0304, 1.5, b"hi");
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..5], &[4, 3, 2, 1]);
        assert_eq!(f64::from_le_bytes(bytes[5..13].try_into().unwrap()), 1.5);
        assert_eq!(&bytes[13..], b"hi");
        assert_eq!(frame(false, 1, 0.0, b"")[0], 0);
    }
}
