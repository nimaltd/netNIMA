//! One TCP, Telnet or TLS server: it listens on its own thread and takes
//! many clients at once, each a peer the app can send to, alone or with the rest.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockRef, Socket, Type};

use super::config::TcpServerConfig;
use super::link::{HANDSHAKE_TIME, Link};
use super::tcp_client::{lost_problem, set_keep_alive};
use super::telnet::Telnet;
use super::tls;
use super::wake::{self, Wake, Waker, raw};
use super::{
    BATCH_MAX, Event, NetState, Peer, PeerId, TIMING, Target, Timing, is_quiet, open_problem,
};

enum Command {
    Write {
        target: Target,
        bytes: Vec<u8>,
    },
    /// Ends one client's connection, with a reset when `reset` is set.
    Drop {
        peer: PeerId,
        reset: bool,
    },
    /// Boxed: the settings are big beside the other commands.
    Reconfigure(Box<TcpServerConfig>),
    /// Sends the bytes to one client as they are, then starts TLS with it.
    StartTls {
        peer: PeerId,
        before: Vec<u8>,
    },
    Close,
}

/// A TCP server tab. Dropping it closes the listener and every client.
pub struct TcpServer {
    commands: Sender<Command>,
    waker: Waker,
    thread: Option<JoinHandle<()>>,
}

impl TcpServer {
    /// Starts listening and keeps at it until the server is dropped, trying
    /// again while the port cannot be opened. Everything that happens comes
    /// back through `on_event`, on the server's own thread.
    pub fn start(config: TcpServerConfig, on_event: impl FnMut(Event) + Send + 'static) -> Self {
        Self::start_with(config, Box::new(on_event), TIMING)
    }

    /// Starts as `start` does, with a timing of its own, such as `Timing::of_tab(true)`.
    pub fn start_with(
        config: TcpServerConfig,
        on_event: Box<dyn FnMut(Event) + Send>,
        timing: Timing,
    ) -> Self {
        let (commands, receiver) = mpsc::channel();
        let (waker, wake) = wake::pair();
        let worker = Worker {
            config,
            on_event,
            commands: receiver,
            wake,
            timing,
            state: None,
            next_peer: 0,
        };
        let thread = thread::Builder::new()
            .name("netnima-tcp-server".into())
            .spawn(move || worker.run())
            .expect("the OS could not start a thread");
        Self {
            commands,
            waker,
            thread: Some(thread),
        }
    }

    /// Sends bytes to one client, to all, or to the one heard from last.
    pub fn write(&self, target: Target, bytes: Vec<u8>) {
        self.tell(Command::Write { target, bytes });
    }

    /// Ends one client's connection, with a reset (RST) instead of a FIN when `reset`.
    pub fn drop_peer(&self, peer: PeerId, reset: bool) {
        self.tell(Command::Drop { peer, reset });
    }

    /// Listens again with new settings. The clients connected go.
    pub fn reconfigure(&self, config: TcpServerConfig) {
        self.tell(Command::Reconfigure(Box::new(config)));
    }

    /// Sends `before` to one client as it is, such as FTP's "234", then
    /// starts TLS with it: the two go together, so the client's first TLS
    /// bytes cannot be read as plain ones. The TLS settings must say `starttls`.
    pub fn start_tls(&self, peer: PeerId, before: Vec<u8>) {
        self.tell(Command::StartTls { peer, before });
    }

    /// Queues a command, and wakes the thread to do it now.
    fn tell(&self, command: Command) {
        let _ = self.commands.send(command);
        self.waker.wake();
    }
}

impl Drop for TcpServer {
    fn drop(&mut self) {
        self.tell(Command::Close);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Why serving ended.
enum Ended {
    Closed,
    Relisten,
}

/// A connected client.
struct Client {
    id: PeerId,
    link: Link,
    telnet: Option<Telnet>,
    pending: Vec<u8>,
    batch_started: Option<Instant>,
    /// Set when the connection has ended, with why when it broke.
    gone: Option<Option<String>>,
}

struct Worker {
    config: TcpServerConfig,
    on_event: Box<dyn FnMut(Event) + Send>,
    commands: Receiver<Command>,
    /// Wakes the thread's wait when a command comes.
    wake: Wake,
    timing: Timing,
    state: Option<NetState>,
    /// The last peer number given: numbers are not used twice in a session.
    next_peer: PeerId,
}

impl Worker {
    fn run(mut self) {
        loop {
            let opened = self
                .tls_config()
                .and_then(|tls| Ok((listen(&self.config)?, tls)));
            match opened {
                Ok((listener, tls)) => match self.serve(&listener, tls.as_ref()) {
                    Ended::Closed => return,
                    Ended::Relisten => continue,
                },
                Err(problem) => {
                    self.set_state(NetState::Waiting {
                        problem: Some(problem),
                    });
                    if !self.wait(self.timing.retry) {
                        return;
                    }
                }
            }
        }
    }

    /// The TLS config, when the server speaks TLS, or what is wrong with its settings.
    fn tls_config(&self) -> Result<Option<tls::ServerSetup>, String> {
        self.config.tls.as_ref().map(tls::server_setup).transpose()
    }

    fn serve(&mut self, listener: &TcpListener, tls: Option<&tls::ServerSetup>) -> Ended {
        let local = listener
            .local_addr()
            .map_or_else(|_| self.config.address.clone(), |at| at.to_string());
        self.set_state(NetState::Listening { local });
        let mut clients: Vec<Client> = Vec::new();
        let mut last_heard: Option<PeerId> = None;
        let mut buf = vec![0; BATCH_MAX];

        let ended = loop {
            if let Some(ended) = self.do_commands(&mut clients, &mut last_heard, tls) {
                break ended;
            }
            let mut busy = self.accept(listener, &mut clients, tls);
            for client in &mut clients {
                busy |= read(client, &mut buf);
                if let Some(last) = client_has_data(client) {
                    last_heard = Some(last);
                }
                if let Some(agreed) = client.link.agreed() {
                    self.emit(Event::Secure {
                        peer: client.id,
                        agreed,
                    });
                }
                if client.gone.is_none() && client.link.handshake_overdue() {
                    client.gone = Some(Some(format!(
                        "it did not end the TLS handshake in {} s: does it speak TLS?",
                        HANDSHAKE_TIME.as_secs()
                    )));
                }
            }
            for client in &mut clients {
                let due = client
                    .batch_started
                    .is_some_and(|start| start.elapsed() >= self.timing.batch);
                if due || client.pending.len() >= BATCH_MAX || client.gone.is_some() {
                    self.flush(client);
                }
            }
            // The clients that went.
            let mut index = 0;
            while index < clients.len() {
                if let Some(problem) = clients[index].gone.clone() {
                    let client = clients.remove(index);
                    if let Some(problem) = problem {
                        self.emit(Event::Problem(format!("Client {}: {problem}", client.id)));
                    }
                    self.emit(Event::PeerLeft(client.id));
                    if last_heard == Some(client.id) {
                        last_heard = None;
                    }
                } else {
                    index += 1;
                }
            }
            // Nothing came: waits for a client to connect or send, for a
            // command, or for bytes held for the screen to be due. After a
            // busy turn it looks again at once: TLS can hold bytes already
            // read from a stream.
            if !busy {
                let mut sockets = Vec::with_capacity(clients.len() + 1);
                sockets.push(raw(listener));
                sockets.extend(clients.iter().map(|client| raw(client.link.stream())));
                let wait = clients
                    .iter()
                    .filter_map(|client| client.batch_started)
                    .map(|start| self.timing.batch.saturating_sub(start.elapsed()))
                    .fold(self.timing.poll, Duration::min);
                if self.wake.wait(&sockets, wait).is_err() {
                    thread::sleep(self.timing.poll);
                }
            }
        };
        for mut client in clients {
            client.link.close();
            self.emit(Event::PeerLeft(client.id));
        }
        ended
    }

    /// Takes every client waiting to connect. Returns whether any came.
    fn accept(
        &mut self,
        listener: &TcpListener,
        clients: &mut Vec<Client>,
        tls: Option<&tls::ServerSetup>,
    ) -> bool {
        let mut came = false;
        loop {
            match listener.accept() {
                Ok((stream, address)) => {
                    came = true;
                    let full = self.config.max_clients != 0
                        && clients.len() >= self.config.max_clients as usize;
                    if full {
                        drop(stream);
                        self.emit(Event::Problem(format!(
                            "{address} was turned away: the server takes {} clients at most.",
                            self.config.max_clients
                        )));
                        continue;
                    }
                    let later = self.config.tls.as_ref().is_some_and(|tls| tls.starttls);
                    let link = self.ready(&stream).and_then(|()| match tls {
                        Some(setup) if !later => Link::server(stream, setup),
                        _ => Ok(Link::plain(stream)),
                    });
                    let link = match link {
                        Ok(link) => link,
                        Err(error) => {
                            self.emit(Event::Problem(format!(
                                "{address} could not be taken: {}",
                                lost_problem(&error)
                            )));
                            continue;
                        }
                    };
                    self.next_peer += 1;
                    let id = self.next_peer;
                    self.emit(Event::PeerJoined(Peer {
                        id,
                        address: address.to_string(),
                    }));
                    clients.push(Client {
                        id,
                        link,
                        telnet: self.config.telnet.then(Telnet::default),
                        pending: Vec::new(),
                        batch_started: None,
                        gone: None,
                    });
                }
                Err(error) if is_quiet(&error) => return came,
                Err(error) => {
                    self.emit(Event::Problem(format!(
                        "A client could not connect: {error}"
                    )));
                    // The client still waits, and the listener says so at
                    // once: not a loop that spins while taking it fails.
                    thread::sleep(self.timing.poll);
                    return came;
                }
            }
        }
    }

    fn ready(&self, stream: &TcpStream) -> io::Result<()> {
        stream.set_nonblocking(true)?;
        stream.set_nodelay(self.config.no_delay)?;
        set_keep_alive(stream, self.config.keep_alive)
    }

    /// Passes a client's waiting bytes on.
    fn flush(&mut self, client: &mut Client) {
        client.batch_started = None;
        if !client.pending.is_empty() {
            let bytes = std::mem::take(&mut client.pending);
            self.emit(Event::Data {
                peer: client.id,
                bytes,
            });
        }
    }

    /// Does what the app asked, until no command is left. Returns why serving
    /// should end, if it should.
    fn do_commands(
        &mut self,
        clients: &mut [Client],
        last_heard: &mut Option<PeerId>,
        tls: Option<&tls::ServerSetup>,
    ) -> Option<Ended> {
        loop {
            let command = match self.commands.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => return Some(Ended::Closed),
            };
            match command {
                Command::Write { target, bytes } => {
                    self.write(clients, *last_heard, target, &bytes)
                }
                Command::Drop { peer, reset } => {
                    if let Some(client) = clients.iter_mut().find(|client| client.id == peer) {
                        if reset {
                            let _ = SockRef::from(client.link.stream())
                                .set_linger(Some(Duration::ZERO));
                        } else {
                            client.link.close();
                        }
                        let _ = client.link.stream().shutdown(std::net::Shutdown::Both);
                        client.gone = Some(None);
                    }
                }
                Command::Reconfigure(config) => {
                    self.config = *config;
                    return Some(Ended::Relisten);
                }
                Command::StartTls { peer, before } => {
                    let Some(client) = clients
                        .iter_mut()
                        .find(|client| client.id == peer && client.gone.is_none())
                    else {
                        continue;
                    };
                    let started = client.link.write_all(&before).and_then(|()| match tls {
                        Some(setup) => client.link.start_server(setup),
                        None => Err(tls::failed(
                            "TLS was asked for, and the tab has no TLS settings.".into(),
                        )),
                    });
                    if let Err(error) = started {
                        client.gone = Some(Some(lost_problem(&error)));
                    }
                }
                Command::Close => return Some(Ended::Closed),
            }
        }
    }

    /// Sends bytes where they should go, and says why when they cannot.
    fn write(
        &mut self,
        clients: &mut [Client],
        last_heard: Option<PeerId>,
        target: Target,
        bytes: &[u8],
    ) {
        let chosen: Vec<PeerId> = match target {
            Target::All => clients.iter().map(|client| client.id).collect(),
            Target::Peer(id) => vec![id],
            Target::Default => match (last_heard, &*clients) {
                (Some(id), _) => vec![id],
                (None, [only]) => vec![only.id],
                (None, []) => {
                    self.emit(Event::Problem(
                        "No client is connected, so nothing was sent.".into(),
                    ));
                    return;
                }
                (None, _) => {
                    self.emit(Event::Problem(
                        "Several clients are connected and none has been heard from: choose one, or All.".into(),
                    ));
                    return;
                }
            },
        };
        for id in chosen {
            let Some(client) = clients
                .iter_mut()
                .find(|client| client.id == id && client.gone.is_none())
            else {
                self.emit(Event::Problem(format!(
                    "Client {id} is gone, so nothing was sent to it."
                )));
                continue;
            };
            let data = match &client.telnet {
                Some(telnet) => telnet.encode(bytes),
                None => bytes.to_vec(),
            };
            if let Err(error) = client.link.write_all(&data) {
                client.gone = Some(Some(lost_problem(&error)));
            }
        }
    }

    /// Waits while the port cannot be opened, still doing what the app asks.
    /// Returns false when the server should end.
    fn wait(&mut self, time: Duration) -> bool {
        let until = Instant::now() + time;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            match self.commands.recv_timeout(left) {
                Err(RecvTimeoutError::Timeout) => return true,
                Ok(Command::Close) | Err(RecvTimeoutError::Disconnected) => return false,
                Ok(Command::Reconfigure(config)) => {
                    self.config = *config;
                    return true;
                }
                Ok(Command::Write { .. }) => self.emit(Event::Problem(
                    "The server is not listening, so nothing was sent.".into(),
                )),
                Ok(Command::Drop { .. } | Command::StartTls { .. }) => {}
            }
        }
    }

    fn set_state(&mut self, state: NetState) {
        if self.state.as_ref() != Some(&state) {
            self.state = Some(state.clone());
            self.emit(Event::State(state));
        }
    }

    fn emit(&mut self, event: Event) {
        (self.on_event)(event);
    }
}

/// Reads what a client sent, until nothing is left for now. Returns whether anything came.
fn read(client: &mut Client, buf: &mut [u8]) -> bool {
    if client.gone.is_some() {
        return false;
    }
    let mut came = false;
    let mut reply = Vec::new();
    loop {
        match client.link.read(buf) {
            Ok(0) => {
                client.gone = Some(None);
                break;
            }
            Ok(count) => {
                came = true;
                match &mut client.telnet {
                    Some(telnet) => telnet.receive(&buf[..count], &mut client.pending, &mut reply),
                    None => client.pending.extend_from_slice(&buf[..count]),
                }
                if client.pending.len() >= BATCH_MAX {
                    break;
                }
            }
            Err(error) if is_quiet(&error) => break,
            Err(error) => {
                client.gone = Some(Some(lost_problem(&error)));
                break;
            }
        }
    }
    if !reply.is_empty()
        && let Err(error) = client.link.write_all(&reply)
    {
        client.gone = Some(Some(lost_problem(&error)));
    }
    if !client.pending.is_empty() {
        client.batch_started.get_or_insert_with(Instant::now);
    }
    came
}

/// The client's number when it has bytes waiting, as the one heard from last.
fn client_has_data(client: &Client) -> Option<PeerId> {
    (!client.pending.is_empty()).then_some(client.id)
}

/// Opens the listening socket, or says why it cannot.
fn listen(config: &TcpServerConfig) -> Result<TcpListener, String> {
    if let Some(problem) = config.problem() {
        return Err(problem);
    }
    let local = config.local()?;
    let shown = local.to_string();
    let fail = |error: io::Error| open_problem(&shown, &error);
    let socket = Socket::new(
        Domain::for_address(local),
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(fail)?;
    // A server started again at once finds its port still held for a moment
    // on Linux and macOS. On Windows the option means something else: another
    // program could take the port, so it stays off there.
    #[cfg(not(windows))]
    socket.set_reuse_address(true).map_err(fail)?;
    socket.bind(&local.into()).map_err(fail)?;
    socket.listen(128).map_err(fail)?;
    let listener: TcpListener = socket.into();
    listener.set_nonblocking(true).map_err(fail)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;
    use crate::net::tests::{AT_ONCE, FAST, SLOW_POLL, expect, joined, received, state};

    fn start(config: TcpServerConfig) -> (TcpServer, Receiver<Event>, u16) {
        start_timed(config, FAST)
    }

    fn start_timed(config: TcpServerConfig, timing: Timing) -> (TcpServer, Receiver<Event>, u16) {
        let (sender, events) = mpsc::channel();
        let server = TcpServer::start_with(
            config,
            Box::new(move |event| {
                let _ = sender.send(event);
            }),
            timing,
        );
        let local = match state(&events, "listening", |state| {
            matches!(state, NetState::Listening { .. })
        }) {
            NetState::Listening { local } => local,
            _ => unreachable!(),
        };
        let port = local.rsplit(':').next().unwrap().parse().unwrap();
        (server, events, port)
    }

    /// A server on the loopback, on a port the OS gives it. A port found free
    /// and let go could be taken by a test running beside this one.
    fn config() -> TcpServerConfig {
        TcpServerConfig {
            address: "127.0.0.1".into(),
            port: 0,
            ..TcpServerConfig::default()
        }
    }

    fn client(port: u16) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    fn read_some(stream: &mut TcpStream, count: usize) -> Vec<u8> {
        let mut data = vec![0; count];
        stream.read_exact(&mut data).unwrap();
        data
    }

    fn problem(events: &Receiver<Event>) -> String {
        match expect(events, "problem", |event| {
            matches!(event, Event::Problem(_))
        }) {
            Event::Problem(problem) => problem,
            _ => unreachable!(),
        }
    }

    #[test]
    fn what_is_written_and_what_comes_go_at_once() {
        let (server, events, port) = start_timed(config(), SLOW_POLL);
        let mut first = client(port);
        let one = joined(&events);
        // The thread is in its long wait: each write has to wake it.
        thread::sleep(Duration::from_millis(50));
        for _ in 0..3 {
            let start = Instant::now();
            server.write(Target::Peer(one.id), b"x".to_vec());
            assert_eq!(read_some(&mut first, 1), b"x");
            assert!(start.elapsed() < AT_ONCE, "{:?}", start.elapsed());
        }
        // A second client, and what it sends, wake it too.
        let start = Instant::now();
        let mut second = client(port);
        let two = joined(&events);
        second.write_all(b"y").unwrap();
        assert_eq!(received(&events, two.id, 1), b"y");
        assert!(start.elapsed() < AT_ONCE, "{:?}", start.elapsed());
    }

    #[test]
    fn clients_are_peers_that_send_and_are_sent_to() {
        let (server, events, port) = start(config());
        let mut first = client(port);
        let one = joined(&events);
        assert_eq!(one.address, first.local_addr().unwrap().to_string());
        let mut second = client(port);
        let two = joined(&events);

        first.write_all(b"from one").unwrap();
        assert_eq!(received(&events, one.id, 8), b"from one");
        second.write_all(b"from two").unwrap();
        assert_eq!(received(&events, two.id, 8), b"from two");

        // Without a choice it answers the one heard from last.
        server.write(Target::Default, b"to two".to_vec());
        assert_eq!(read_some(&mut second, 6), b"to two");
        server.write(Target::Peer(one.id), b"to one".to_vec());
        assert_eq!(read_some(&mut first, 6), b"to one");
        server.write(Target::All, b"all".to_vec());
        assert_eq!(read_some(&mut first, 3), b"all");
        assert_eq!(read_some(&mut second, 3), b"all");
    }

    #[test]
    fn a_client_that_goes_is_told_and_one_dropped_sees_the_end() {
        let (server, events, port) = start(config());
        let first = client(port);
        let one = joined(&events);
        drop(first);
        assert_eq!(
            expect(&events, "left", |event| matches!(event, Event::PeerLeft(_))),
            Event::PeerLeft(one.id)
        );

        let mut second = client(port);
        let two = joined(&events);
        server.drop_peer(two.id, false);
        let mut buf = [0; 4];
        assert_eq!(second.read(&mut buf).unwrap(), 0);
        assert_eq!(
            expect(&events, "left", |event| matches!(event, Event::PeerLeft(_))),
            Event::PeerLeft(two.id)
        );
    }

    #[test]
    fn one_client_too_many_is_turned_away() {
        let (_server, events, port) = start(TcpServerConfig {
            max_clients: 1,
            ..config()
        });
        let _first = client(port);
        joined(&events);
        let mut second = client(port);
        assert!(problem(&events).contains("turned away"));
        let mut buf = [0; 4];
        let read = second.read(&mut buf);
        assert!(matches!(read, Ok(0)) || read.is_err(), "{read:?}");
    }

    #[test]
    fn with_several_clients_and_none_heard_it_asks_which() {
        let (server, events, port) = start(config());
        let _first = client(port);
        joined(&events);
        let _second = client(port);
        joined(&events);
        server.write(Target::Default, b"who?".to_vec());
        assert!(problem(&events).contains("choose one"));
    }

    #[test]
    fn telnet_clients_get_their_options_answered() {
        let (_server, events, port) = start(TcpServerConfig {
            telnet: true,
            ..config()
        });
        let mut stream = client(port);
        let peer = joined(&events);
        // IAC DO ECHO: this end does not echo, and says so.
        stream.write_all(&[255, 253, 1]).unwrap();
        stream.write_all(b"hi").unwrap();
        assert_eq!(received(&events, peer.id, 2), b"hi");
        assert_eq!(read_some(&mut stream, 3), [255, 252, 1]);
    }

    #[test]
    fn a_port_in_use_is_said_in_words() {
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let (sender, events) = mpsc::channel();
        let _server = TcpServer::start_with(
            TcpServerConfig {
                address: "127.0.0.1".into(),
                port,
                ..TcpServerConfig::default()
            },
            Box::new(move |event| {
                let _ = sender.send(event);
            }),
            FAST,
        );
        let NetState::Waiting {
            problem: Some(problem),
        } = state(&events, "waiting", |state| {
            matches!(state, NetState::Waiting { .. })
        })
        else {
            panic!("no reason given");
        };
        assert!(problem.contains("in use"), "{problem}");
    }

    #[test]
    fn a_lot_of_data_reaches_the_client_whole() {
        let (server, events, port) = start(config());
        let mut stream = client(port);
        joined(&events);
        let data: Vec<u8> = (0..2_000_000u32).map(|n| n as u8).collect();
        server.write(Target::All, data.clone());
        assert_eq!(read_some(&mut stream, data.len()), data);
    }
}
