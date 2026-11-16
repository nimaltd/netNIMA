//! One TCP, Telnet or TLS client: a connection kept open on its own thread,
//! made again when the other end starts later or goes away, if the tab wants that.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};

use super::config::TcpClientConfig;
use super::link::{HANDSHAKE_TIME, Link};
use super::telnet::Telnet;
use super::tls;
use super::wake::{self, Wake, Waker, raw};
use super::{
    BATCH_MAX, Event, NetState, Peer, PeerId, TIMING, Timing, addresses, is_not_there, is_quiet,
    open_problem,
};

enum Command {
    Write(Vec<u8>),
    /// Ends the connection with a reset rather than the usual goodbye, to
    /// see how the other end takes it.
    Reset,
    /// Ends the connection with the usual goodbye; it is made again if the
    /// tab connects again by itself.
    HangUp,
    /// Boxed: the settings are big beside the other commands.
    Reconfigure(Box<TcpClientConfig>),
    /// Sends the bytes as they are, then starts TLS on the connection.
    StartTls(Vec<u8>),
    Close,
}

/// A TCP client tab's connection. Dropping it closes the connection.
pub struct TcpClient {
    commands: Sender<Command>,
    waker: Waker,
    thread: Option<JoinHandle<()>>,
}

impl TcpClient {
    /// Starts connecting and keeps the connection until the client is
    /// dropped. Everything that happens comes back through `on_event`, which
    /// runs on the client's own thread.
    pub fn start(config: TcpClientConfig, on_event: impl FnMut(Event) + Send + 'static) -> Self {
        Self::start_with(config, Box::new(on_event), TIMING)
    }

    /// Starts as `start` does, with a timing of its own, such as `Timing::of_tab(true)`.
    pub fn start_with(
        config: TcpClientConfig,
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
            connections: 0,
            later: None,
        };
        let thread = thread::Builder::new()
            .name("netnima-tcp-client".into())
            .spawn(move || worker.run())
            .expect("the OS could not start a thread");
        Self {
            commands,
            waker,
            thread: Some(thread),
        }
    }

    /// Sends bytes to the other end. They are dropped while not connected.
    pub fn write(&self, data: Vec<u8>) {
        self.tell(Command::Write(data));
    }

    /// Ends the connection with a reset (RST) instead of a FIN.
    pub fn reset(&self) {
        self.tell(Command::Reset);
    }

    /// Ends the connection with the usual goodbye (FIN). A client that
    /// connects again by itself does, a moment later.
    pub fn hang_up(&self) {
        self.tell(Command::HangUp);
    }

    /// Connects again with new settings.
    pub fn reconfigure(&self, config: TcpClientConfig) {
        self.tell(Command::Reconfigure(Box::new(config)));
    }

    /// Sends `before` as it is, then starts TLS on the connection, for a
    /// protocol that asks for it partway, as FTP's AUTH TLS does. The tab's
    /// TLS settings must say `starttls`.
    pub fn start_tls(&self, before: Vec<u8>) {
        self.tell(Command::StartTls(before));
    }

    /// Queues a command, and wakes the thread to do it now.
    fn tell(&self, command: Command) {
        let _ = self.commands.send(command);
        self.waker.wake();
    }
}

impl Drop for TcpClient {
    fn drop(&mut self) {
        self.tell(Command::Close);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Why serving a connection ended.
enum Ended {
    /// The app closed the client.
    Closed,
    /// The other end closed the connection, or it broke.
    Lost(Option<String>),
    /// This end reset it.
    Reset,
    /// New settings: connect again.
    Reconnect,
}

struct Worker {
    config: TcpClientConfig,
    on_event: Box<dyn FnMut(Event) + Send>,
    commands: Receiver<Command>,
    /// Wakes the thread's wait when a command comes.
    wake: Wake,
    timing: Timing,
    state: Option<NetState>,
    /// Connections made so far: each is a peer of its own.
    connections: PeerId,
    /// The connection's TLS, when it waits for the protocol to ask for it.
    later: Option<tls::ClientSetup>,
}

impl Worker {
    fn run(mut self) {
        loop {
            match self.connect() {
                Ok(stream) => {
                    let ended = self.serve(stream);
                    let reason = match ended {
                        Ended::Closed => return,
                        Ended::Reconnect => continue,
                        Ended::Lost(reason) => reason,
                        Ended::Reset => Some("This end reset the connection.".into()),
                    };
                    if !self.config.reconnect {
                        self.set_state(NetState::Ended {
                            problem: reason
                                .or_else(|| Some("The other end closed the connection.".into())),
                        });
                        // Nothing more until new settings, or the end.
                        if !self.idle() {
                            return;
                        }
                        continue;
                    }
                    self.set_state(NetState::Waiting { problem: reason });
                    // A server that closes at once is not asked again straight away.
                    if !self.wait(self.timing.retry) {
                        return;
                    }
                }
                Err(problem) => {
                    self.set_state(NetState::Waiting { problem });
                    if !self.wait(self.timing.retry) {
                        return;
                    }
                }
            }
        }
    }

    /// Connects, or says why not: `None` when nothing answers yet.
    fn connect(&mut self) -> Result<Link, Option<String>> {
        if let Some(problem) = self.config.problem() {
            return Err(Some(problem));
        }
        // The TLS settings first: a file missing is said before connecting.
        let tls = match &self.config.tls {
            Some(options) => Some(tls::client_setup(options, &self.config.host).map_err(Some)?),
            None => None,
        };
        let host = self.config.host.trim().to_string();
        let found = addresses(&host, self.config.port)
            .map_err(|error| Some(format!("Cannot find the host {host}: {error}")))?;

        for address in found {
            match self.connect_to(address) {
                Ok(stream) => {
                    return self
                        .ready(stream, tls)
                        .map_err(|error| Some(error.to_string()));
                }
                Err(Some(problem)) => return Err(Some(problem)),
                // Nothing there: the next address, then a wait.
                Err(None) => {}
            }
        }
        Err(None)
    }

    /// One try at one address: `Err(None)` when nothing answers there.
    fn connect_to(&self, address: SocketAddr) -> Result<TcpStream, Option<String>> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )
        .map_err(|error| Some(format!("Could not make a socket: {error}")))?;
        if self.config.local_port != 0 {
            let local: SocketAddr = if address.is_ipv6() {
                SocketAddr::from(([0u16; 8], self.config.local_port))
            } else {
                SocketAddr::from(([0u8; 4], self.config.local_port))
            };
            socket
                .bind(&local.into())
                .map_err(|error| Some(open_problem(&local.to_string(), &error)))?;
        }
        match socket.connect_timeout(&address.into(), self.timing.connect) {
            Ok(()) => Ok(socket.into()),
            Err(error) if is_not_there(&error) => Err(None),
            Err(error) => Err(Some(format!(
                "Could not connect to {}: {error}",
                self.config.address()
            ))),
        }
    }

    /// Sets up a new connection, starts its TLS handshake if the tab speaks
    /// TLS, and says it is connected.
    fn ready(&mut self, stream: TcpStream, tls: Option<tls::ClientSetup>) -> io::Result<Link> {
        stream.set_nodelay(self.config.no_delay)?;
        // Reads never wait: the thread waits for the stream and for commands
        // together, so what the app sends goes out at once.
        stream.set_nonblocking(true)?;
        set_keep_alive(&stream, self.config.keep_alive)?;
        let address = stream.peer_addr()?.to_string();
        let local = stream.local_addr()?.to_string();
        let later = self.config.tls.as_ref().is_some_and(|tls| tls.starttls);
        self.later = None;
        let link = match tls {
            Some(setup) if later => {
                self.later = Some(setup);
                Link::plain(stream)
            }
            Some(setup) => Link::client(stream, setup)?,
            None => Link::plain(stream),
        };
        self.connections += 1;
        self.set_state(NetState::Connected {
            address: address.clone(),
            local,
        });
        self.emit(Event::PeerJoined(Peer {
            id: self.connections,
            address,
        }));
        Ok(link)
    }

    /// Passes data both ways until the client closes, the connection ends or
    /// the settings change.
    fn serve(&mut self, mut link: Link) -> Ended {
        let peer = self.connections;
        let mut telnet = self.config.telnet.then(Telnet::default);
        let mut buf = vec![0; BATCH_MAX];
        let mut pending = Vec::new();
        let mut reply = Vec::new();
        let mut batch_started: Option<Instant> = None;

        let ended = loop {
            if let Some(ended) = self.do_commands(&mut link, telnet.as_ref()) {
                break ended;
            }

            let mut quiet = false;
            match link.read(&mut buf) {
                Ok(0) => break Ended::Lost(None),
                Ok(count) => {
                    match &mut telnet {
                        Some(telnet) => telnet.receive(&buf[..count], &mut pending, &mut reply),
                        None => pending.extend_from_slice(&buf[..count]),
                    }
                    if !reply.is_empty() && link.write_all(&std::mem::take(&mut reply)).is_err() {
                        break Ended::Lost(None);
                    }
                    if !pending.is_empty() {
                        batch_started.get_or_insert_with(Instant::now);
                    }
                }
                Err(error) if is_quiet(&error) => quiet = true,
                Err(error) => break Ended::Lost(Some(lost_problem(&error))),
            }
            if let Some(agreed) = link.agreed() {
                self.emit(Event::Secure { peer, agreed });
            }
            if link.handshake_overdue() {
                break Ended::Lost(Some(format!(
                    "The TLS handshake did not end in {} s: does the other end speak TLS on this port?",
                    HANDSHAKE_TIME.as_secs()
                )));
            }

            let batch_due = batch_started.is_some_and(|start| start.elapsed() >= self.timing.batch);
            if batch_due || pending.len() >= BATCH_MAX {
                self.emit(Event::Data {
                    peer,
                    bytes: std::mem::take(&mut pending),
                });
                batch_started = None;
            }

            // Nothing more to read for now: waits for the other end, for a
            // command, or for the bytes held for the screen to be due. Only
            // then: TLS can hold bytes already read from the stream.
            if quiet {
                let (poll, batch) = (self.timing.poll, self.timing.batch);
                let wait = batch_started.map_or(poll, |start| {
                    batch.saturating_sub(start.elapsed()).min(poll)
                });
                if self.wake.wait(&[raw(link.stream())], wait).is_err() {
                    thread::sleep(self.timing.poll);
                }
            }
        };

        if !pending.is_empty() {
            self.emit(Event::Data {
                peer,
                bytes: pending,
            });
        }
        if matches!(ended, Ended::Reset) {
            let _ = SockRef::from(link.stream()).set_linger(Some(Duration::ZERO));
        } else {
            link.close();
        }
        drop(link);
        self.emit(Event::PeerLeft(peer));
        ended
    }

    /// Does what the app asked, until no command is left. Returns why serving
    /// should end, if it should.
    fn do_commands(&mut self, link: &mut Link, telnet: Option<&Telnet>) -> Option<Ended> {
        loop {
            let command = match self.commands.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => return Some(Ended::Closed),
            };
            match command {
                Command::Write(data) => {
                    let sent = match telnet {
                        Some(telnet) => link.write_all(&telnet.encode(&data)),
                        None => link.write_all(&data),
                    };
                    if let Err(error) = sent {
                        return Some(Ended::Lost(Some(lost_problem(&error))));
                    }
                }
                Command::Reset => return Some(Ended::Reset),
                Command::HangUp => {
                    return Some(Ended::Lost(Some("This end closed the connection.".into())));
                }
                Command::Reconfigure(config) => {
                    self.config = *config;
                    return Some(Ended::Reconnect);
                }
                Command::StartTls(before) => {
                    let started = link.write_all(&before).and_then(|()| match self.later.take() {
                        Some(setup) => link.start_client(setup),
                        None => Err(tls::failed(
                            "TLS was asked for, and the tab has no TLS settings, or it has started already."
                                .into(),
                        )),
                    });
                    if let Err(error) = started {
                        return Some(Ended::Lost(Some(lost_problem(&error))));
                    }
                }
                Command::Close => return Some(Ended::Closed),
            }
        }
    }

    /// Waits while not connected, still doing what the app asks. Returns
    /// false when the client should end.
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
                // Try again at once with the new settings.
                Ok(Command::Reconfigure(config)) => {
                    self.config = *config;
                    return true;
                }
                // Nothing to send it to.
                Ok(Command::Write(_) | Command::Reset | Command::HangUp | Command::StartTls(_)) => {
                }
            }
        }
    }

    /// Waits for new settings after a connection ended for good. Returns
    /// false when the client should end.
    fn idle(&mut self) -> bool {
        loop {
            match self.commands.recv() {
                Ok(Command::Reconfigure(config)) => {
                    self.config = *config;
                    return true;
                }
                Ok(Command::Close) | Err(_) => return false,
                Ok(Command::Write(_) | Command::Reset | Command::HangUp | Command::StartTls(_)) => {
                }
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

/// Why a connection broke, in words.
pub(crate) fn lost_problem(error: &io::Error) -> String {
    if let Some(words) = tls::words(error) {
        return words;
    }
    match error.kind() {
        io::ErrorKind::ConnectionReset => "The other end reset the connection.".into(),
        io::ErrorKind::ConnectionAborted => "The connection was aborted.".into(),
        _ => format!("The connection broke: {error}"),
    }
}

/// Turns keep-alive probes on every `seconds` of quiet, or off with 0.
pub(crate) fn set_keep_alive(stream: &TcpStream, seconds: u32) -> io::Result<()> {
    let socket = SockRef::from(stream);
    if seconds == 0 {
        return socket.set_keepalive(false);
    }
    let every = Duration::from_secs(u64::from(seconds));
    socket.set_tcp_keepalive(&TcpKeepalive::new().with_time(every).with_interval(every))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;
    use crate::net::tests::{AT_ONCE, FAST, SLOW_POLL, joined, received, state};

    fn server() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    fn config(port: u16) -> TcpClientConfig {
        TcpClientConfig {
            host: "127.0.0.1".into(),
            port,
            ..TcpClientConfig::default()
        }
    }

    fn start(config: TcpClientConfig) -> (TcpClient, Receiver<Event>) {
        start_timed(config, FAST)
    }

    fn start_timed(config: TcpClientConfig, timing: Timing) -> (TcpClient, Receiver<Event>) {
        let (sender, events) = mpsc::channel();
        let client = TcpClient::start_with(
            config,
            Box::new(move |event| {
                let _ = sender.send(event);
            }),
            timing,
        );
        (client, events)
    }

    #[test]
    fn what_is_written_goes_out_at_once() {
        let (listener, port) = server();
        let (client, events) = start_timed(config(port), SLOW_POLL);
        let mut stream = accept(&listener);
        connected(&events);
        let peer = joined(&events);
        // The thread is in its long wait: each write has to wake it.
        thread::sleep(Duration::from_millis(50));
        for _ in 0..3 {
            let start = Instant::now();
            client.write(b"x".to_vec());
            assert_eq!(read(&mut stream, 1), b"x");
            assert!(start.elapsed() < AT_ONCE, "{:?}", start.elapsed());
        }
        // What comes wakes it too.
        let start = Instant::now();
        stream.write_all(b"y").unwrap();
        assert_eq!(received(&events, peer.id, 1), b"y");
        assert!(start.elapsed() < AT_ONCE, "{:?}", start.elapsed());
    }

    fn accept(listener: &TcpListener) -> TcpStream {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    fn connected(events: &Receiver<Event>) -> NetState {
        state(events, "connect", |state| {
            matches!(state, NetState::Connected { .. })
        })
    }

    fn read(stream: &mut TcpStream, count: usize) -> Vec<u8> {
        let mut data = vec![0; count];
        stream.read_exact(&mut data).unwrap();
        data
    }

    #[test]
    fn connects_and_passes_data_both_ways() {
        let (listener, port) = server();
        let (client, events) = start(config(port));
        let mut stream = accept(&listener);
        let NetState::Connected { address, .. } = connected(&events) else {
            unreachable!()
        };
        assert_eq!(address, format!("127.0.0.1:{port}"));
        let peer = joined(&events);

        stream.write_all(b"hello\r\n").unwrap();
        assert_eq!(received(&events, peer.id, 7), b"hello\r\n");

        client.write(b"help\r".to_vec());
        assert_eq!(read(&mut stream, 5), b"help\r");
    }

    #[test]
    fn waits_for_a_server_that_starts_later_and_comes_back_after_it_goes() {
        let (listener, port) = server();
        drop(listener);
        let (_client, events) = start(config(port));
        state(&events, "wait", |state| {
            matches!(state, NetState::Waiting { problem: None })
        });

        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        drop(accept(&listener));
        connected(&events);
        let first = joined(&events);
        state(&events, "wait again", |state| {
            matches!(state, NetState::Waiting { .. })
        });
        let mut stream = accept(&listener);
        connected(&events);
        let second = joined(&events);
        assert!(second.id > first.id, "each connection is a peer of its own");
        stream.write_all(b"back").unwrap();
        assert_eq!(received(&events, second.id, 4), b"back");
    }

    #[test]
    fn without_reconnect_it_ends_and_says_why() {
        let (listener, port) = server();
        let (_client, events) = start(TcpClientConfig {
            reconnect: false,
            ..config(port)
        });
        drop(accept(&listener));
        let ended = state(&events, "end", |state| {
            matches!(state, NetState::Ended { .. })
        });
        assert_eq!(
            ended,
            NetState::Ended {
                problem: Some("The other end closed the connection.".into())
            }
        );
    }

    #[test]
    fn a_reset_ends_the_connection_without_a_goodbye() {
        let (listener, port) = server();
        let (client, events) = start(TcpClientConfig {
            reconnect: false,
            ..config(port)
        });
        let mut stream = accept(&listener);
        connected(&events);
        client.reset();
        state(&events, "end", |state| {
            matches!(state, NetState::Ended { .. })
        });
        let mut buf = [0; 4];
        let read = stream.read(&mut buf);
        assert!(
            matches!(&read, Err(error) if error.kind() == io::ErrorKind::ConnectionReset)
                || matches!(read, Ok(0)),
            "{read:?}"
        );
    }

    #[test]
    fn telnet_options_are_answered_and_kept_out() {
        let (listener, port) = server();
        let (client, events) = start(TcpClientConfig {
            telnet: true,
            ..config(port)
        });
        let mut stream = accept(&listener);
        connected(&events);
        let peer = joined(&events);

        // IAC WILL ECHO, then a prompt.
        stream.write_all(&[255, 251, 1]).unwrap();
        stream.write_all(b"login: ").unwrap();
        assert_eq!(received(&events, peer.id, 7), b"login: ");
        assert_eq!(read(&mut stream, 3), [255, 253, 1]);

        client.write(b"ls\r".to_vec());
        assert_eq!(read(&mut stream, 4), b"ls\r\0");
    }

    #[test]
    fn it_connects_from_the_local_port_it_is_given() {
        let (listener, port) = server();
        let free = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_port = free.local_addr().unwrap().port();
        drop(free);
        let (_client, events) = start(TcpClientConfig {
            local_port,
            ..config(port)
        });
        let stream = accept(&listener);
        connected(&events);
        assert_eq!(stream.peer_addr().unwrap().port(), local_port);
    }

    #[test]
    fn missing_settings_say_what_to_fill_in() {
        let (_client, events) = start(TcpClientConfig::default());
        let NetState::Waiting {
            problem: Some(problem),
        } = state(&events, "wait", |state| {
            matches!(state, NetState::Waiting { .. })
        })
        else {
            panic!("no reason given");
        };
        assert!(problem.contains("port"), "{problem}");
    }

    #[test]
    fn dropping_the_client_ends_its_thread() {
        let (listener, port) = server();
        let (client, events) = start(config(port));
        let _stream = accept(&listener);
        connected(&events);
        let before = Instant::now();
        drop(client);
        assert!(before.elapsed() < Duration::from_secs(1));
    }
}
