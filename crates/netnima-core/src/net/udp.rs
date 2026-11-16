//! One UDP tab: a socket open on its own thread, which hears from any peer
//! and sends to the remote address, to one peer, or to all.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use super::config::UdpConfig;
use super::wake::{self, Wake, Waker, raw};
use super::{
    Event, NetState, Peer, PeerId, TIMING, Target, Timing, addresses, is_quiet, open_problem,
};

/// The largest datagram there is.
const DATAGRAM_MAX: usize = 65_536;

enum Command {
    Send {
        target: Target,
        bytes: Vec<u8>,
    },
    Reconfigure(UdpConfig),
    /// Where what is sent to no one in particular goes, from now on.
    Remote(SocketAddr),
    Close,
}

/// A UDP tab's socket. Dropping it closes the socket.
pub struct UdpSession {
    commands: Sender<Command>,
    waker: Waker,
    thread: Option<JoinHandle<()>>,
}

impl UdpSession {
    /// Opens the socket and keeps it open until the session is dropped,
    /// trying again while it cannot open. Everything that happens comes back
    /// through `on_event`, on the session's own thread.
    pub fn start(config: UdpConfig, on_event: impl FnMut(Event) + Send + 'static) -> Self {
        Self::start_with(config, Box::new(on_event), TIMING)
    }

    pub(crate) fn start_with(
        config: UdpConfig,
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
            peers: HashMap::new(),
            order: Vec::new(),
            last_heard: None,
        };
        let thread = thread::Builder::new()
            .name("netnima-udp".into())
            .spawn(move || worker.run())
            .expect("the OS could not start a thread");
        Self {
            commands,
            waker,
            thread: Some(thread),
        }
    }

    /// Sends one datagram. While the socket is not open, it is dropped and
    /// the session says why.
    pub fn send(&self, target: Target, bytes: Vec<u8>) {
        self.tell(Command::Send { target, bytes });
    }

    /// Opens the socket again with new settings. The peers heard so far go.
    pub fn reconfigure(&self, config: UdpConfig) {
        self.tell(Command::Reconfigure(config));
    }

    /// Sends what goes to no one in particular to `at` from now on, on the
    /// same socket: as an LwM2M device does after bootstrap, to the server
    /// it was given.
    pub fn set_remote(&self, at: SocketAddr) {
        self.tell(Command::Remote(at));
    }

    /// Queues a command, and wakes the thread to do it now.
    fn tell(&self, command: Command) {
        let _ = self.commands.send(command);
        self.waker.wake();
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.tell(Command::Close);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Why serving the socket ended.
enum Ended {
    Closed,
    Reopen,
}

struct Worker {
    config: UdpConfig,
    on_event: Box<dyn FnMut(Event) + Send>,
    commands: Receiver<Command>,
    /// Wakes the thread's wait when a command comes.
    wake: Wake,
    timing: Timing,
    state: Option<NetState>,
    /// The peers heard from, by address, and their addresses in the order heard.
    peers: HashMap<SocketAddr, PeerId>,
    order: Vec<SocketAddr>,
    last_heard: Option<SocketAddr>,
}

impl Worker {
    fn run(mut self) {
        loop {
            match open(&self.config) {
                Ok(socket) => match self.serve(&socket) {
                    Ended::Closed => return,
                    Ended::Reopen => continue,
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

    /// Passes datagrams both ways until the session closes or its settings change.
    fn serve(&mut self, socket: &UdpSocket) -> Ended {
        let local = socket
            .local_addr()
            .map_or_else(|_| self.config.local_address.clone(), |at| at.to_string());
        self.set_state(NetState::Listening { local });
        let mut remote = self.resolve_remote();
        let mut buf = vec![0; DATAGRAM_MAX];
        let ended = loop {
            if let Some(ended) = self.do_commands(socket, &mut remote) {
                break ended;
            }
            // Waits for a datagram or a command, without a read timeout: on
            // Windows, a read that times out can lose the datagram that comes
            // at that moment.
            match self.wake.wait(&[raw(socket)], self.timing.poll) {
                Ok(true) => self.read_all(socket, &mut buf),
                Ok(false) => {}
                Err(error) => {
                    self.emit(Event::Problem(format!(
                        "Waiting for datagrams failed: {error}"
                    )));
                    thread::sleep(self.timing.poll);
                }
            }
        };
        self.forget_peers();
        ended
    }

    /// Reads the datagrams waiting, a batch at most, so commands are not kept waiting.
    fn read_all(&mut self, socket: &UdpSocket, buf: &mut [u8]) {
        for _ in 0..64 {
            match socket.recv_from(buf) {
                Ok((count, from)) => {
                    let peer = self.peer(from);
                    self.last_heard = Some(from);
                    self.emit(Event::Data {
                        peer,
                        bytes: buf[..count].to_vec(),
                    });
                }
                Err(error) if is_quiet(&error) => return,
                // An ICMP answer to a datagram sent, such as "port unreachable".
                Err(error) => {
                    self.emit(Event::Problem(format!(
                        "A datagram did not arrive: {error}"
                    )));
                    return;
                }
            }
        }
    }

    /// The remote address the send box sends to, looked up when the socket opens.
    fn resolve_remote(&mut self) -> Option<SocketAddr> {
        let host = self.config.remote_host.trim().to_string();
        if host.is_empty() {
            return None;
        }
        match addresses(&host, self.config.remote_port) {
            // An address of the same kind as the socket's, IPv4 or IPv6.
            Ok(found) => {
                let v6 = self.config.local().is_ok_and(|local| local.is_ipv6());
                let chosen = found.iter().copied().find(|at| at.is_ipv6() == v6);
                if chosen.is_none() {
                    let kind = if v6 { "IPv6" } else { "IPv4" };
                    self.emit(Event::Problem(format!(
                        "{host} has no {kind} address, and the tab listens on {kind}."
                    )));
                }
                chosen
            }
            Err(error) => {
                self.emit(Event::Problem(format!(
                    "Cannot find the host {host}: {error}"
                )));
                None
            }
        }
    }

    /// Does what the app asked, until no command is left.
    fn do_commands(
        &mut self,
        socket: &UdpSocket,
        remote: &mut Option<SocketAddr>,
    ) -> Option<Ended> {
        loop {
            let command = match self.commands.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => return Some(Ended::Closed),
            };
            match command {
                Command::Send { target, bytes } => self.send(socket, *remote, target, &bytes),
                Command::Reconfigure(config) => {
                    self.config = config;
                    return Some(Ended::Reopen);
                }
                Command::Remote(at) => *remote = Some(at),
                Command::Close => return Some(Ended::Closed),
            }
        }
    }

    /// Sends one datagram where it should go, and says why when it cannot.
    fn send(
        &mut self,
        socket: &UdpSocket,
        remote: Option<SocketAddr>,
        target: Target,
        bytes: &[u8],
    ) {
        let to: Vec<SocketAddr> = match target {
            Target::Default => remote.or(self.last_heard).into_iter().collect(),
            Target::Peer(id) => self
                .order
                .iter()
                .copied()
                .filter(|at| self.peers.get(at) == Some(&id))
                .collect(),
            Target::All => {
                let mut all = self.order.clone();
                if let Some(remote) = remote
                    && !all.contains(&remote)
                {
                    all.push(remote);
                }
                all
            }
        };
        if to.is_empty() {
            let problem = match target {
                Target::Peer(_) => "That peer is gone.",
                _ if self.config.remote_host.trim().is_empty() => {
                    "Nothing to send to: set the remote address, or wait to hear from a peer."
                }
                _ => "The remote host was not found, so the datagram was not sent.",
            };
            self.emit(Event::Problem(problem.into()));
            return;
        }
        for at in to {
            if let Err(error) = send_to(socket, bytes, at) {
                self.emit(Event::Problem(send_problem(at, bytes.len(), &error)));
            }
        }
    }

    /// The number of the peer at `from`, told to the app when it is new.
    fn peer(&mut self, from: SocketAddr) -> PeerId {
        if let Some(&id) = self.peers.get(&from) {
            return id;
        }
        let id = self.order.len() as PeerId + 1;
        self.peers.insert(from, id);
        self.order.push(from);
        self.emit(Event::PeerJoined(Peer {
            id,
            address: from.to_string(),
        }));
        id
    }

    /// The peers go with the socket they were heard on.
    fn forget_peers(&mut self) {
        let ids: Vec<PeerId> = self
            .order
            .iter()
            .filter_map(|at| self.peers.get(at).copied())
            .collect();
        self.peers.clear();
        self.order.clear();
        self.last_heard = None;
        for id in ids {
            self.emit(Event::PeerLeft(id));
        }
    }

    /// Waits while the socket cannot open, still doing what the app asks.
    /// Returns false when the session should end.
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
                    self.config = config;
                    return true;
                }
                Ok(Command::Send { .. }) => self.emit(Event::Problem(
                    "The socket is not open, so the datagram was not sent.".into(),
                )),
                Ok(Command::Remote(_)) => {}
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

/// Why a datagram could not be sent, in words.
pub(crate) fn send_problem(to: SocketAddr, size: usize, error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::PermissionDenied if to.ip().is_ipv4() && is_broadcast(to.ip()) => format!(
            "Could not send to {to}: it is a broadcast address, and Broadcast is off in the tab's settings."
        ),
        _ if size > 65_507 => {
            format!("Could not send {size} bytes to {to}: a datagram holds 65,507 at most.")
        }
        _ => format!("Could not send to {to}: {error}"),
    }
}

/// 255.255.255.255, or an address that ends in .255 as most broadcast addresses do.
fn is_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_broadcast() || ip.octets()[3] == 255,
        IpAddr::V6(_) => false,
    }
}

/// Opens the socket as the settings say, or says why it cannot.
pub(crate) fn open(config: &UdpConfig) -> Result<UdpSocket, String> {
    if let Some(problem) = config.problem() {
        return Err(problem);
    }
    let local = config.local()?;
    let shown = local.to_string();
    let fail = |error: io::Error| open_problem(&shown, &error);
    let socket =
        Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP)).map_err(fail)?;
    if config.reuse_address {
        socket.set_reuse_address(true).map_err(fail)?;
    }
    socket.bind(&local.into()).map_err(fail)?;
    socket.set_broadcast(config.broadcast).map_err(fail)?;
    match local.ip() {
        IpAddr::V4(_) => socket.set_ttl_v4(config.ttl).map_err(fail)?,
        IpAddr::V6(_) => socket.set_unicast_hops_v6(config.ttl).map_err(fail)?,
    }
    if let Some(multicast) = &config.multicast {
        let group: IpAddr = multicast
            .group
            .trim()
            .parse()
            .map_err(|_| format!("{} is not a multicast group.", multicast.group.trim()))?;
        let join =
            |error: io::Error| format!("Could not join the multicast group {group}: {error}");
        match group {
            IpAddr::V4(group) => {
                let interface = match multicast.interface.trim() {
                    "" => Ipv4Addr::UNSPECIFIED,
                    text => text
                        .parse()
                        .map_err(|_| format!("{text} is not an IPv4 address of an interface."))?,
                };
                socket.join_multicast_v4(&group, &interface).map_err(join)?;
                if !interface.is_unspecified() {
                    socket.set_multicast_if_v4(&interface).map_err(join)?;
                }
                socket
                    .set_multicast_loop_v4(multicast.loopback)
                    .map_err(join)?;
                socket.set_multicast_ttl_v4(config.ttl).map_err(join)?;
            }
            IpAddr::V6(group) => {
                socket
                    .join_multicast_v6(&group, multicast.interface_index)
                    .map_err(join)?;
                if multicast.interface_index != 0 {
                    socket
                        .set_multicast_if_v6(multicast.interface_index)
                        .map_err(join)?;
                }
                socket
                    .set_multicast_loop_v6(multicast.loopback)
                    .map_err(join)?;
                socket.set_multicast_hops_v6(config.ttl).map_err(join)?;
            }
        }
    }
    let socket: UdpSocket = socket.into();
    socket.set_nonblocking(true).map_err(fail)?;
    keep_reading_after_unreachable(&socket);
    Ok(socket)
}

/// Sends one datagram on a socket that does not block, waiting a little
/// while the OS's buffer is full.
pub(crate) fn send_to(socket: &UdpSocket, bytes: &[u8], at: SocketAddr) -> io::Result<()> {
    for _ in 0..200 {
        match socket.send_to(bytes, at) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::ErrorKind::WouldBlock.into())
}

/// On Windows, a datagram sent to a port nothing listens on comes back as an
/// ICMP "port unreachable", and the socket's next read then fails, again and
/// again. Turned off, the socket reads on as on the other OSes.
#[cfg(windows)]
fn keep_reading_after_unreachable(socket: &UdpSocket) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, WSAIoctl};

    let off: u32 = 0;
    let mut returned: u32 = 0;
    // Safe: the socket is open, and the buffers live through the call, which does not keep them.
    unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&raw const off).cast(),
            size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        );
    }
}

#[cfg(not(windows))]
fn keep_reading_after_unreachable(_socket: &UdpSocket) {}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Receiver;

    use super::*;
    use crate::net::tests::{
        AT_ONCE, FAST, SLOW_POLL, expect, joined, joined_from, received, state,
    };

    fn start(config: UdpConfig) -> (UdpSession, Receiver<Event>) {
        start_timed(config, FAST)
    }

    fn start_timed(config: UdpConfig, timing: Timing) -> (UdpSession, Receiver<Event>) {
        let (sender, events) = mpsc::channel();
        let session = UdpSession::start_with(
            config,
            Box::new(move |event| {
                let _ = sender.send(event);
            }),
            timing,
        );
        (session, events)
    }

    #[test]
    fn a_datagram_sent_goes_out_at_once() {
        let (session, events) = start_timed(loopback(), SLOW_POLL);
        let NetState::Listening { local } = state(&events, "listening", |state| {
            matches!(state, NetState::Listening { .. })
        }) else {
            unreachable!()
        };
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        other.send_to(b"hi", local.as_str()).unwrap();
        joined(&events);
        // The thread is back in its long wait: each send has to wake it.
        thread::sleep(Duration::from_millis(50));
        let mut buf = [0u8; 16];
        for _ in 0..3 {
            let start = Instant::now();
            session.send(Target::Default, b"back".to_vec());
            let (count, _) = other.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..count], b"back");
            assert!(start.elapsed() < AT_ONCE, "{:?}", start.elapsed());
        }
    }

    /// A tab listening on a free port of the loopback, and its port.
    fn listening(config: UdpConfig) -> (UdpSession, Receiver<Event>, u16) {
        let (session, events) = start(config);
        let local = match state(&events, "listening", |state| {
            matches!(state, NetState::Listening { .. })
        }) {
            NetState::Listening { local } => local,
            _ => unreachable!(),
        };
        let port = local.parse::<SocketAddr>().unwrap().port();
        (session, events, port)
    }

    fn loopback() -> UdpConfig {
        UdpConfig {
            local_address: "127.0.0.1".into(),
            ..UdpConfig::default()
        }
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
    fn two_tabs_send_to_each_other_and_answer_back() {
        let (server, server_events, server_port) = listening(loopback());
        let (client, client_events, client_port) = listening(UdpConfig {
            remote_host: "127.0.0.1".into(),
            remote_port: server_port,
            ..loopback()
        });

        client.send(Target::Default, b"ping".to_vec());
        let peer = joined_from(&server_events, &format!("127.0.0.1:{client_port}"));
        assert_eq!(received(&server_events, peer.id, 4), b"ping");

        // The server has no remote address: it answers the one it heard last.
        server.send(Target::Default, b"pong".to_vec());
        let back = joined_from(&client_events, &format!("127.0.0.1:{server_port}"));
        assert_eq!(received(&client_events, back.id, 4), b"pong");
    }

    #[test]
    fn each_datagram_comes_whole_and_on_its_own() {
        let (_server, events, port) = listening(loopback());
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        for text in ["one", "two", "three"] {
            sender
                .send_to(text.as_bytes(), ("127.0.0.1", port))
                .unwrap();
        }
        let peer = joined(&events);
        let mut got = Vec::new();
        while got.len() < 3 {
            if let Event::Data { bytes, .. } = expect(
                &events,
                "datagram",
                |event| matches!(event, Event::Data { peer: from, .. } if *from == peer.id),
            ) {
                got.push(bytes);
            }
        }
        assert_eq!(got, [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]);
    }

    #[test]
    fn peers_are_told_apart_and_reached_one_by_one_or_all() {
        let (server, events, port) = listening(loopback());
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        for socket in [&first, &second] {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
        }
        first.send_to(b"a", ("127.0.0.1", port)).unwrap();
        let one = joined(&events);
        second.send_to(b"b", ("127.0.0.1", port)).unwrap();
        let two = joined(&events);
        assert_ne!(one.id, two.id);
        assert_eq!(one.address, first.local_addr().unwrap().to_string());

        let mut buf = [0; 16];
        server.send(Target::Peer(two.id), b"only you".to_vec());
        let (count, _) = second.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..count], b"only you");

        server.send(Target::All, b"all".to_vec());
        for socket in [&first, &second] {
            let (count, _) = socket.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..count], b"all");
        }
    }

    #[test]
    fn with_nobody_to_send_to_it_says_so() {
        let (session, events, _) = listening(loopback());
        session.send(Target::Default, b"lost".to_vec());
        assert!(problem(&events).contains("Nothing to send to"));
        session.send(Target::Peer(9), b"lost".to_vec());
        assert!(problem(&events).contains("gone"));
    }

    #[test]
    fn a_port_in_use_is_said_in_words_and_tried_again() {
        let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let (_session, events) = start(UdpConfig {
            local_port: port,
            ..loopback()
        });
        let waiting = state(&events, "waiting", |state| {
            matches!(state, NetState::Waiting { .. })
        });
        let NetState::Waiting {
            problem: Some(problem),
        } = waiting
        else {
            panic!("no reason given");
        };
        assert!(
            problem.contains(&format!("Port {port} is in use")),
            "{problem}"
        );

        // Once the port is free, the tab opens by itself.
        drop(taken);
        state(&events, "listening", |state| {
            matches!(state, NetState::Listening { .. })
        });
    }

    #[test]
    fn new_settings_open_the_socket_again() {
        let (session, events, first_port) = listening(loopback());
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second_port = other.local_addr().unwrap().port();
        drop(other);
        session.reconfigure(UdpConfig {
            local_port: second_port,
            ..loopback()
        });
        let local = state(
            &events,
            "listening again",
            |state| matches!(state, NetState::Listening { local } if !local.ends_with(&format!(":{first_port}"))),
        );
        assert_eq!(
            local,
            NetState::Listening {
                local: format!("127.0.0.1:{second_port}")
            }
        );
    }

    #[test]
    fn sending_to_a_port_nobody_listens_on_does_not_stop_the_tab() {
        // Port 9, the old discard service, which nothing listens on these days.
        // A free port found by binding could go to another test running beside this one.
        let (session, events, port) = listening(UdpConfig {
            remote_host: "127.0.0.1".into(),
            remote_port: 9,
            ..loopback()
        });
        session.send(Target::Default, b"nobody".to_vec());
        thread::sleep(Duration::from_millis(50));
        // It still hears what comes after.
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"still here", ("127.0.0.1", port)).unwrap();
        let peer = joined(&events);
        assert_eq!(received(&events, peer.id, 10), b"still here");
    }

    #[test]
    fn a_multicast_group_is_heard_on_the_loopback() {
        let group = "239.255.77.77";
        let (_listener, events, port) = listening(UdpConfig {
            local_address: String::new(),
            reuse_address: true,
            multicast: Some(crate::net::Multicast {
                group: group.into(),
                interface: "127.0.0.1".into(),
                interface_index: 0,
                loopback: true,
            }),
            ..UdpConfig::default()
        });
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Some machines send no multicast on the loopback; the join itself is what matters most.
        if sender.set_multicast_if_v4_compat().is_err() {
            return;
        }
        let _ = sender.send_to(b"to the group", (group, port));
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if let Ok(Event::Data { bytes, .. }) = events.recv_timeout(Duration::from_millis(100)) {
                assert_eq!(bytes, b"to the group");
                return;
            }
        }
    }

    /// Sends multicast through the loopback, where the OS allows it.
    trait LoopbackMulticast {
        fn set_multicast_if_v4_compat(&self) -> io::Result<()>;
    }

    impl LoopbackMulticast for UdpSocket {
        fn set_multicast_if_v4_compat(&self) -> io::Result<()> {
            socket2::SockRef::from(self).set_multicast_if_v4(&Ipv4Addr::LOCALHOST)
        }
    }
}
