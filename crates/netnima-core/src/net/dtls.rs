//! DTLS over UDP: a client that keeps a connection to its server and
//! handshakes again when it ends, and a server that takes many clients, each
//! a peer, with certificates or a pre-shared key.
//!
//! Two engines, both Sans-IO here: this session owns the UDP socket and each
//! connection's state machine, feeds them datagrams and timer ticks, and
//! sends what they give back. dimpl, in Rust, speaks DTLS 1.2 and 1.3 with
//! ECDSA certificates, and DTLS 1.2 with a PSK and AES-128-CCM-8, as CoAP and
//! LwM2M devices use. OpenSSL, for old and small devices, speaks DTLS 1.0 and
//! 1.2 with any suite it has: the PSK and CBC ones too, and RSA certificates.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, DtlsCertificate, Output, ProtocolVersion, PskResolver};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};

use super::config::UdpConfig;
use super::legacy::{DtlsSetup, OldDtls, Seen};
use super::tls::{self, Agreed, Checker, Engine, Verify};
use super::udp::{open, send_problem, send_to};
use super::wake::{self, Wake, Waker, raw};
use super::{Event, NetState, Peer, PeerId, TIMING, Target, Timing, addresses};
use crate::certs;

/// The most connections a server keeps at once.
const MOST_PEERS: usize = 256;
/// How long a client waits before it handshakes again.
const AGAIN_AFTER: Duration = Duration::from_secs(2);

/// What is said when a handshake does not end in time.
pub(crate) const NOT_FINISHED: &str = "The other end did not finish the DTLS handshake: is a DTLS server there, with the same PSK or certificate kind?";

/// The DTLS versions a tab speaks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DtlsVersion {
    /// A client offers 1.2 and 1.3; a server takes either. Over OpenSSL:
    /// 1.0 and 1.2.
    #[default]
    Auto,
    Dtls12,
    Dtls13,
    /// DTLS 1.0 alone, over OpenSSL.
    Dtls10,
    /// DTLS 1.0 and 1.2, over OpenSSL.
    All,
}

/// A DTLS tab's settings, for a client or a server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DtlsOptions {
    pub version: DtlsVersion,
    /// The engine: dimpl, in Rust, unless the settings need OpenSSL. In
    /// `Engine`, `Rustls` stands for the Rust engine.
    pub engine: Engine,
    /// OpenSSL's names of the suites to offer or take, such as
    /// PSK-AES128-CBC-SHA256: empty for all.
    pub ciphers: String,
    /// A pre-shared key instead of certificates: with dimpl, DTLS 1.2 with
    /// AES-128-CCM-8; with OpenSSL, any PSK suite.
    pub psk: bool,
    /// The client's identity; on a server, the one it takes, or any when empty.
    pub psk_identity: String,
    /// The key: hex digits, such as 000102030405, or text in quotes, such as "secret".
    pub psk_key: String,
    /// This end's certificate, ECDSA P-256 or P-384: empty for one netNIMA makes.
    pub cert_file: String,
    /// Its private key: empty when it is in the certificate's file.
    pub key_file: String,
    /// A client: how the server's certificate is checked.
    pub verify: Verify,
    pub ca_file: String,
    pub check_name: bool,
    /// A client: the name the server's certificate must be for; empty for the host.
    pub server_name: String,
    /// A server: asks each client for a certificate, and needs one.
    pub client_auth: bool,
    /// A server: sends a cookie first (HelloVerifyRequest), against spoofed addresses.
    pub cookie: bool,
}

impl Default for DtlsOptions {
    fn default() -> Self {
        Self {
            version: DtlsVersion::Auto,
            engine: Engine::Auto,
            ciphers: String::new(),
            psk: false,
            psk_identity: "netnima".into(),
            psk_key: "000102030405060708090a0b0c0d0e0f".into(),
            cert_file: String::new(),
            key_file: String::new(),
            verify: Verify::None,
            ca_file: String::new(),
            check_name: true,
            server_name: String::new(),
            client_auth: false,
            cookie: true,
        }
    }
}

/// A key as typed: hex digits, with spaces or colons if wanted, or text in quotes.
pub fn psk_key(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if let Some(quoted) = text
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        return Ok(quoted.as_bytes().to_vec());
    }
    let digits: String = text
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-'))
        .collect();
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(
            "The key is hex digits, such as 000102030405, or text in quotes, such as \"secret\"."
                .into(),
        );
    }
    Ok((0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap_or(0))
        .collect())
}

/// The identity a PSK was last asked for, which the session gives to the
/// connection it was feeding then, to show.
type SeenIdentity = Arc<std::sync::Mutex<Option<Vec<u8>>>>;

/// Gives the key for the identity set; a server with no identity set takes any.
struct FixedPsk {
    identity: Vec<u8>,
    key: Vec<u8>,
    seen: SeenIdentity,
}

impl PskResolver for FixedPsk {
    fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(identity.to_vec());
        }
        (self.identity.is_empty() || identity == self.identity.as_slice() || identity.is_empty())
            .then(|| self.key.clone())
    }
}

/// Whether a tab's settings need OpenSSL rather than dimpl.
fn over_openssl(options: &DtlsOptions) -> Result<bool, String> {
    let old = matches!(options.version, DtlsVersion::Dtls10 | DtlsVersion::All);
    match options.engine {
        Engine::Openssl => Ok(true),
        Engine::Rustls if old => {
            Err("DTLS 1.0 is spoken by OpenSSL: choose it, or Auto, as the engine.".into())
        }
        Engine::Rustls => Ok(false),
        Engine::Auto => Ok(old || !options.ciphers.trim().is_empty()),
    }
}

/// What both roles make their connections from: dimpl's settings, or OpenSSL's.
enum Setup {
    Rust {
        config: Arc<Config>,
        certificate: Option<DtlsCertificate>,
        checker: Option<Checker>,
        seen: SeenIdentity,
    },
    Openssl(DtlsSetup),
}

fn setup(options: &DtlsOptions, client: bool, handshake: Duration) -> Result<Setup, String> {
    if over_openssl(options)? {
        return Ok(Setup::Openssl(DtlsSetup::new(options, client)?));
    }
    let mut builder = Config::builder()
        .handshake_timeout(handshake)
        .require_client_certificate(!client && options.client_auth && !options.psk)
        .use_server_cookie(options.cookie);
    let seen = SeenIdentity::default();
    let certificate = if options.psk {
        let key = psk_key(&options.psk_key)?;
        let identity = options.psk_identity.trim().as_bytes().to_vec();
        if client && identity.is_empty() {
            return Err("Enter the PSK identity the server knows this end by.".into());
        }
        let resolver = Arc::new(FixedPsk {
            identity: identity.clone(),
            key,
            seen: seen.clone(),
        });
        builder = if client {
            builder.with_psk_client(identity, resolver)
        } else {
            builder.with_psk_server(None, resolver)
        };
        None
    } else {
        Some(certificate(options, client)?)
    };
    let config = builder
        .build()
        .map_err(|error| format!("DTLS cannot be set up: {error}"))?;
    let checker = if client && !options.psk {
        Checker::for_options(options.verify, &options.ca_file, options.check_name)?
    } else {
        None
    };
    Ok(Setup::Rust {
        config: Arc::new(config),
        certificate,
        checker,
        seen,
    })
}

/// This end's certificate: the files set, netNIMA's own for a server, or one
/// made now for a client.
fn certificate(options: &DtlsOptions, client: bool) -> Result<DtlsCertificate, String> {
    let (certificate, private_key) = if !options.cert_file.trim().is_empty() {
        let (chain, key) = tls::identity(&options.cert_file, &options.key_file)?;
        (chain[0].to_vec(), key.secret_der().to_vec())
    } else if client {
        certs::throwaway()?
    } else {
        let (chain, key) = certs::own()?;
        (chain[0].to_vec(), key.secret_der().to_vec())
    };
    Ok(DtlsCertificate {
        certificate,
        private_key,
    })
}

enum Command {
    Send { target: Target, bytes: Vec<u8> },
    Close,
}

/// A DTLS client or server tab. Dropping it closes every connection.
pub struct DtlsSession {
    commands: Sender<Command>,
    waker: Waker,
    thread: Option<JoinHandle<()>>,
}

impl DtlsSession {
    /// Opens the socket, and as a client starts the handshake with the
    /// remote address. What happens comes back through `on_event`.
    pub fn start(
        udp: UdpConfig,
        options: DtlsOptions,
        client: bool,
        on_event: impl FnMut(Event) + Send + 'static,
    ) -> Self {
        Self::start_with(udp, options, client, Box::new(on_event), TIMING)
    }

    pub(crate) fn start_with(
        udp: UdpConfig,
        options: DtlsOptions,
        client: bool,
        on_event: Box<dyn FnMut(Event) + Send>,
        timing: Timing,
    ) -> Self {
        let (commands, receiver) = mpsc::channel();
        let (waker, wake) = wake::pair();
        let worker = Worker {
            udp,
            options,
            client,
            on_event,
            commands: receiver,
            wake,
            timing,
            state: None,
            next_peer: 0,
            last_heard: None,
        };
        let thread = thread::Builder::new()
            .name("netnima-dtls".into())
            .spawn(move || worker.run())
            .expect("the OS could not start a thread");
        Self {
            commands,
            waker,
            thread: Some(thread),
        }
    }

    /// Sends bytes as one DTLS record: on a client to its server, on a
    /// server to one client, all, or the one heard from last.
    pub fn send(&self, target: Target, bytes: Vec<u8>) {
        self.tell(Command::Send { target, bytes });
    }

    /// Queues a command, and wakes the thread to do it now.
    fn tell(&self, command: Command) {
        let _ = self.commands.send(command);
        self.waker.wake();
    }
}

impl Drop for DtlsSession {
    fn drop(&mut self) {
        self.tell(Command::Close);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A connection's state machine: dimpl's, or OpenSSL's.
enum Machine {
    Rust(Box<Dtls>),
    Openssl(Box<OldDtls>),
}

impl Machine {
    fn handle_timeout(&mut self, now: Instant, connected: bool) -> Result<(), String> {
        match self {
            Self::Rust(dtls) => dtls
                .handle_timeout(now)
                .map_err(|error| dtls_problem(&error, connected)),
            Self::Openssl(old) => old.handle_timeout(now),
        }
    }

    fn handle_packet(&mut self, bytes: &[u8], connected: bool) -> Result<(), String> {
        match self {
            Self::Rust(dtls) => dtls
                .handle_packet(bytes)
                .map_err(|error| dtls_problem(&error, connected)),
            Self::Openssl(old) => old.handle_packet(bytes),
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        match self {
            Self::Rust(dtls) => dtls
                .send_application_data(bytes)
                .map(|_| ())
                .map_err(|error| dtls_problem(&error, true)),
            Self::Openssl(old) => old.send(bytes),
        }
    }

    fn close(&mut self) {
        match self {
            Self::Rust(dtls) => {
                let _ = dtls.close();
            }
            Self::Openssl(old) => old.close(),
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Self::Rust(dtls) => dtls.is_closed(),
            Self::Openssl(old) => old.is_closed(),
        }
    }
}

/// One connection: a peer and its DTLS state machine.
struct Conn {
    peer: PeerId,
    address: SocketAddr,
    machine: Machine,
    next: Option<Instant>,
    connected: bool,
    cert: Option<Vec<u8>>,
    /// dimpl: the PSK identity the other end gave, to show.
    identity: Option<String>,
    /// What was sent before the handshake ended, sent when it does.
    waiting: Vec<Vec<u8>>,
    /// Set when it ended, with why when it broke.
    ended: Option<Option<String>>,
}

/// What a connection did when it was driven.
enum Happened {
    Connected,
    Data(Vec<u8>),
}

struct Worker {
    udp: UdpConfig,
    options: DtlsOptions,
    client: bool,
    on_event: Box<dyn FnMut(Event) + Send>,
    commands: Receiver<Command>,
    /// Wakes the thread's wait when a command comes.
    wake: Wake,
    timing: Timing,
    state: Option<NetState>,
    next_peer: PeerId,
    last_heard: Option<PeerId>,
}

impl Worker {
    fn run(mut self) {
        loop {
            let ready = setup(&self.options, self.client, self.timing.handshake)
                .and_then(|setup| Ok((open(&self.udp)?, setup)));
            match ready {
                Ok((socket, setup)) => {
                    self.serve(&socket, &setup);
                    return;
                }
                Err(problem) => {
                    self.set_state(NetState::Waiting {
                        problem: Some(problem),
                    });
                    if !self.wait(self.timing.retry.max(Duration::from_millis(500))) {
                        return;
                    }
                }
            }
        }
    }

    fn new_conn(&mut self, setup: &Setup, address: SocketAddr) -> Result<Conn, String> {
        let machine = match setup {
            Setup::Rust {
                config,
                certificate,
                ..
            } => {
                let now = Instant::now();
                let mut dtls = match (certificate, self.options.version) {
                    (None, _) => Dtls::new_12_psk(config.clone(), now),
                    (Some(certificate), DtlsVersion::Dtls12) => {
                        Dtls::new_12(config.clone(), certificate.clone(), now)
                    }
                    (Some(certificate), DtlsVersion::Dtls13) => {
                        Dtls::new_13(config.clone(), certificate.clone(), now)
                    }
                    // Auto: the other versions are OpenSSL's.
                    (Some(certificate), _) => {
                        Dtls::new_auto(config.clone(), certificate.clone(), now)
                    }
                };
                if self.client {
                    dtls.set_active(true);
                }
                Machine::Rust(Box::new(dtls))
            }
            Setup::Openssl(context) => Machine::Openssl(Box::new(if self.client {
                context.connect(&self.name(), self.timing.handshake)?
            } else {
                context.accept(self.timing.handshake)?
            })),
        };
        self.next_peer += 1;
        let peer = self.next_peer;
        self.emit(Event::PeerJoined(Peer {
            id: peer,
            address: address.to_string(),
        }));
        Ok(Conn {
            peer,
            address,
            machine,
            next: None,
            connected: false,
            cert: None,
            identity: None,
            waiting: Vec::new(),
            ended: None,
        })
    }

    fn serve(&mut self, socket: &UdpSocket, setup: &Setup) {
        let local = socket
            .local_addr()
            .map_or_else(|_| self.udp.local_address.clone(), |at| at.to_string());
        let remote = if self.client { self.remote() } else { None };
        if !self.client {
            self.set_state(NetState::Listening {
                local: local.clone(),
            });
        }
        let name = self.server_name();
        let mut conns: Vec<Conn> = Vec::new();
        let mut buf = vec![0u8; 2048];
        let mut datagram = vec![0u8; 65536];
        let mut again_at = Some(Instant::now());

        loop {
            // What the app asked.
            loop {
                match self.commands.try_recv() {
                    Ok(Command::Send { target, bytes }) => {
                        self.send(&mut conns, socket, &mut buf, target, bytes)
                    }
                    Ok(Command::Close) | Err(TryRecvError::Disconnected) => {
                        for conn in &mut conns {
                            conn.machine.close();
                            let _ = drive(conn, socket, &mut buf);
                        }
                        for conn in conns {
                            self.emit(Event::PeerLeft(conn.peer));
                        }
                        return;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }

            let now = Instant::now();
            // A client handshakes with its server, again after one ends.
            if self.client && conns.is_empty() && again_at.is_some_and(|at| now >= at) {
                again_at = None;
                match remote {
                    Some(remote) => match self.new_conn(setup, remote) {
                        Ok(mut conn) => {
                            self.set_state(NetState::Waiting { problem: None });
                            self.step(&mut conn, socket, &mut buf, setup, name.as_ref(), &local);
                            conns.push(conn);
                        }
                        Err(problem) => {
                            self.set_state(NetState::Waiting {
                                problem: Some(problem),
                            });
                            again_at = Some(now + AGAIN_AFTER);
                        }
                    },
                    None => self.set_state(NetState::Waiting {
                        problem: Some(
                            "Enter the server's address as the remote host and port.".into(),
                        ),
                    }),
                }
            }

            // Timers: what is sent again, and handshakes that took too long.
            for conn in &mut conns {
                if conn.ended.is_none() && conn.next.is_some_and(|next| now >= next) {
                    match conn.machine.handle_timeout(now, conn.connected) {
                        Ok(()) => self.step(conn, socket, &mut buf, setup, name.as_ref(), &local),
                        Err(problem) => conn.ended = Some(Some(problem)),
                    }
                }
            }

            // Datagrams, until the next timer is due or a command comes.
            let next_timer = conns.iter().filter_map(|conn| conn.next).min();
            let wait = next_timer
                .map_or(self.timing.poll, |next| {
                    next.saturating_duration_since(Instant::now())
                })
                .min(self.timing.poll)
                .max(Duration::from_millis(1));
            let readable = match self.wake.wait(&[raw(socket)], wait) {
                Ok(readable) => readable,
                // Not a loop that spins while the wait fails.
                Err(_) => {
                    thread::sleep(wait);
                    false
                }
            };
            if readable {
                for _ in 0..64 {
                    let (count, from) = match socket.recv_from(&mut datagram) {
                        Ok(got) => got,
                        Err(error) if super::is_quiet(&error) => break,
                        Err(error) => {
                            self.emit(Event::Problem(format!(
                                "A datagram did not arrive: {error}"
                            )));
                            break;
                        }
                    };
                    let bytes = &datagram[..count];
                    let found = conns
                        .iter()
                        .position(|conn| conn.address == from && conn.ended.is_none());
                    let at = match found {
                        Some(at) => at,
                        None if self.client => continue,
                        None => {
                            // Only a handshake record starts a connection.
                            if bytes.first() != Some(&22) {
                                continue;
                            }
                            if conns.len() >= MOST_PEERS {
                                self.emit(Event::Problem(format!(
                                    "{from} was turned away: the server keeps {MOST_PEERS} connections at most."
                                )));
                                continue;
                            }
                            match self.new_conn(setup, from) {
                                Ok(conn) => conns.push(conn),
                                Err(problem) => {
                                    self.emit(Event::Problem(format!("{from}: {problem}")));
                                    continue;
                                }
                            }
                            conns.len() - 1
                        }
                    };
                    let conn = &mut conns[at];
                    let now = Instant::now();
                    let connected = conn.connected;
                    let fed = conn
                        .machine
                        .handle_timeout(now, connected)
                        .and_then(|()| conn.machine.handle_packet(bytes, connected));
                    // A PSK asked for while this datagram was fed was this connection's.
                    if let Setup::Rust { seen, .. } = setup
                        && let Some(identity) = seen.lock().ok().and_then(|mut seen| seen.take())
                    {
                        conn.identity = Some(String::from_utf8_lossy(&identity).into_owned());
                    }
                    match fed {
                        Ok(()) => {
                            self.last_heard = Some(conn.peer);
                            self.step(conn, socket, &mut buf, setup, name.as_ref(), &local);
                        }
                        Err(problem) => conn.ended = Some(Some(problem)),
                    }
                }
            }

            // The connections that ended.
            let mut index = 0;
            while index < conns.len() {
                let closed = conns[index].machine.is_closed();
                if conns[index].ended.is_none() && closed {
                    conns[index].ended = Some(None);
                }
                let Some(why) = conns[index].ended.clone() else {
                    index += 1;
                    continue;
                };
                let conn = conns.remove(index);
                if let Some(problem) = &why {
                    let who = if self.client {
                        String::new()
                    } else {
                        format!("{}: ", conn.address)
                    };
                    self.emit(Event::Problem(format!("{who}{problem}")));
                }
                self.emit(Event::PeerLeft(conn.peer));
                if self.last_heard == Some(conn.peer) {
                    self.last_heard = None;
                }
                if self.client {
                    self.set_state(NetState::Waiting { problem: why });
                    again_at = Some(Instant::now() + AGAIN_AFTER);
                }
            }
        }
    }

    /// Drives a connection after it was fed, and tells what it did.
    fn step(
        &mut self,
        conn: &mut Conn,
        socket: &UdpSocket,
        buf: &mut Vec<u8>,
        setup: &Setup,
        name: Option<&ServerName<'static>>,
        local: &str,
    ) {
        match drive(conn, socket, buf) {
            Ok(happened) => {
                for event in happened {
                    match event {
                        Happened::Connected => {
                            // A client checks the server's certificate now, when asked
                            // to. OpenSSL has checked it in the handshake.
                            let checker = match setup {
                                Setup::Rust { checker, .. } => checker.as_ref(),
                                Setup::Openssl(_) => None,
                            };
                            if let (Some(checker), Some(cert), Some(name)) =
                                (checker, &conn.cert, name)
                                && let Err(problem) = checker.check(cert, name)
                            {
                                conn.machine.close();
                                let _ = drive(conn, socket, buf);
                                conn.ended = Some(Some(problem));
                                return;
                            }
                            conn.connected = true;
                            if self.client {
                                self.set_state(NetState::Connected {
                                    address: conn.address.to_string(),
                                    local: local.to_string(),
                                });
                            }
                            let agreed = agreed(conn, &self.options);
                            self.emit(Event::Secure {
                                peer: conn.peer,
                                agreed,
                            });
                            for bytes in std::mem::take(&mut conn.waiting) {
                                if let Err(problem) = conn.machine.send(&bytes) {
                                    conn.ended = Some(Some(problem));
                                    return;
                                }
                            }
                            if let Err(problem) = drive(conn, socket, buf).map(|_| ()) {
                                conn.ended = Some(Some(problem));
                            }
                        }
                        Happened::Data(bytes) => self.emit(Event::Data {
                            peer: conn.peer,
                            bytes,
                        }),
                    }
                }
            }
            Err(problem) => conn.ended = Some(Some(problem)),
        }
    }

    fn send(
        &mut self,
        conns: &mut [Conn],
        socket: &UdpSocket,
        buf: &mut Vec<u8>,
        target: Target,
        bytes: Vec<u8>,
    ) {
        let chosen: Vec<usize> = match target {
            Target::All => (0..conns.len()).collect(),
            Target::Peer(peer) => conns
                .iter()
                .position(|conn| conn.peer == peer)
                .into_iter()
                .collect(),
            Target::Default if self.client => (0..conns.len()).collect(),
            Target::Default => match (self.last_heard, conns.len()) {
                (Some(peer), _) => conns
                    .iter()
                    .position(|conn| conn.peer == peer)
                    .into_iter()
                    .collect(),
                (None, 1) => vec![0],
                (None, 0) => Vec::new(),
                (None, _) => {
                    self.emit(Event::Problem(
                        "Several clients are connected and none has been heard from: choose one, or All.".into(),
                    ));
                    return;
                }
            },
        };
        if chosen.is_empty() {
            self.emit(Event::Problem(
                if self.client {
                    "Not connected yet: nothing was sent."
                } else {
                    "No client is connected, so nothing was sent."
                }
                .into(),
            ));
            return;
        }
        for at in chosen {
            let conn = &mut conns[at];
            if !conn.connected {
                // Sent when the handshake ends.
                conn.waiting.push(bytes.clone());
                continue;
            }
            match conn.machine.send(&bytes) {
                Ok(()) => {
                    if let Err(problem) = drive(conn, socket, buf) {
                        conn.ended = Some(Some(problem));
                    }
                }
                Err(problem) => conn.ended = Some(Some(problem)),
            }
        }
    }

    /// The server's address, for a client.
    fn remote(&mut self) -> Option<SocketAddr> {
        let host = self.udp.remote_host.trim().to_string();
        if host.is_empty() || self.udp.remote_port == 0 {
            return None;
        }
        match addresses(&host, self.udp.remote_port) {
            Ok(found) => {
                let v6 = self.udp.local().is_ok_and(|local| local.is_ipv6());
                found.into_iter().find(|at| at.is_ipv6() == v6)
            }
            Err(error) => {
                self.emit(Event::Problem(format!(
                    "Cannot find the host {host}: {error}"
                )));
                None
            }
        }
    }

    /// The name a client asks for and checks the server's certificate for.
    fn name(&self) -> String {
        let name = if self.options.server_name.trim().is_empty() {
            self.udp.remote_host.trim()
        } else {
            self.options.server_name.trim()
        };
        name.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    }

    fn server_name(&self) -> Option<ServerName<'static>> {
        ServerName::try_from(self.name()).ok()
    }

    fn wait(&mut self, time: Duration) -> bool {
        match self.commands.recv_timeout(time) {
            Ok(Command::Close) | Err(RecvTimeoutError::Disconnected) => false,
            Ok(Command::Send { .. }) => {
                self.emit(Event::Problem(
                    "The socket is not open, so nothing was sent.".into(),
                ));
                true
            }
            Err(RecvTimeoutError::Timeout) => true,
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

/// Sends what a connection has to send, and gathers what it did, until it
/// says when it wants to be woken next.
fn drive(conn: &mut Conn, socket: &UdpSocket, buf: &mut Vec<u8>) -> Result<Vec<Happened>, String> {
    let mut happened = Vec::new();
    let dtls = match &mut conn.machine {
        Machine::Rust(dtls) => dtls,
        Machine::Openssl(old) => {
            for datagram in old.take_datagrams() {
                if let Err(error) = send_to(socket, &datagram, conn.address) {
                    return Err(send_problem(conn.address, datagram.len(), &error));
                }
            }
            for seen in old.take_seen() {
                match seen {
                    Seen::Connected => happened.push(Happened::Connected),
                    Seen::Data(bytes) => happened.push(Happened::Data(bytes)),
                    Seen::Closed => {
                        conn.ended.get_or_insert(None);
                    }
                }
            }
            conn.next = old.next_timeout();
            return Ok(happened);
        }
    };
    loop {
        match dtls.poll_output(buf) {
            Output::Packet(packet) => {
                if let Err(error) = send_to(socket, packet, conn.address) {
                    return Err(send_problem(conn.address, packet.len(), &error));
                }
            }
            Output::BufferTooSmall { needed } => buf.resize(needed, 0),
            Output::Timeout(at) => {
                conn.next = Some(at);
                return Ok(happened);
            }
            Output::Connected => happened.push(Happened::Connected),
            Output::PeerCert(der) => conn.cert = Some(der.to_vec()),
            Output::ApplicationData(data) => happened.push(Happened::Data(data.to_vec())),
            Output::CloseNotify => {
                conn.ended.get_or_insert(None);
            }
            _ => {}
        }
    }
}

/// What a connection's handshake agreed, as far as its engine says.
fn agreed(conn: &Conn, options: &DtlsOptions) -> Agreed {
    let dtls = match &conn.machine {
        Machine::Rust(dtls) => dtls,
        Machine::Openssl(old) => return old.agreed(),
    };
    let version = match dtls.protocol_version() {
        Some(ProtocolVersion::DTLS1_3) => "DTLS 1.3",
        _ => "DTLS 1.2",
    };
    let suite = if options.psk {
        "TLS_PSK_WITH_AES_128_CCM_8".to_string()
    } else if version == "DTLS 1.3" {
        "TLS 1.3 AEAD (AES-GCM or ChaCha20-Poly1305)".to_string()
    } else {
        "ECDHE-ECDSA with AES-GCM or ChaCha20-Poly1305".to_string()
    };
    Agreed {
        version: version.into(),
        suite,
        group: String::new(),
        alpn: String::new(),
        name: if options.psk {
            // The identity the other end gave, or this end's own.
            let set = options.psk_identity.trim();
            match conn
                .identity
                .as_deref()
                .filter(|identity| !identity.is_empty())
            {
                Some(identity) => format!("PSK identity {identity}"),
                None if !set.is_empty() => format!("PSK identity {set}"),
                None => "PSK".into(),
            }
        } else {
            String::new()
        },
        resumed: false,
        chain: conn.cert.iter().map(|der| tls::describe(der)).collect(),
    }
}

/// A DTLS error in plain words.
fn dtls_problem(error: &dimpl::Error, connected: bool) -> String {
    let text = error.to_string();
    let lower = text.to_lowercase();
    if lower.contains("timeout") || lower.contains("timed out") {
        if connected {
            "The DTLS connection timed out.".into()
        } else {
            NOT_FINISHED.into()
        }
    } else if lower.contains("psk") {
        format!("The PSK was turned down: {text}. Check the identity and the key on both ends.")
    } else if lower.contains("certificate") {
        format!("A certificate was turned down: {text}.")
    } else if lower.contains("closed") {
        "The other end closed the connection.".into()
    } else {
        format!("DTLS failed: {text}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::tests::{AT_ONCE, FAST, SLOW_POLL, expect, received, state};

    fn server(options: DtlsOptions) -> (DtlsSession, Receiver<Event>, u16) {
        server_timed(options, FAST)
    }

    fn server_timed(options: DtlsOptions, timing: Timing) -> (DtlsSession, Receiver<Event>, u16) {
        let (sender, events) = mpsc::channel();
        let session = DtlsSession::start_with(
            UdpConfig {
                local_address: "127.0.0.1".into(),
                ..UdpConfig::default()
            },
            options,
            false,
            Box::new(move |event| {
                let _ = sender.send(event);
            }),
            timing,
        );
        let NetState::Listening { local } = state(&events, "listening", |state| {
            matches!(state, NetState::Listening { .. })
        }) else {
            unreachable!()
        };
        let port = local.rsplit(':').next().unwrap().parse().unwrap();
        (session, events, port)
    }

    fn client(port: u16, options: DtlsOptions) -> (DtlsSession, Receiver<Event>) {
        client_timed(port, options, FAST)
    }

    fn client_timed(
        port: u16,
        options: DtlsOptions,
        timing: Timing,
    ) -> (DtlsSession, Receiver<Event>) {
        let (sender, events) = mpsc::channel();
        let session = DtlsSession::start_with(
            UdpConfig {
                local_address: "127.0.0.1".into(),
                remote_host: "127.0.0.1".into(),
                remote_port: port,
                ..UdpConfig::default()
            },
            options,
            true,
            Box::new(move |event| {
                let _ = sender.send(event);
            }),
            timing,
        );
        (session, events)
    }

    #[test]
    fn records_sent_go_out_at_once_both_ways() {
        let options = DtlsOptions {
            psk: true,
            psk_identity: "sensor-7".into(),
            psk_key: "0102030405060708".into(),
            ..DtlsOptions::default()
        };
        let (server, server_events, port) = server_timed(options.clone(), SLOW_POLL);
        let (client, client_events) = client_timed(port, options, SLOW_POLL);
        let (me, _) = secure(&client_events);
        let (peer, _) = secure(&server_events);
        // Both threads are in their long waits: each send has to wake one.
        thread::sleep(Duration::from_millis(50));
        for _ in 0..3 {
            let start = Instant::now();
            client.send(Target::Default, b"up".to_vec());
            assert_eq!(received(&server_events, peer, 2), b"up");
            server.send(Target::Peer(peer), b"down".to_vec());
            assert_eq!(received(&client_events, me, 4), b"down");
            assert!(start.elapsed() < AT_ONCE, "{:?}", start.elapsed());
        }
    }

    fn secure(events: &Receiver<Event>) -> (PeerId, Agreed) {
        match expect(events, "DTLS", |event| {
            matches!(event, Event::Secure { .. })
        }) {
            Event::Secure { peer, agreed } => (peer, agreed),
            _ => unreachable!(),
        }
    }

    #[test]
    fn keys_are_hex_or_text() {
        assert_eq!(psk_key("00 01:ff").unwrap(), [0, 1, 255]);
        assert_eq!(psk_key("\"secret\"").unwrap(), b"secret");
        assert!(psk_key("xyz").is_err());
        assert!(psk_key("abc").is_err());
    }

    #[test]
    fn a_client_and_a_server_talk_with_certificates_in_both_versions() {
        for version in [DtlsVersion::Dtls12, DtlsVersion::Dtls13, DtlsVersion::Auto] {
            let options = DtlsOptions {
                version,
                ..DtlsOptions::default()
            };
            let (server, server_events, port) = server(options.clone());
            let (client, client_events) = client(port, options);
            let (me, agreed) = secure(&client_events);
            assert!(agreed.version.starts_with("DTLS 1."), "{agreed:?}");
            assert_eq!(agreed.chain.len(), 1, "the server's certificate is shown");
            let (peer, _) = secure(&server_events);
            client.send(Target::Default, b"hello over DTLS".to_vec());
            assert_eq!(received(&server_events, peer, 15), b"hello over DTLS");
            server.send(Target::Peer(peer), b"and back".to_vec());
            assert_eq!(received(&client_events, me, 8), b"and back");
        }
    }

    #[test]
    fn a_client_and_a_server_talk_with_a_psk() {
        let options = DtlsOptions {
            psk: true,
            psk_identity: "sensor-7".into(),
            psk_key: "0102030405060708".into(),
            ..DtlsOptions::default()
        };
        let (_server, server_events, port) = server(DtlsOptions {
            psk_identity: String::new(),
            ..options.clone()
        });
        let (client, client_events) = client(port, options);
        let (_, agreed) = secure(&client_events);
        assert_eq!(agreed.suite, "TLS_PSK_WITH_AES_128_CCM_8");
        assert_eq!(agreed.name, "PSK identity sensor-7");
        // The server takes any identity, and shows the one the client gave.
        let (peer, seen) = secure(&server_events);
        assert_eq!(seen.name, "PSK identity sensor-7");
        client.send(Target::Default, b"psk".to_vec());
        assert_eq!(received(&server_events, peer, 3), b"psk");
    }

    #[test]
    fn a_wrong_psk_does_not_connect() {
        let (_server, _server_events, port) = server(DtlsOptions {
            psk: true,
            psk_key: "0102030405060708".into(),
            ..DtlsOptions::default()
        });
        let (_client, client_events) = client(
            port,
            DtlsOptions {
                psk: true,
                psk_key: "ffffffffffffffff".into(),
                ..DtlsOptions::default()
            },
        );
        let problem = match expect(&client_events, "problem", |event| {
            matches!(event, Event::Problem(_))
        }) {
            Event::Problem(problem) => problem,
            _ => unreachable!(),
        };
        assert!(!problem.is_empty());
    }

    fn problem(events: &Receiver<Event>) -> String {
        match expect(events, "problem", |event| {
            matches!(event, Event::Problem(_))
        }) {
            Event::Problem(problem) => problem,
            _ => unreachable!(),
        }
    }

    /// DTLS over OpenSSL, the engine for old and small devices.
    mod openssl_engine {
        use super::*;

        fn old(version: DtlsVersion) -> DtlsOptions {
            DtlsOptions {
                version,
                engine: Engine::Openssl,
                ..DtlsOptions::default()
            }
        }

        fn psk(engine: Engine, ciphers: &str) -> DtlsOptions {
            DtlsOptions {
                version: DtlsVersion::Dtls12,
                engine,
                ciphers: ciphers.into(),
                psk: true,
                psk_identity: "sensor-7".into(),
                psk_key: "0102030405060708".into(),
                ..DtlsOptions::default()
            }
        }

        /// A client and a server that connect, and bytes both ways.
        fn talk(server_options: DtlsOptions, client_options: DtlsOptions) -> (Agreed, Agreed) {
            let (server_end, server_events, port) = server(server_options);
            let (client_end, client_events) = client(port, client_options);
            let (me, agreed) = secure(&client_events);
            let (peer, seen) = secure(&server_events);
            client_end.send(Target::Default, b"hello over DTLS".to_vec());
            assert_eq!(received(&server_events, peer, 15), b"hello over DTLS");
            server_end.send(Target::Peer(peer), b"and back".to_vec());
            assert_eq!(received(&client_events, me, 8), b"and back");
            (agreed, seen)
        }

        #[test]
        fn dtls_1_0_and_1_2_are_spoken() {
            for (version, said) in [
                (DtlsVersion::Dtls10, "DTLS 1.0 (OpenSSL)"),
                (DtlsVersion::Dtls12, "DTLS 1.2 (OpenSSL)"),
                (DtlsVersion::All, "DTLS 1.2 (OpenSSL)"),
            ] {
                let (agreed, seen) = talk(old(version), old(version));
                assert_eq!(agreed.version, said, "{agreed:?}");
                assert_eq!(seen.version, said, "{seen:?}");
                assert_eq!(agreed.chain.len(), 1, "the server's certificate is shown");
            }
        }

        #[test]
        fn a_psk_takes_the_suite_asked_for() {
            for (ciphers, suite) in [
                ("PSK-AES128-CBC-SHA256", "TLS_PSK_WITH_AES_128_CBC_SHA256"),
                ("PSK-AES128-CCM8", "TLS_PSK_WITH_AES_128_CCM_8"),
            ] {
                let (agreed, seen) = talk(
                    DtlsOptions {
                        psk_identity: String::new(),
                        ..psk(Engine::Openssl, "")
                    },
                    psk(Engine::Openssl, ciphers),
                );
                assert_eq!(agreed.suite, suite, "{agreed:?}");
                assert_eq!(agreed.name, "PSK identity sensor-7", "{agreed:?}");
                assert_eq!(seen.name, "PSK identity sensor-7", "{seen:?}");
            }
        }

        #[test]
        fn a_wrong_psk_does_not_connect() {
            let (_server, _server_events, port) = server(psk(Engine::Openssl, ""));
            let (_client, client_events) = client(
                port,
                DtlsOptions {
                    psk_key: "ffffffffffffffff".into(),
                    ..psk(Engine::Openssl, "")
                },
            );
            let said = problem(&client_events);
            assert!(said.contains("PSK"), "{said}");
        }

        #[test]
        fn each_engine_talks_to_the_other() {
            let rust = DtlsOptions {
                version: DtlsVersion::Dtls12,
                engine: Engine::Rustls,
                ..DtlsOptions::default()
            };
            let auto = DtlsOptions {
                version: DtlsVersion::Auto,
                ..rust.clone()
            };
            let openssl = old(DtlsVersion::Auto);
            for (server_options, client_options) in [
                (rust.clone(), openssl.clone()),
                (openssl.clone(), rust),
                (openssl, auto),
            ] {
                let (agreed, seen) = talk(server_options, client_options);
                assert!(agreed.version.starts_with("DTLS 1.2"), "{agreed:?}");
                assert!(seen.version.starts_with("DTLS 1.2"), "{seen:?}");
            }
            // dimpl's PSK suite, with OpenSSL at either end.
            for (server_engine, client_engine) in [
                (Engine::Rustls, Engine::Openssl),
                (Engine::Openssl, Engine::Rustls),
            ] {
                let (agreed, _) = talk(psk(server_engine, ""), psk(client_engine, ""));
                assert!(agreed.suite.contains("CCM_8"), "{agreed:?}");
            }
        }

        #[test]
        fn a_long_send_goes_in_records_that_fit_a_datagram() {
            let (_server, server_events, port) = server(old(DtlsVersion::Dtls12));
            let (client_end, client_events) = client(port, old(DtlsVersion::Dtls12));
            secure(&client_events);
            let (from, _) = secure(&server_events);
            let long: Vec<u8> = (0..40_000u32).map(|at| (at % 251) as u8).collect();
            client_end.send(Target::Default, long.clone());
            // Each record comes as data of its own, and none is bigger than
            // the MTU of 1200 bytes lets it be.
            let (mut data, mut records) = (Vec::new(), 0);
            while data.len() < long.len() {
                if let Event::Data { bytes, .. } = expect(
                    &server_events,
                    "data",
                    |event| matches!(event, Event::Data { peer, .. } if *peer == from),
                ) {
                    assert!(bytes.len() < 1200, "{} bytes in a record", bytes.len());
                    records += 1;
                    data.extend(bytes);
                }
            }
            assert_eq!(data, long);
            assert!(records > 33, "{records} records");
        }

        #[test]
        fn a_server_without_cookies_takes_clients_too() {
            let (agreed, _) = talk(
                DtlsOptions {
                    cookie: false,
                    ..old(DtlsVersion::Dtls12)
                },
                old(DtlsVersion::Dtls12),
            );
            assert_eq!(agreed.version, "DTLS 1.2 (OpenSSL)");
        }

        #[test]
        fn an_ecdsa_suite_with_ccm_8_can_be_asked_for() {
            let (agreed, seen) = talk(
                old(DtlsVersion::Dtls12),
                DtlsOptions {
                    ciphers: "ECDHE-ECDSA-AES128-CCM8".into(),
                    ..DtlsOptions::default()
                },
            );
            for end in [agreed, seen] {
                assert_eq!(end.suite, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", "{end:?}");
                assert_eq!(end.version, "DTLS 1.2 (OpenSSL)", "{end:?}");
            }
        }

        #[test]
        fn a_server_certificate_not_trusted_is_turned_down() {
            let (_server, _server_events, port) = server(old(DtlsVersion::Dtls12));
            let (_client, client_events) = client(
                port,
                DtlsOptions {
                    verify: Verify::System,
                    ..old(DtlsVersion::Dtls12)
                },
            );
            let said = problem(&client_events);
            assert!(said.contains("certificate was turned down"), "{said}");
        }

        #[test]
        fn old_versions_and_suites_pick_openssl_by_themselves() {
            let with = |version, ciphers: &str| DtlsOptions {
                version,
                ciphers: ciphers.into(),
                ..DtlsOptions::default()
            };
            assert_eq!(over_openssl(&with(DtlsVersion::Dtls10, "")), Ok(true));
            assert_eq!(over_openssl(&with(DtlsVersion::All, "")), Ok(true));
            assert_eq!(
                over_openssl(&with(DtlsVersion::Dtls12, "PSK-AES128-CBC-SHA256")),
                Ok(true)
            );
            assert_eq!(over_openssl(&with(DtlsVersion::Auto, "")), Ok(false));
            assert_eq!(over_openssl(&psk(Engine::Auto, "")), Ok(false));
            assert!(
                over_openssl(&DtlsOptions {
                    engine: Engine::Rustls,
                    ..with(DtlsVersion::Dtls10, "")
                })
                .is_err()
            );
        }

        #[test]
        fn dtls_1_3_is_not_asked_of_openssl() {
            let (sender, events) = mpsc::channel();
            let _session = DtlsSession::start_with(
                UdpConfig {
                    local_address: "127.0.0.1".into(),
                    ..UdpConfig::default()
                },
                old(DtlsVersion::Dtls13),
                false,
                Box::new(move |event| {
                    let _ = sender.send(event);
                }),
                FAST,
            );
            let NetState::Waiting { problem } = state(&events, "waiting", |state| {
                matches!(state, NetState::Waiting { problem: Some(_) })
            }) else {
                unreachable!()
            };
            let problem = problem.unwrap_or_default();
            assert!(
                problem.contains("DTLS 1.3 is spoken by the Rust engine"),
                "{problem}"
            );
        }
    }
}
