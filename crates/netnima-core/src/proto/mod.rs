//! Protocols on top of the sockets. Each is an engine between a socket and
//! the tab: lines typed in the send box are its commands, such as
//! `pub sensors/temp 21.5`, and every message that goes or comes is shown as
//! a line people read, such as `← PUBLISH sensors/temp: 21.5`.
//!
//! An engine runs on the protocol session's own thread, with the socket's
//! events, the commands and a tick ten times a second for its timers, so it
//! needs no locks of its own.

pub mod cbor;
pub mod coap;
pub mod dhcp;
pub mod discovery;
pub mod echo;
pub mod ftp;
pub mod http;
pub mod iperf;
pub mod lwm2m;
pub mod modbus;
pub mod mqtt;
pub mod mqttsn;
pub mod ping;
pub mod services;
pub mod smp;
pub mod snmp;
pub mod stun;
pub mod websocket;
mod words;

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::net::{
    DtlsOptions, DtlsSession, Event, Peer, PeerId, Target, TcpClient, TcpClientConfig, TcpServer,
    TcpServerConfig, TlsClientOptions, TlsServerOptions, UdpConfig, UdpSession,
};
pub use words::{Words, hex_text, payload_text};

/// How often an engine's timers are looked at.
const TICK: Duration = Duration::from_millis(100);

/// The TLS settings of a protocol's TCP socket, for an engine that makes
/// connections of its own with them, as FTPS does for its data.
#[derive(Clone, Debug)]
pub enum SocketTls {
    Client(TlsClientOptions),
    Server(TlsServerOptions),
}

/// How an engine wants its socket's TLS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TlsUse {
    /// TLS waits until the engine asks for it with [`Io::start_tls`], as
    /// FTP's AUTH TLS does.
    pub later: bool,
    /// Connections the engine makes of its own, with the same settings,
    /// take up the socket's TLS session, as FTPS's data connections do.
    pub shared: bool,
}

/// The socket under a protocol: the UI sends the one the protocol uses.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SocketSetup {
    pub udp: Option<UdpConfig>,
    pub client: Option<TcpClientConfig>,
    pub server: Option<TcpServerConfig>,
    /// DTLS on the UDP socket, such as CoAP's coaps.
    pub dtls: Option<DtlsOptions>,
}

/// A running socket of any kind.
pub(crate) enum Socket {
    /// No socket: the engine does its own work, as ping does.
    None,
    Udp(UdpSession),
    Dtls(DtlsSession),
    Client(TcpClient),
    Server(TcpServer),
}

impl Socket {
    fn write(&self, target: Target, bytes: Vec<u8>) {
        match self {
            Socket::None => {}
            Socket::Udp(session) => session.send(target, bytes),
            Socket::Dtls(session) => session.send(target, bytes),
            Socket::Client(client) => client.write(bytes),
            Socket::Server(server) => server.write(target, bytes),
        }
    }

    fn drop_peer(&self, peer: PeerId) {
        match self {
            Socket::Server(server) => server.drop_peer(peer, false),
            Socket::Client(client) => client.hang_up(),
            Socket::None | Socket::Udp(_) | Socket::Dtls(_) => {}
        }
    }

    fn start_tls(&self, peer: PeerId, before: Vec<u8>) {
        match self {
            Socket::Server(server) => server.start_tls(peer, before),
            Socket::Client(client) => client.start_tls(before),
            Socket::None | Socket::Udp(_) | Socket::Dtls(_) => {}
        }
    }

    /// Whether `retarget` can change where the socket sends.
    fn set_remote(&self, at: std::net::SocketAddr) -> bool {
        match self {
            Socket::Udp(session) => {
                session.set_remote(at);
                true
            }
            Socket::None | Socket::Dtls(_) | Socket::Client(_) | Socket::Server(_) => false,
        }
    }
}

/// What an engine acts with: the socket to send on, and the tab to tell.
pub struct Io<'a> {
    socket: &'a Socket,
    tell: &'a mut dyn FnMut(Event),
    /// For an engine inside another, such as MQTT inside WebSocket: what it
    /// sends, held for the outer one to pass on.
    held: Option<&'a mut Vec<(Target, Vec<u8>)>>,
}

const CAME: &str = "\x1b[32m\u{2190}\x1b[0m ";
const WENT: &str = "\x1b[36m\u{2192}\x1b[0m ";
const NOTE: &str = "\x1b[2m";
const BAD: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

impl Io<'_> {
    /// Sends bytes on the socket: to the other end of a client, a UDP tab's
    /// remote address with `Target::Default`, one peer, or all.
    pub fn send(&mut self, target: Target, bytes: Vec<u8>) {
        match self.held.as_deref_mut() {
            Some(held) => held.push((target, bytes)),
            None => self.socket.write(target, bytes),
        }
    }

    /// An `Io` for an engine inside this one: what it sends is held in
    /// `held`, and the rest it does goes where this one's does.
    pub(crate) fn holding<'b>(&'b mut self, held: &'b mut Vec<(Target, Vec<u8>)>) -> Io<'b> {
        Io {
            socket: self.socket,
            tell: &mut *self.tell,
            held: Some(held),
        }
    }

    /// Shows a message that came from `peer`, one line, with any more lines
    /// of it indented under it.
    pub fn came(&mut self, peer: PeerId, text: &str) {
        self.line(peer, CAME, text, "", true);
    }

    /// Shows a message this end sent to `peer`.
    pub fn went(&mut self, peer: PeerId, text: &str) {
        self.line(peer, WENT, text, "", true);
    }

    /// Shows a note of the engine's own, such as the answer to `help`.
    pub fn note(&mut self, text: &str) {
        self.line(0, NOTE, text, RESET, false);
    }

    /// Shows what is wrong with a command, or with what came.
    pub fn bad(&mut self, text: &str) {
        self.line(0, BAD, text, RESET, false);
    }

    /// Tells the tab something that does not end the session, as the status bar shows it.
    pub fn problem(&mut self, text: impl Into<String>) {
        (self.tell)(Event::Problem(text.into()));
    }

    /// Tells the tab's view what happened, as an object with a `type`, such
    /// as `{"type": "message", "topic": ..}`: the lines say it for people.
    pub fn report(&mut self, report: serde_json::Value) {
        (self.tell)(Event::Report(report));
    }

    /// Ends one peer's connection: a server's client, or a client's own connection.
    pub fn drop_peer(&mut self, peer: PeerId) {
        self.socket.drop_peer(peer);
    }

    /// Sends `before` as it is, then starts TLS on the peer's connection, as
    /// FTP's AUTH TLS does: a server's "234" goes in `before`, so nothing
    /// comes between them. The engine asked for this with [`Engine::tls`].
    pub fn start_tls(&mut self, peer: PeerId, before: Vec<u8>) {
        self.socket.start_tls(peer, before);
    }

    /// Sends what goes to no one in particular to `at` from now on, as an
    /// LwM2M device does after bootstrap. Only a UDP socket can: false for
    /// the others, which keep their other end.
    pub fn retarget(&mut self, at: std::net::SocketAddr) -> bool {
        self.socket.set_remote(at)
    }

    /// Writes `text` a line at a time, `before` and `after` each; the lines
    /// after the first are indented under it when `indent`.
    fn line(&mut self, peer: PeerId, before: &str, text: &str, after: &str, indent: bool) {
        let mut out = String::with_capacity(text.len() + 16);
        for (index, line) in text.lines().enumerate() {
            if index == 0 || !indent {
                out.push_str(before);
            } else {
                out.push_str("    ");
            }
            out.push_str(line);
            out.push_str(after);
            out.push_str("\r\n");
        }
        if out.is_empty() {
            out.push_str(before);
            out.push_str(after);
            out.push_str("\r\n");
        }
        (self.tell)(Event::Data {
            peer,
            bytes: out.into_bytes(),
        });
    }
}

/// A protocol's two ends are each an engine: it is told what the socket
/// does and what is typed, and acts through `Io`.
pub trait Engine: Send {
    /// The commands it takes, one per line, for `help`.
    fn help(&self) -> &'static str;

    /// A peer came: a client's connection was made, a server took a client,
    /// or a datagram came from an address not heard before.
    fn joined(&mut self, _peer: &Peer, _io: &mut Io) {}

    /// A peer went.
    fn left(&mut self, _peer: PeerId, _io: &mut Io) {}

    /// Bytes that came from a peer: a piece of its stream, or one datagram.
    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io);

    /// A line typed in the send box, without its line end.
    fn command(&mut self, words: &mut Words, io: &mut Io);

    /// About ten times a second, for keep-alives and answers that do not come.
    fn tick(&mut self, _now: Instant, _io: &mut Io) {}

    /// Told the TLS settings of the tab's TCP socket, if it has any, before
    /// the socket starts; says how it wants them used.
    fn tls(&mut self, _tls: Option<SocketTls>) -> TlsUse {
        TlsUse::default()
    }
}

/// Which socket a kind of tab runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketKind {
    /// None: the engine does its own work.
    None,
    Udp,
    Client,
    Server,
}

/// The engine for a kind of tab, such as "mqtt_client", with its options
/// from the tab's settings, and the socket it runs on.
pub fn engine(
    kind: &str,
    options: serde_json::Value,
) -> Result<(Box<dyn Engine>, SocketKind), String> {
    use SocketKind::{Client, Server, Udp};
    let none = SocketKind::None;
    let carriage: websocket::Carriage = read(options.clone())?;
    let made: (Box<dyn Engine>, SocketKind) = match kind {
        "mqtt_client" => {
            let client = mqtt::Client::new(read(options)?);
            if carriage.websocket {
                let over = websocket::Carrier::client(client, carriage.upgrade("mqtt"));
                (Box::new(over), Client)
            } else {
                (Box::new(client), Client)
            }
        }
        "mqtt_server" => {
            let broker = mqtt::Broker::new(read(options)?);
            if carriage.websocket {
                (Box::new(websocket::Carrier::server(broker, "mqtt")), Server)
            } else {
                (Box::new(broker), Server)
            }
        }
        "coap_client" => (Box::new(coap::Client::new(read(options)?)), Udp),
        "coap_server" => (Box::new(coap::Server::new(read(options)?)), Udp),
        "coap_tcp_client" => (
            Box::new(coap::OverTcp::new(coap::Client::new(read(options)?))),
            Client,
        ),
        "coap_tcp_server" => (
            Box::new(coap::OverTcp::new(coap::Server::new(read(options)?))),
            Server,
        ),
        "coap_ws_client" => {
            let mut upgrade = carriage.upgrade("coap");
            if options.get("path").is_none() {
                upgrade.path = "/.well-known/coap".into();
            }
            let client = coap::OverTcp::over_websocket(coap::Client::new(read(options)?));
            (
                Box::new(websocket::Carrier::client(client, upgrade).whole_messages()),
                Client,
            )
        }
        "coap_ws_server" => {
            let server = coap::OverTcp::over_websocket(coap::Server::new(read(options)?));
            (
                Box::new(websocket::Carrier::server(server, "coap").whole_messages()),
                Server,
            )
        }
        "modbus_client" => (Box::new(modbus::Master::new(read(options)?)), Client),
        "modbus_server" => (Box::new(modbus::Slave::new(read(options)?)), Server),
        "http_client" => (Box::new(http::Client::new(read(options)?)), Client),
        "http_server" => (Box::new(http::Server::new(read(options)?)), Server),
        "websocket_client" => (Box::new(websocket::Client::new(read(options)?)), Client),
        "websocket_server" => (Box::new(websocket::Server::new(read(options)?)), Server),
        "syslog_client" => (Box::new(services::SyslogSender::new(read(options)?)), Udp),
        "syslog_server" => (Box::new(services::SyslogReceiver::default()), Udp),
        "syslog_tcp_client" => (
            Box::new(services::SyslogSender::over_stream(read(options)?)),
            Client,
        ),
        "syslog_tcp_server" => (Box::new(services::SyslogReceiver::over_stream()), Server),
        "ntp_client" => (Box::new(services::NtpClient::default()), Udp),
        "ntp_server" => (Box::new(services::NtpServer), Udp),
        "wol_client" => (Box::new(services::WakeSender), Udp),
        "wol_server" => (Box::new(services::WakeListener), Udp),
        "dns_client" => (Box::new(services::DnsClient::default()), Udp),
        "dns_server" => (Box::new(services::DnsServer::new(read(options)?)), Udp),
        "dns_tcp_client" => (Box::new(services::DnsClient::over_stream()), Client),
        "dns_tcp_server" => (
            Box::new(services::DnsServer::over_stream(read(options)?)),
            Server,
        ),
        "tftp_client" => (Box::new(services::TftpClient::new(read(options)?)), Udp),
        "tftp_server" => (Box::new(services::TftpServer::new(read(options)?)), Udp),
        "iperf_client" => (Box::new(iperf::Client::new(read(options)?, false)), Client),
        "iperf_server" => (Box::new(iperf::Server::new(false)), Server),
        "iperf_udp_client" => (Box::new(iperf::Client::new(read(options)?, true)), Udp),
        "iperf_udp_server" => (Box::new(iperf::Server::new(true)), Udp),
        // The echo client does its own sending, to time round trips truly.
        "echo_client" => (Box::new(echo::Client::new(read(options)?, false)), none),
        "echo_server" => (Box::new(echo::Server::new(read(options)?)), Server),
        "echo_udp_client" => (Box::new(echo::Client::new(read(options)?, true)), none),
        "echo_udp_server" => (Box::new(echo::Server::new(read(options)?)), Udp),
        "ping" => (Box::new(ping::Ping::new(read(options)?)), none),
        "ftp_client" => (Box::new(ftp::Client::new(read(options)?)), Client),
        "ftp_server" => (Box::new(ftp::Server::new(read(options)?)), Server),
        "dhcp_client" => (Box::new(dhcp::Client::new(read(options)?)), Udp),
        "dhcp_server" => (Box::new(dhcp::Server::new(read(options)?)), Udp),
        "lwm2m_client" => (Box::new(lwm2m::Client::new(read(options)?)), Udp),
        "lwm2m_server" => (Box::new(lwm2m::Server::new(read(options)?)), Udp),
        "mcumgr_client" => (Box::new(smp::Client::new(read(options)?)), Udp),
        "mcumgr_server" => (Box::new(smp::Device::default()), Udp),
        "mdns_client" => (Box::new(discovery::MdnsBrowser::default()), Udp),
        "mdns_server" => (
            Box::new(discovery::MdnsAdvertiser::new(read(options)?)),
            Udp,
        ),
        "ssdp_client" => (Box::new(discovery::SsdpSearch::default()), Udp),
        "ssdp_server" => (Box::new(discovery::SsdpAnswer::new(read(options)?)), Udp),
        "mqttsn_client" => (Box::new(mqttsn::Client::new(read(options)?)), Udp),
        "mqttsn_server" => (Box::new(mqttsn::Gateway::new(read(options)?)), Udp),
        "stun_client" => (Box::new(stun::Client::default()), Udp),
        "stun_server" => (Box::new(stun::Server::default()), Udp),
        "snmp_client" => (Box::new(snmp::Manager::new(read(options)?)), Udp),
        "snmp_server" => (Box::new(snmp::Agent::new(read(options)?)), Udp),
        _ => return Err(format!("netNIMA has no engine for {kind} tabs yet.")),
    };
    Ok(made)
}

/// Bytes as a view reads them in a report: two hex digits a byte.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What a kind of tab takes in its send box, from its engine's `help`, for
/// the send box to offer while a line is typed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ProtocolHelp {
    /// Its commands, in help's order, then `help` itself.
    pub commands: Vec<CommandHelp>,
    /// What help says besides, such as "Numbers may be hex: 0x10.", a sentence each.
    pub notes: Vec<String>,
}

/// One command, from a line of `help`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandHelp {
    /// How it is typed, such as `pub [-q0|-q1|-q2] [-r] <topic> <payload>`;
    /// one that starts with `<` or `[`, such as `<text>`, stands for any line
    /// that is not a command.
    pub usage: String,
    /// What it does.
    pub what: String,
}

/// What a kind of tab takes, as `help` says it; `None` for a kind with no
/// engine, such as a plain TCP tab. An engine is made with its default
/// settings to ask: it does nothing until a session runs it.
pub fn help_for(kind: &str) -> Option<ProtocolHelp> {
    let (engine, _) = engine(kind, serde_json::Value::Null).ok()?;
    let mut help = parse_help(engine.help());
    help.commands.push(CommandHelp {
        usage: "help".into(),
        what: "list these commands".into(),
    });
    Some(help)
}

/// The lines of `help`: a command is how it is typed, two spaces or more,
/// then what it does; a line without such a gap is a note. An indented line
/// goes on with the line before, and so does a note's sentence that goes on
/// in lower case.
fn parse_help(text: &str) -> ProtocolHelp {
    let mut help = ProtocolHelp::default();
    // Whether the line before was a note, for a line that goes on with it.
    let mut in_note = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let goes_on = line.starts_with(char::is_whitespace)
            || (in_note && line.starts_with(char::is_lowercase) && !line.contains("  "));
        let last = match (goes_on, in_note) {
            (false, _) => None,
            (true, true) => help.notes.last_mut(),
            (true, false) => help.commands.last_mut().map(|command| &mut command.what),
        };
        if let Some(last) = last {
            last.push(' ');
            last.push_str(line.trim());
            continue;
        }
        let line = line.trim();
        in_note = match line.split_once("  ") {
            Some((usage, what)) => {
                help.commands.push(CommandHelp {
                    usage: usage.trim_end().to_string(),
                    what: what.trim_start().to_string(),
                });
                false
            }
            None => {
                help.notes.push(line.to_string());
                true
            }
        };
    }
    help
}

/// An engine's options from the tab's settings: what is missing takes its default.
fn read<T: DeserializeOwned + Default>(options: serde_json::Value) -> Result<T, String> {
    if options.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(options)
        .map_err(|error| format!("The tab's settings cannot be read: {error}"))
}

enum Input {
    Socket(Event),
    Typed(Vec<u8>),
    Close,
}

/// A protocol tab's session: its socket and its engine, on a thread of
/// their own. Dropping it closes both.
pub struct ProtocolSession {
    inputs: Sender<Input>,
    thread: Option<JoinHandle<()>>,
}

impl ProtocolSession {
    /// Starts the socket the engine runs on and the engine. What happens
    /// comes back through `on_event`: the socket's state and peers as they
    /// are, and each message as a line of text, as data from its peer.
    pub fn start(
        kind: &str,
        options: serde_json::Value,
        setup: SocketSetup,
        on_event: impl FnMut(Event) + Send + 'static,
    ) -> Result<Self, String> {
        let (engine, socket_kind) = engine(kind, options)?;
        // The kinds of tab are named for their end: "coap_client", "coap_server".
        let client = kind.ends_with("_client");
        // What comes goes to the engine at once, not in batches for the
        // screen: an engine shows its own lines, and times round trips.
        let timing = crate::net::Timing {
            batch: Duration::ZERO,
            ..crate::net::TIMING
        };
        Self::start_with(
            engine,
            socket_kind,
            client,
            setup,
            Box::new(on_event),
            timing,
        )
    }

    pub(crate) fn start_with(
        mut engine: Box<dyn Engine>,
        socket_kind: SocketKind,
        client: bool,
        mut setup: SocketSetup,
        on_event: Box<dyn FnMut(Event) + Send>,
        timing: crate::net::Timing,
    ) -> Result<Self, String> {
        // The engine learns the socket's TLS, and says whether it waits.
        let tls = match socket_kind {
            SocketKind::Client => setup
                .client
                .as_ref()
                .and_then(|client| client.tls.clone())
                .map(SocketTls::Client),
            SocketKind::Server => setup
                .server
                .as_ref()
                .and_then(|server| server.tls.clone())
                .map(SocketTls::Server),
            SocketKind::None | SocketKind::Udp => None,
        };
        let wanted = engine.tls(tls);
        if let Some(tls) = setup.client.as_mut().and_then(|client| client.tls.as_mut()) {
            tls.starttls |= wanted.later;
            tls.share_sessions |= wanted.shared;
        }
        if let Some(tls) = setup.server.as_mut().and_then(|server| server.tls.as_mut()) {
            tls.starttls |= wanted.later;
            tls.share_sessions |= wanted.shared;
        }
        let (inputs, receiver) = mpsc::channel();
        let from_socket = inputs.clone();
        let pass = move |event| {
            let _ = from_socket.send(Input::Socket(event));
        };
        let socket = match socket_kind {
            SocketKind::None => Socket::None,
            SocketKind::Udp => match setup.dtls {
                Some(dtls) => Socket::Dtls(DtlsSession::start_with(
                    setup.udp.unwrap_or_default(),
                    dtls,
                    client,
                    Box::new(pass),
                    timing,
                )),
                None => Socket::Udp(UdpSession::start_with(
                    setup.udp.unwrap_or_default(),
                    Box::new(pass),
                    timing,
                )),
            },
            SocketKind::Client => Socket::Client(TcpClient::start_with(
                setup.client.ok_or("The tab has no client settings.")?,
                Box::new(pass),
                timing,
            )),
            SocketKind::Server => Socket::Server(TcpServer::start_with(
                setup.server.ok_or("The tab has no server settings.")?,
                Box::new(pass),
                timing,
            )),
        };
        let thread = thread::Builder::new()
            .name("netnima-protocol".into())
            .spawn(move || run(engine, socket, receiver, on_event))
            .map_err(|error| format!("Could not start the protocol: {error}"))?;
        Ok(Self {
            inputs,
            thread: Some(thread),
        })
    }

    /// Bytes typed: each line in them is a command, and an unfinished line
    /// waits for the rest.
    pub fn typed(&self, bytes: Vec<u8>) {
        let _ = self.inputs.send(Input::Typed(bytes));
    }

    /// One command, as if typed with its line end.
    pub fn command(&self, line: &str) {
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        self.typed(bytes);
    }
}

impl Drop for ProtocolSession {
    fn drop(&mut self) {
        let _ = self.inputs.send(Input::Close);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(
    mut engine: Box<dyn Engine>,
    socket: Socket,
    inputs: Receiver<Input>,
    mut on_event: Box<dyn FnMut(Event) + Send>,
) {
    // With no socket to say so, the session is open as soon as it runs.
    if matches!(socket, Socket::None) {
        on_event(Event::State(crate::net::NetState::Listening {
            local: "this PC".into(),
        }));
    }
    let mut typing: Vec<u8> = Vec::new();
    let mut ticked = Instant::now();
    loop {
        let input = match inputs.recv_timeout(TICK) {
            Ok(Input::Close) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(input) => Some(input),
            Err(RecvTimeoutError::Timeout) => None,
        };
        let mut io = Io {
            socket: &socket,
            tell: &mut *on_event,
            held: None,
        };
        match input {
            Some(Input::Socket(event)) => match event {
                Event::Data { peer, bytes } => engine.received(peer, &bytes, &mut io),
                Event::PeerJoined(peer) => {
                    (io.tell)(Event::PeerJoined(peer.clone()));
                    engine.joined(&peer, &mut io);
                }
                Event::PeerLeft(peer) => {
                    engine.left(peer, &mut io);
                    (io.tell)(Event::PeerLeft(peer));
                }
                other => (io.tell)(other),
            },
            Some(Input::Typed(bytes)) => {
                typing.extend_from_slice(&bytes);
                while let Some(end) = typing
                    .iter()
                    .position(|&byte| byte == b'\n' || byte == b'\r')
                {
                    let line: Vec<u8> = typing.drain(..=end).collect();
                    let line = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                    if line.trim().is_empty() {
                        continue;
                    }
                    let mut words = Words::new(&line);
                    match words.peek().as_deref() {
                        Some("help") | Some("?") => io.note(engine.help()),
                        _ => engine.command(&mut words, &mut io),
                    }
                }
            }
            Some(Input::Close) | None => {}
        }
        if ticked.elapsed() >= TICK {
            ticked = Instant::now();
            engine.tick(ticked, &mut io);
        }
    }
    drop(socket);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::net::tests::FAST;

    /// The kinds of tab the UI lists in `protocols.ts`: each has an engine.
    const KINDS: [&str; 34] = [
        "mqtt_client",
        "mqtt_server",
        "coap_client",
        "coap_server",
        "modbus_client",
        "modbus_server",
        "http_client",
        "http_server",
        "websocket_client",
        "websocket_server",
        "syslog_client",
        "syslog_server",
        "ntp_client",
        "ntp_server",
        "wol_client",
        "wol_server",
        "dns_client",
        "dns_server",
        "tftp_client",
        "tftp_server",
        "iperf_client",
        "iperf_server",
        "iperf_udp_client",
        "iperf_udp_server",
        "mcumgr_client",
        "mcumgr_server",
        "mdns_client",
        "mdns_server",
        "ssdp_client",
        "ssdp_server",
        "mqtt_client",
        "coap_client",
        "http_client",
        "mdns_client",
    ];
    const MORE_KINDS: [&str; 25] = [
        "coap_ws_client",
        "coap_ws_server",
        "stun_client",
        "stun_server",
        "echo_client",
        "echo_server",
        "echo_udp_client",
        "echo_udp_server",
        "coap_tcp_client",
        "coap_tcp_server",
        "mqttsn_client",
        "mqttsn_server",
        "snmp_client",
        "snmp_server",
        "lwm2m_client",
        "lwm2m_server",
        "dhcp_client",
        "dhcp_server",
        "ping",
        "ftp_client",
        "ftp_server",
        "syslog_tcp_client",
        "syslog_tcp_server",
        "dns_tcp_client",
        "dns_tcp_server",
    ];

    #[test]
    fn every_kind_the_ui_lists_has_an_engine_with_its_default_settings() {
        for kind in KINDS.iter().chain(MORE_KINDS.iter()) {
            assert!(engine(kind, serde_json::Value::Null).is_ok(), "{kind}");
        }
        assert!(engine("nothing_client", serde_json::Value::Null).is_err());
        // What the UI does not send takes its default.
        assert!(engine("mqtt_client", serde_json::json!({"client_id": "board"})).is_ok());
        assert!(engine("mqtt_client", serde_json::json!({"keep_alive": "soon"})).is_err());
    }

    #[test]
    fn a_help_line_is_a_command_and_what_it_does_or_a_note() {
        let help = parse_help(
            "pub <topic> <payload>   publish
ping                    send PINGREQ;
                        it comes back

Numbers may be hex:
    0x10.
It takes no commands, but answers
echo and reset.",
        );
        let command = |usage: &str, what: &str| CommandHelp {
            usage: usage.into(),
            what: what.into(),
        };
        assert_eq!(
            help.commands,
            [
                command("pub <topic> <payload>", "publish"),
                command("ping", "send PINGREQ; it comes back"),
            ]
        );
        assert_eq!(
            help.notes,
            [
                "Numbers may be hex: 0x10.",
                "It takes no commands, but answers echo and reset."
            ]
        );
    }

    #[test]
    fn every_engine_says_how_each_command_is_typed_and_what_it_does() {
        for kind in KINDS.iter().chain(MORE_KINDS.iter()) {
            let help = help_for(kind).unwrap();
            assert_eq!(help.commands.last().unwrap().usage, "help", "{kind}");
            for command in &help.commands {
                // A word to type first, such as pub or /close; or what stands
                // for any line, such as <text> or [-e|-a] <message>.
                let word = command.usage.split_whitespace().next().unwrap_or("");
                let word_char = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
                let typed = word.strip_prefix('/').unwrap_or(word);
                assert!(
                    word.starts_with(['<', '['])
                        || (!typed.is_empty() && typed.chars().all(word_char)),
                    "{kind}: {}",
                    command.usage
                );
                assert!(!command.what.is_empty(), "{kind}: {}", command.usage);
            }
            // A note is a sentence, not a command whose gap is too narrow.
            for note in &help.notes {
                assert!(note.starts_with(char::is_uppercase), "{kind}: {note}");
                assert!(note.ends_with(['.', ';']), "{kind}: {note}");
            }
        }
        assert_eq!(help_for("tcp_client"), None);
        let mqtt = help_for("mqtt_client").unwrap();
        let publish = &mqtt.commands[0];
        assert_eq!(publish.usage, "pub [-q0|-q1|-q2] [-r] <topic> <payload>");
        assert!(publish.what.starts_with("publish; -q0 -q1 -q2 for QoS"));
        assert_eq!(
            help_for("modbus_client").unwrap().notes,
            ["Numbers may be hex: 0x10."]
        );
    }

    /// A protocol session on the loopback, its events collected.
    pub(crate) fn start(
        engine: Box<dyn Engine>,
        kind: SocketKind,
        setup: SocketSetup,
    ) -> (ProtocolSession, Receiver<Event>) {
        start_timed(engine, kind, setup, FAST)
    }

    /// A protocol session on the loopback with its own timing.
    pub(crate) fn start_timed(
        engine: Box<dyn Engine>,
        kind: SocketKind,
        setup: SocketSetup,
        timing: crate::net::Timing,
    ) -> (ProtocolSession, Receiver<Event>) {
        let (sender, events) = mpsc::channel();
        // A UDP socket with a remote address, or a TCP client, is the client end.
        let client =
            setup.udp.as_ref().is_some_and(|udp| udp.remote_port != 0) || setup.client.is_some();
        let session = ProtocolSession::start_with(
            engine,
            kind,
            client,
            setup,
            Box::new(move |event| {
                let _ = sender.send(event);
            }),
            timing,
        )
        .unwrap();
        (session, events)
    }

    /// Waits for the engine's next report of type `kind`, leaving out what comes before it.
    pub(crate) fn reported(events: &Receiver<Event>, kind: &str) -> serde_json::Value {
        let until = Instant::now() + Duration::from_secs(5);
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match events.recv_timeout(left) {
                Ok(Event::Report(report)) if report["type"] == kind => return report,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("no {kind} report came");
    }

    /// Waits until a line shown has `text` in it, and gives back every line shown until then.
    pub(crate) fn shown(events: &Receiver<Event>, text: &str) -> String {
        let until = Instant::now() + Duration::from_secs(5);
        let mut all = String::new();
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match events.recv_timeout(left) {
                Ok(Event::Data { bytes, .. }) => {
                    all.push_str(&String::from_utf8_lossy(&bytes));
                    if plain(&all).contains(text) {
                        return plain(&all);
                    }
                }
                Ok(Event::Problem(problem)) => all.push_str(&format!(
                    "(problem: {problem})
"
                )),
                Ok(Event::State(state)) => all.push_str(&format!(
                    "(state: {state:?})
"
                )),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("no {text:?} within 5 s; shown:\n{}", plain(&all));
    }

    /// Text without its colors.
    pub(crate) fn plain(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// The port a server or a UDP socket opened on.
    pub(crate) fn listening(events: &Receiver<Event>) -> u16 {
        let crate::net::NetState::Listening { local } =
            crate::net::tests::state(events, "listening", |state| {
                matches!(state, crate::net::NetState::Listening { .. })
            })
        else {
            unreachable!()
        };
        local.rsplit(':').next().unwrap().parse().unwrap()
    }

    pub(crate) fn server_on_loopback() -> TcpServerConfig {
        TcpServerConfig {
            address: "127.0.0.1".into(),
            port: 0,
            ..TcpServerConfig::default()
        }
    }

    pub(crate) fn client_to(port: u16) -> TcpClientConfig {
        TcpClientConfig {
            host: "127.0.0.1".into(),
            port,
            ..TcpClientConfig::default()
        }
    }

    pub(crate) fn udp_on_loopback(remote_port: u16) -> UdpConfig {
        UdpConfig {
            local_address: "127.0.0.1".into(),
            remote_host: if remote_port == 0 {
                String::new()
            } else {
                "127.0.0.1".into()
            },
            remote_port,
            ..UdpConfig::default()
        }
    }
}
