//! WebSocket (RFC 6455): a client and a server, ws and wss, with text,
//! binary, ping and close frames shown one per line.
//!
//! What is typed goes as a text message; commands start with a slash, such
//! as /ping or /close.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::http::{self, Message};
use super::{Engine, Io, Words, hex_text, payload_text};
use crate::net::{Peer, PeerId, Target};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MOST: usize = 16 * 1024 * 1024;

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;

/// One frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    /// The frame's bytes; a client's are masked with `mask`.
    pub fn encode(&self, mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = vec![u8::from(self.fin) << 7 | self.opcode];
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let length = self.payload.len();
        if length < 126 {
            out.push(mask_bit | length as u8);
        } else if length <= 0xffff {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
        match mask {
            Some(mask) => {
                out.extend_from_slice(&mask);
                out.extend(
                    self.payload
                        .iter()
                        .enumerate()
                        .map(|(index, byte)| byte ^ mask[index % 4]),
                );
            }
            None => out.extend_from_slice(&self.payload),
        }
        out
    }
}

/// Takes the first whole frame off a stream's bytes, its payload unmasked.
pub fn take(buffer: &mut Vec<u8>) -> Result<Option<Frame>, String> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    if buffer[0] & 0x70 != 0 {
        return Err("a frame has reserved bits set, for an extension not agreed".into());
    }
    let masked = buffer[1] & 0x80 != 0;
    let (length, mut at) = match buffer[1] & 0x7f {
        126 => {
            if buffer.len() < 4 {
                return Ok(None);
            }
            (usize::from(u16::from_be_bytes([buffer[2], buffer[3]])), 4)
        }
        127 => {
            if buffer.len() < 10 {
                return Ok(None);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buffer[2..10]);
            (u64::from_be_bytes(bytes) as usize, 10)
        }
        length => (usize::from(length), 2),
    };
    if length > MOST {
        return Err(format!(
            "a frame of {length} bytes is more than netNIMA takes"
        ));
    }
    let mask = if masked {
        if buffer.len() < at + 4 {
            return Ok(None);
        }
        let mask = [buffer[at], buffer[at + 1], buffer[at + 2], buffer[at + 3]];
        at += 4;
        Some(mask)
    } else {
        None
    };
    if buffer.len() < at + length {
        return Ok(None);
    }
    let mut payload = buffer[at..at + length].to_vec();
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    let frame = Frame {
        fin: buffer[0] & 0x80 != 0,
        opcode: buffer[0] & 0x0f,
        payload,
    };
    buffer.drain(..at + length);
    Ok(Some(frame))
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(BASE64[(value >> (18 - 6 * index) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// What the server's Sec-WebSocket-Accept must be for a key.
pub fn accept_for(key: &str) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{GUID}").as_bytes(),
    );
    base64(digest.as_ref())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(7, |since| since.as_nanos() as u64)
        | 1;
    for byte in &mut bytes {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = seed as u8;
    }
    bytes
}

fn close_text(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return "no code".into();
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let words = match code {
        1000 => "normal",
        1001 => "going away",
        1002 => "protocol error",
        1003 => "data it cannot take",
        1007 => "bad text",
        1008 => "policy",
        1009 => "too big",
        1011 => "server error",
        _ => "",
    };
    let reason = String::from_utf8_lossy(&payload[2..]);
    let mut text = format!("{code}");
    if !words.is_empty() {
        text.push_str(&format!(" {words}"));
    }
    if !reason.is_empty() {
        text.push_str(&format!(": {reason}"));
    }
    text
}

/// A frame in one line.
pub fn describe(frame: &Frame) -> String {
    let more = if frame.fin { "" } else { ", more to come" };
    match frame.opcode {
        TEXT => format!("text{more}: {}", String::from_utf8_lossy(&frame.payload)),
        BINARY => format!(
            "binary, {} bytes{more}: {}",
            frame.payload.len(),
            hex_text(&frame.payload)
        ),
        CONTINUATION => format!("continued{more}: {}", payload_text(&frame.payload)),
        CLOSE => format!("close, {}", close_text(&frame.payload)),
        PING => format!("ping: {}", payload_text(&frame.payload)),
        PONG => format!("pong: {}", payload_text(&frame.payload)),
        other => format!("opcode {other:#x}: {}", hex_text(&frame.payload)),
    }
}

/// A typed line as a frame: text, or a slash command.
fn frame_of(words: &mut Words) -> Result<Option<Frame>, String> {
    let first = words.peek().unwrap_or_default();
    if !first.starts_with('/') {
        return Ok(Some(Frame {
            fin: true,
            opcode: TEXT,
            payload: words.rest(),
        }));
    }
    words.next();
    let frame = match first.as_str() {
        "/text" => Frame {
            fin: true,
            opcode: TEXT,
            payload: words.rest(),
        },
        "/binary" | "/hex" => {
            let hex: String = words.rest_text().split_whitespace().collect();
            let payload = (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(hex.get(at..at + 2).unwrap_or("x"), 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| "/binary takes hex, such as /binary 01 02 ff.".to_string())?;
            Frame {
                fin: true,
                opcode: BINARY,
                payload,
            }
        }
        "/ping" => Frame {
            fin: true,
            opcode: PING,
            payload: words.rest(),
        },
        "/close" => {
            let code: u16 = words.number_or("the close code", 1000)?;
            let mut payload = code.to_be_bytes().to_vec();
            payload.extend_from_slice(words.rest_text().as_bytes());
            Frame {
                fin: true,
                opcode: CLOSE,
                payload,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(frame))
}

// ----- The client -----

/// A WebSocket client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// The host the tab connects to, for the Host header.
    pub host: String,
    pub port: u16,
    pub path: String,
    /// Subprotocols offered, with commas between, such as "mqtt".
    pub protocols: String,
    /// An Origin header, which some servers check; empty for none.
    pub origin: String,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 80,
            path: "/".into(),
            protocols: String::new(),
            origin: String::new(),
        }
    }
}

/// A client's request to switch to WebSocket, with `key` in it.
fn upgrade_request(options: &ClientOptions, key: &str) -> Message {
    let host = if options.port == 80 || options.port == 443 || options.port == 0 {
        options.host.clone()
    } else {
        crate::net::host_and_port(&options.host, options.port)
    };
    let path = if options.path.trim().is_empty() {
        "/".to_string()
    } else {
        options.path.trim().to_string()
    };
    let mut headers = vec![
        ("Host".to_string(), host),
        ("Upgrade".into(), "websocket".into()),
        ("Connection".into(), "Upgrade".into()),
        ("Sec-WebSocket-Key".into(), key.to_string()),
        ("Sec-WebSocket-Version".into(), "13".into()),
        ("User-Agent".into(), format!("netNIMA/{}", crate::VERSION)),
    ];
    if !options.protocols.trim().is_empty() {
        headers.push((
            "Sec-WebSocket-Protocol".into(),
            options.protocols.trim().into(),
        ));
    }
    if !options.origin.trim().is_empty() {
        headers.push(("Origin".into(), options.origin.trim().into()));
    }
    Message {
        start: format!("GET {path} HTTP/1.1"),
        headers,
        body: Vec::new(),
    }
}

pub struct Client {
    options: ClientOptions,
    peer: Option<PeerId>,
    buffer: Vec<u8>,
    key: String,
    /// After the server's 101.
    open: bool,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        Self {
            options,
            peer: None,
            buffer: Vec::new(),
            key: String::new(),
            open: false,
        }
    }

    fn send(&mut self, frame: Frame, io: &mut Io) {
        let Some(peer) = self.peer.filter(|_| self.open) else {
            io.bad("Not connected: nothing was sent.");
            return;
        };
        io.went(peer, &describe(&frame));
        io.send(Target::Default, frame.encode(Some(random_bytes::<4>())));
    }
}

const CLIENT_HELP: &str =
    "<text>                    send a text message: anything that does not start with /
/text <text>              send text, also one that starts with /
/binary <hex>             send a binary message, such as /binary 01 02 ff
/ping [text]              send a ping
/close [code] [reason]    close, 1000 unless told";

impl Engine for Client {
    fn help(&self) -> &'static str {
        CLIENT_HELP
    }

    fn joined(&mut self, peer: &Peer, io: &mut Io) {
        self.peer = Some(peer.id);
        self.buffer.clear();
        self.open = false;
        self.key = base64(&random_bytes::<16>());
        let request = upgrade_request(&self.options, &self.key);
        io.went(peer.id, &request.describe());
        io.send(Target::Default, request.encode());
    }

    fn left(&mut self, _peer: PeerId, _io: &mut Io) {
        self.peer = None;
        self.open = false;
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        self.buffer.extend_from_slice(bytes);
        if !self.open {
            match http::take(&mut self.buffer, true, false) {
                Ok(Some(response)) => {
                    io.came(peer, &response.describe());
                    let switched = response.start.split(' ').nth(1) == Some("101");
                    let accept_ok = response.header("sec-websocket-accept")
                        == Some(accept_for(&self.key).as_str());
                    if !switched {
                        io.bad("The server did not switch to WebSocket.");
                        io.drop_peer(peer);
                        return;
                    }
                    if !accept_ok {
                        io.bad("Its Sec-WebSocket-Accept is not the one the key asks for: taken anyway.");
                    }
                    self.open = true;
                    io.note("WebSocket open: type a message.");
                }
                Ok(None) => return,
                Err(problem) => {
                    io.bad(&format!("The answer is not HTTP: {problem}."));
                    io.drop_peer(peer);
                    return;
                }
            }
        }
        loop {
            match take(&mut self.buffer) {
                Ok(Some(frame)) => {
                    io.came(peer, &describe(&frame));
                    match frame.opcode {
                        PING => self.send(
                            Frame {
                                fin: true,
                                opcode: PONG,
                                payload: frame.payload,
                            },
                            io,
                        ),
                        CLOSE => {
                            self.send(
                                Frame {
                                    fin: true,
                                    opcode: CLOSE,
                                    payload: frame.payload.get(..2).unwrap_or(&[]).to_vec(),
                                },
                                io,
                            );
                            self.open = false;
                            io.drop_peer(peer);
                        }
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(problem) => {
                    io.bad(&format!("A frame cannot be read: {problem}."));
                    self.buffer.clear();
                    break;
                }
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match frame_of(words) {
            Ok(Some(frame)) => self.send(frame, io),
            Ok(None) => io.bad("That is not a command here. Type help for the list."),
            Err(problem) => io.bad(&problem),
        }
    }
}

// ----- The server -----

/// A WebSocket server tab's settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServerOptions {
    /// Sends every message back to the client that sent it.
    pub echo: bool,
}

struct Connection {
    buffer: Vec<u8>,
    open: bool,
}

pub struct Server {
    echo: bool,
    connections: BTreeMap<PeerId, Connection>,
}

impl Server {
    pub fn new(options: ServerOptions) -> Self {
        Self {
            echo: options.echo,
            connections: BTreeMap::new(),
        }
    }

    fn send(&self, peer: PeerId, frame: &Frame, io: &mut Io) {
        io.went(peer, &describe(frame));
        io.send(Target::Peer(peer), frame.encode(None));
    }

    fn open_peers(&self) -> Vec<PeerId> {
        self.connections
            .iter()
            .filter(|(_, connection)| connection.open)
            .map(|(peer, _)| *peer)
            .collect()
    }
}

const SERVER_HELP: &str = "<text>                    send a text message to every client
/to <client> <text>       send text to one client
/binary <hex>             send binary to every client
/ping [text]              ping every client
/close [code] [reason]    close every client's connection
/clients                  the clients connected
/echo on|off              send each message back to its sender";

impl Engine for Server {
    fn help(&self) -> &'static str {
        SERVER_HELP
    }

    fn joined(&mut self, peer: &Peer, _io: &mut Io) {
        self.connections.insert(
            peer.id,
            Connection {
                buffer: Vec::new(),
                open: false,
            },
        );
    }

    fn left(&mut self, peer: PeerId, _io: &mut Io) {
        self.connections.remove(&peer);
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Some(connection) = self.connections.get_mut(&peer) else {
            return;
        };
        connection.buffer.extend_from_slice(bytes);
        if !connection.open {
            match http::take(&mut connection.buffer, false, false) {
                Ok(Some(request)) => {
                    io.came(peer, &request.describe());
                    let upgrade = request
                        .header("upgrade")
                        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
                    let response = match (upgrade, request.header("sec-websocket-key")) {
                        (true, Some(key)) => {
                            let mut headers = vec![
                                ("Upgrade".to_string(), "websocket".to_string()),
                                ("Connection".into(), "Upgrade".into()),
                                ("Sec-WebSocket-Accept".into(), accept_for(key)),
                            ];
                            if let Some(protocols) = request.header("sec-websocket-protocol") {
                                let first =
                                    protocols.split(',').next().unwrap_or("").trim().to_string();
                                headers.push(("Sec-WebSocket-Protocol".into(), first));
                            }
                            connection.open = true;
                            Message {
                                start: "HTTP/1.1 101 Switching Protocols".into(),
                                headers,
                                body: Vec::new(),
                            }
                        }
                        _ => Message {
                            start: "HTTP/1.1 426 Upgrade Required".into(),
                            headers: vec![
                                ("Upgrade".into(), "websocket".into()),
                                ("Content-Length".into(), "0".into()),
                            ],
                            body: Vec::new(),
                        },
                    };
                    io.went(peer, &response.describe());
                    io.send(Target::Peer(peer), response.encode());
                    if !connection.open {
                        return;
                    }
                }
                Ok(None) => return,
                Err(problem) => {
                    io.bad(&format!(
                        "What came is not HTTP: {problem}. The client is dropped."
                    ));
                    io.drop_peer(peer);
                    return;
                }
            }
        }
        let mut frames = Vec::new();
        loop {
            let Some(connection) = self.connections.get_mut(&peer) else {
                return;
            };
            match take(&mut connection.buffer) {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break,
                Err(problem) => {
                    io.bad(&format!("A frame cannot be read: {problem}."));
                    connection.buffer.clear();
                    break;
                }
            }
        }
        for frame in frames {
            io.came(peer, &describe(&frame));
            match frame.opcode {
                PING => self.send(
                    peer,
                    &Frame {
                        fin: true,
                        opcode: PONG,
                        payload: frame.payload,
                    },
                    io,
                ),
                CLOSE => {
                    self.send(
                        peer,
                        &Frame {
                            fin: true,
                            opcode: CLOSE,
                            payload: frame.payload.get(..2).unwrap_or(&[]).to_vec(),
                        },
                        io,
                    );
                    io.drop_peer(peer);
                }
                TEXT | BINARY if self.echo => self.send(peer, &frame, io),
                _ => {}
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.peek().as_deref() {
            Some("/clients") => {
                let open = self.open_peers();
                io.note(&if open.is_empty() {
                    "No client is connected.".to_string()
                } else {
                    format!(
                        "Clients: {}",
                        open.iter()
                            .map(PeerId::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                });
                return;
            }
            Some("/echo") => {
                words.next();
                self.echo = words.next().is_none_or(|word| word != "off");
                io.note(if self.echo {
                    "Messages go back to their senders."
                } else {
                    "Messages are not sent back."
                });
                return;
            }
            Some("/to") => {
                words.next();
                let result = (|| -> Result<(), String> {
                    let peer: PeerId = words.number("the client's number")?;
                    if !self.open_peers().contains(&peer) {
                        return Err(format!("Client {peer} is not connected."));
                    }
                    let frame = Frame {
                        fin: true,
                        opcode: TEXT,
                        payload: words.rest(),
                    };
                    self.send(peer, &frame, io);
                    Ok(())
                })();
                if let Err(problem) = result {
                    io.bad(&problem);
                }
                return;
            }
            _ => {}
        }
        match frame_of(words) {
            Ok(Some(frame)) => {
                let peers = self.open_peers();
                if peers.is_empty() {
                    io.bad("No client is connected: nothing was sent.");
                }
                for peer in peers {
                    self.send(peer, &frame, io);
                    if frame.opcode == CLOSE {
                        io.drop_peer(peer);
                    }
                }
            }
            Ok(None) => io.bad("That is not a command here. Type help for the list."),
            Err(problem) => io.bad(&problem),
        }
    }
}

// ----- Another protocol over WebSocket -----

/// Whether a protocol tab runs over WebSocket, as MQTT does on ws:// and
/// wss://, from the tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Carriage {
    /// A client upgrades first; a server takes WebSocket clients as well as plain ones.
    pub websocket: bool,
    /// The path a client asks for, such as /mqtt.
    pub path: String,
    /// Where a client connects, for the Host header.
    pub host: String,
    pub port: u16,
}

impl Default for Carriage {
    fn default() -> Self {
        Self {
            websocket: false,
            path: "/mqtt".into(),
            host: "localhost".into(),
            port: 80,
        }
    }
}

impl Carriage {
    /// A client's upgrade request, offering `protocol`, such as "mqtt".
    pub fn upgrade(&self, protocol: &str) -> ClientOptions {
        ClientOptions {
            host: self.host.clone(),
            port: self.port,
            path: self.path.clone(),
            protocols: protocol.into(),
            origin: String::new(),
        }
    }
}

/// How one connection of a carrier is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Before the upgrade's answer, or a server's first bytes.
    Upgrading,
    /// WebSocket frames.
    Framed,
    /// A server's client that speaks the protocol without WebSocket.
    Plain,
}

struct End {
    peer: Peer,
    buffer: Vec<u8>,
    mode: Mode,
    /// A client's Sec-WebSocket-Key.
    key: String,
}

/// Another protocol's engine over WebSocket, as MQTT runs on ws:// and
/// wss://: the HTTP upgrade first, then what the engine sends goes in binary
/// frames, and the frames' payloads reach it as its stream. A server tells
/// plain clients by their first bytes, and takes them too.
pub struct Carrier<E> {
    inner: E,
    /// A client's upgrade; none for a server.
    client: Option<ClientOptions>,
    /// The subprotocol a server agrees to, such as "mqtt".
    protocol: String,
    ends: BTreeMap<PeerId, End>,
    /// The peer heard from last, for what is sent to no one in particular.
    last: Option<PeerId>,
    /// Each message reaches the engine on its own, not as part of a stream:
    /// for CoAP, whose messages over WebSocket carry no length.
    whole: bool,
    /// A server takes clients that speak without WebSocket too.
    plain: bool,
    /// What came of a message sent in fragments, until its last.
    pieces: BTreeMap<PeerId, Vec<u8>>,
}

impl<E: Engine> Carrier<E> {
    pub fn client(inner: E, upgrade: ClientOptions) -> Self {
        Self {
            inner,
            client: Some(upgrade),
            protocol: String::new(),
            ends: BTreeMap::new(),
            last: None,
            whole: false,
            plain: false,
            pieces: BTreeMap::new(),
        }
    }

    pub fn server(inner: E, protocol: &str) -> Self {
        Self {
            inner,
            client: None,
            protocol: protocol.into(),
            ends: BTreeMap::new(),
            last: None,
            whole: false,
            plain: true,
            pieces: BTreeMap::new(),
        }
    }

    /// Each WebSocket message goes to the engine on its own, and a server
    /// takes WebSocket clients alone: as CoAP over WebSocket wants.
    pub fn whole_messages(self) -> Self {
        Self {
            whole: true,
            plain: false,
            ..self
        }
    }

    /// Runs the engine inside, then sends on what it sent: in frames to
    /// WebSocket ends, as it is to plain ones.
    fn inside(&mut self, io: &mut Io, run: impl FnOnce(&mut E, &mut Io)) {
        let mut held = Vec::new();
        run(&mut self.inner, &mut io.holding(&mut held));
        for (target, bytes) in held {
            let peers: Vec<PeerId> = match target {
                Target::Peer(peer) => vec![peer],
                Target::All => self.ends.keys().copied().collect(),
                Target::Default => self
                    .last
                    .or_else(|| self.ends.keys().next().copied())
                    .into_iter()
                    .collect(),
            };
            for peer in peers {
                match self.ends.get(&peer).map(|end| end.mode) {
                    Some(Mode::Framed) => self.send_frame(peer, &binary(bytes.clone()), io),
                    Some(Mode::Plain) => io.send(Target::Peer(peer), bytes.clone()),
                    _ => {}
                }
            }
        }
    }

    fn send_frame(&self, peer: PeerId, frame: &Frame, io: &mut Io) {
        if self.client.is_some() {
            io.send(Target::Default, frame.encode(Some(random_bytes::<4>())));
        } else {
            io.send(Target::Peer(peer), frame.encode(None));
        }
    }

    /// Reads the upgrade, or a server's first bytes: true once the engine
    /// inside has the connection.
    fn upgrade(&mut self, peer: PeerId, io: &mut Io) -> bool {
        let client = self.client.is_some();
        let Some(end) = self.ends.get_mut(&peer) else {
            return false;
        };
        if !client && self.plain {
            // HTTP's GET starts with G; MQTT's CONNECT with 0x10.
            match end.buffer.first() {
                None => return false,
                Some(b'G') => {}
                Some(_) => {
                    end.mode = Mode::Plain;
                    let who = end.peer.clone();
                    self.inside(io, |inner, io| inner.joined(&who, io));
                    return true;
                }
            }
        }
        let message = match http::take(&mut end.buffer, client, false) {
            Ok(Some(message)) => message,
            Ok(None) => return false,
            Err(problem) => {
                io.bad(&format!("The WebSocket upgrade is not HTTP: {problem}."));
                io.drop_peer(peer);
                return false;
            }
        };
        io.came(peer, &message.start);
        if client {
            if message.start.split(' ').nth(1) != Some("101") {
                io.bad("The server did not switch to WebSocket: is the path right?");
                io.drop_peer(peer);
                return false;
            }
            if message.header("sec-websocket-accept") != Some(accept_for(&end.key).as_str()) {
                io.bad("Its Sec-WebSocket-Accept is not the one the key asks for: taken anyway.");
            }
        } else {
            let upgrade = message
                .header("upgrade")
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
            let Some(key) = message.header("sec-websocket-key").filter(|_| upgrade) else {
                let refused = Message {
                    start: "HTTP/1.1 426 Upgrade Required".into(),
                    headers: vec![
                        ("Upgrade".into(), "websocket".into()),
                        ("Content-Length".into(), "0".into()),
                    ],
                    body: Vec::new(),
                };
                io.went(peer, &refused.start);
                io.send(Target::Peer(peer), refused.encode());
                return false;
            };
            let mut headers = vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".into(), "Upgrade".into()),
                ("Sec-WebSocket-Accept".into(), accept_for(key)),
            ];
            let offered = message.header("sec-websocket-protocol").unwrap_or("");
            if offered
                .split(',')
                .any(|name| name.trim().eq_ignore_ascii_case(&self.protocol))
            {
                headers.push(("Sec-WebSocket-Protocol".into(), self.protocol.clone()));
            }
            let switched = Message {
                start: "HTTP/1.1 101 Switching Protocols".into(),
                headers,
                body: Vec::new(),
            };
            io.went(peer, &switched.start);
            io.send(Target::Peer(peer), switched.encode());
        }
        end.mode = Mode::Framed;
        let who = end.peer.clone();
        self.inside(io, |inner, io| inner.joined(&who, io));
        true
    }
}

fn binary(payload: Vec<u8>) -> Frame {
    Frame {
        fin: true,
        opcode: BINARY,
        payload,
    }
}

impl<E: Engine> Engine for Carrier<E> {
    fn help(&self) -> &'static str {
        self.inner.help()
    }

    fn joined(&mut self, peer: &Peer, io: &mut Io) {
        let mut end = End {
            peer: peer.clone(),
            buffer: Vec::new(),
            mode: Mode::Upgrading,
            key: String::new(),
        };
        if let Some(options) = &self.client {
            end.key = base64(&random_bytes::<16>());
            let request = upgrade_request(options, &end.key);
            io.went(peer.id, &format!("{} (WebSocket)", request.start));
            io.send(Target::Default, request.encode());
        }
        self.ends.insert(peer.id, end);
    }

    fn left(&mut self, peer: PeerId, io: &mut Io) {
        if self.last == Some(peer) {
            self.last = None;
        }
        if let Some(end) = self.ends.remove(&peer)
            && end.mode != Mode::Upgrading
        {
            self.inside(io, |inner, io| inner.left(peer, io));
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Some(end) = self.ends.get_mut(&peer) else {
            return;
        };
        end.buffer.extend_from_slice(bytes);
        self.last = Some(peer);
        if end.mode == Mode::Upgrading && !self.upgrade(peer, io) {
            return;
        }
        let Some(end) = self.ends.get_mut(&peer) else {
            return;
        };
        let mut stream = Vec::new();
        // Whole messages, when the engine takes them one by one.
        let mut messages = Vec::new();
        let mut answers = Vec::new();
        let mut closed = false;
        if end.mode == Mode::Plain {
            stream = std::mem::take(&mut end.buffer);
        } else {
            loop {
                match take(&mut end.buffer) {
                    Ok(Some(frame))
                        if self.whole && matches!(frame.opcode, TEXT | BINARY | CONTINUATION) =>
                    {
                        let piece = self.pieces.entry(peer).or_default();
                        piece.extend_from_slice(&frame.payload);
                        if frame.fin {
                            messages.push(std::mem::take(piece));
                        }
                    }
                    Ok(Some(frame)) => match frame.opcode {
                        TEXT | BINARY | CONTINUATION => stream.extend_from_slice(&frame.payload),
                        PING => answers.push(Frame {
                            fin: true,
                            opcode: PONG,
                            payload: frame.payload,
                        }),
                        CLOSE => {
                            io.came(peer, &describe(&frame));
                            answers.push(Frame {
                                fin: true,
                                opcode: CLOSE,
                                payload: frame.payload.get(..2).unwrap_or(&[]).to_vec(),
                            });
                            closed = true;
                            break;
                        }
                        _ => {}
                    },
                    Ok(None) => break,
                    Err(problem) => {
                        io.bad(&format!("A WebSocket frame cannot be read: {problem}."));
                        end.buffer.clear();
                        break;
                    }
                }
            }
        }
        if !stream.is_empty() {
            self.inside(io, |inner, io| inner.received(peer, &stream, io));
        }
        for message in messages {
            self.inside(io, |inner, io| inner.received(peer, &message, io));
        }
        for answer in &answers {
            self.send_frame(peer, answer, io);
        }
        if closed {
            self.pieces.remove(&peer);
            io.drop_peer(peer);
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        self.inside(io, |inner, io| inner.command(words, io));
    }

    fn tick(&mut self, now: std::time::Instant, io: &mut Io) {
        self.inside(io, |inner, io| inner.tick(now, io));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{client_to, listening, server_on_loopback, shown, start};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn the_accept_key_is_the_one_rfc_6455_shows() {
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
    }

    #[test]
    fn frames_read_back_masked_or_not_and_long() {
        for length in [5, 300, 70_000] {
            let frame = Frame {
                fin: true,
                opcode: BINARY,
                payload: vec![0x5a; length],
            };
            for mask in [None, Some([1, 2, 3, 4])] {
                let mut bytes = frame.encode(mask);
                assert_eq!(take(&mut bytes).unwrap(), Some(frame.clone()));
                assert!(bytes.is_empty());
            }
        }
    }

    #[test]
    fn a_client_and_the_server_talk() {
        let (server, server_events) = start(
            Box::new(Server::new(ServerOptions { echo: true })),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                host: "127.0.0.1".into(),
                port,
                path: "/ws".into(),
                protocols: "chat".into(),
                origin: String::new(),
            })),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        shown(&client_events, "WebSocket open");
        client.command("hello there");
        shown(&client_events, "text: hello there");
        shown(&server_events, "text: hello there");
        client.command("/ping are you there");
        shown(&client_events, "pong: are you there");
        server.command("from the server");
        shown(&client_events, "text: from the server");
        client.command("/binary 01 02 ff");
        shown(&server_events, "binary, 3 bytes: 01 02 ff");
        client.command("/close 1000 done");
        shown(&client_events, "close, 1000 normal");
    }
}
