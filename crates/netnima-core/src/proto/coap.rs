//! CoAP (RFC 7252) over UDP: the messages, a client and a server, with
//! Observe (RFC 7641) and block-wise transfers (RFC 7959).
//!
//! The client sends confirmable requests again until they are answered, as
//! CoAP says, follows a response that comes in blocks to its end, and keeps
//! showing what a resource it observes sends. The server keeps resources in
//! memory, answers GET, PUT, POST and DELETE on them, lists them at
//! /.well-known/core, and tells their observers when they change.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use super::{Engine, Io, Words, hex, hex_text, payload_text};
use crate::net::{Peer, PeerId, Target};

pub const CON: u8 = 0;
pub const NON: u8 = 1;
pub const ACK: u8 = 2;
pub const RST: u8 = 3;

pub const GET: u8 = 0x01;
pub const POST: u8 = 0x02;
pub const PUT: u8 = 0x03;
pub const DELETE: u8 = 0x04;

pub(crate) const OBSERVE: u16 = 6;
pub(crate) const URI_PATH: u16 = 11;
pub(crate) const CONTENT_FORMAT: u16 = 12;
pub(crate) const URI_QUERY: u16 = 15;
pub(crate) const ACCEPT: u16 = 17;
const BLOCK2: u16 = 23;
pub(crate) const BLOCK1: u16 = 27;
const SIZE2: u16 = 28;

/// The block size the server sends in, and the client asks for.
const BLOCK_SIZE: usize = 512;
/// How long a confirmable message waits for its ACK the first time.
pub(crate) const ACK_TIMEOUT: Duration = Duration::from_secs(2);
/// How many times a confirmable message is sent again.
pub(crate) const MAX_RETRANSMIT: u32 = 4;

/// A code such as 2.05: its class and detail in one byte.
pub(crate) const fn code(class: u8, detail: u8) -> u8 {
    class << 5 | detail
}

pub const CREATED: u8 = code(2, 1);
pub const DELETED: u8 = code(2, 2);
pub const CHANGED: u8 = code(2, 4);
pub const CONTENT: u8 = code(2, 5);
pub const NOT_FOUND: u8 = code(4, 4);
pub const BAD_REQUEST: u8 = code(4, 0);
pub const METHOD_NOT_ALLOWED: u8 = code(4, 5);

/// One CoAP message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub kind: u8,
    pub code: u8,
    pub id: u16,
    pub token: Vec<u8>,
    /// Options by number, in order; one number may come more than once.
    pub options: Vec<(u16, Vec<u8>)>,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.payload.len());
        out.push(0x40 | (self.kind & 3) << 4 | (self.token.len().min(8) as u8));
        out.push(self.code);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.token[..self.token.len().min(8)]);
        let mut options = self.options.clone();
        options.sort_by_key(|(number, _)| *number);
        let mut last = 0u16;
        for (number, value) in &options {
            let delta = number - last;
            last = *number;
            let (delta_nibble, delta_extra) = nibble(delta);
            let (length_nibble, length_extra) = nibble(value.len() as u16);
            out.push(delta_nibble << 4 | length_nibble);
            out.extend_from_slice(&delta_extra);
            out.extend_from_slice(&length_extra);
            out.extend_from_slice(value);
        }
        if !self.payload.is_empty() {
            out.push(0xff);
            out.extend_from_slice(&self.payload);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("it is shorter than CoAP's 4-byte header".into());
        }
        if bytes[0] >> 6 != 1 {
            return Err(format!("its version is {}, not 1", bytes[0] >> 6));
        }
        let token_length = usize::from(bytes[0] & 0x0f);
        if token_length > 8 {
            return Err("its token is longer than 8 bytes".into());
        }
        let mut message = Message {
            kind: (bytes[0] >> 4) & 3,
            code: bytes[1],
            id: u16::from_be_bytes([bytes[2], bytes[3]]),
            ..Message::default()
        };
        let mut at = 4 + token_length;
        message.token = bytes.get(4..at).ok_or("it ends inside its token")?.to_vec();
        let mut number = 0u16;
        while at < bytes.len() {
            if bytes[at] == 0xff {
                message.payload = bytes[at + 1..].to_vec();
                if message.payload.is_empty() {
                    return Err("a payload marker comes with no payload".into());
                }
                break;
            }
            let delta_nibble = bytes[at] >> 4;
            let length_nibble = bytes[at] & 0x0f;
            at += 1;
            let (delta, used) = extended(delta_nibble, &bytes[at..])?;
            at += used;
            let (length, used) = extended(length_nibble, &bytes[at..])?;
            at += used;
            number = number
                .checked_add(delta)
                .ok_or("an option number is too big")?;
            let value = bytes
                .get(at..at + usize::from(length))
                .ok_or("it ends inside an option")?;
            message.options.push((number, value.to_vec()));
            at += usize::from(length);
        }
        Ok(message)
    }

    pub fn option(&self, number: u16) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(found, _)| *found == number)
            .map(|(_, value)| value.as_slice())
    }

    pub fn uint_option(&self, number: u16) -> Option<u32> {
        self.option(number).map(read_uint)
    }

    /// "/sensors/temp?unit=c", from the Uri-Path and Uri-Query options.
    pub fn path(&self) -> String {
        let mut path = String::new();
        for (number, value) in &self.options {
            if *number == URI_PATH {
                path.push('/');
                path.push_str(&String::from_utf8_lossy(value));
            }
        }
        if path.is_empty() {
            path.push('/');
        }
        let query: Vec<String> = self
            .options
            .iter()
            .filter(|(number, _)| *number == URI_QUERY)
            .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
            .collect();
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query.join("&"));
        }
        path
    }

    /// The path alone, without its query.
    pub(crate) fn plain_path(&self) -> String {
        let path = self.path();
        path.split('?').next().unwrap_or("/").to_string()
    }
}

fn nibble(value: u16) -> (u8, Vec<u8>) {
    match value {
        0..=12 => (value as u8, Vec::new()),
        13..=268 => (13, vec![(value - 13) as u8]),
        _ => (14, (value - 269).to_be_bytes().to_vec()),
    }
}

fn extended(nibble: u8, rest: &[u8]) -> Result<(u16, usize), String> {
    match nibble {
        0..=12 => Ok((u16::from(nibble), 0)),
        13 => Ok((
            u16::from(*rest.first().ok_or("an option ends too soon")?) + 13,
            1,
        )),
        14 => {
            let bytes = rest.get(..2).ok_or("an option ends too soon")?;
            Ok((
                u16::from_be_bytes([bytes[0], bytes[1]]).saturating_add(269),
                2,
            ))
        }
        _ => Err("an option uses the reserved value 15".into()),
    }
}

pub(crate) fn read_uint(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .take(4)
        .fold(0u32, |value, byte| value << 8 | u32::from(*byte))
}

/// A number as CoAP sends it in an option: as few bytes as it needs.
pub(crate) fn uint(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(4);
    bytes[first..].to_vec()
}

/// Uri-Path and Uri-Query options from "/a/b?x=1&y=2".
pub(crate) fn path_options(path: &str) -> Vec<(u16, Vec<u8>)> {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let mut options: Vec<(u16, Vec<u8>)> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| (URI_PATH, segment.as_bytes().to_vec()))
        .collect();
    options.extend(
        query
            .split('&')
            .filter(|part| !part.is_empty())
            .map(|part| (URI_QUERY, part.as_bytes().to_vec())),
    );
    options
}

/// A Block1 or Block2 option's number, whether more follow, and its size.
pub(crate) fn block(value: u32) -> (u32, bool, usize) {
    (value >> 4, value & 0x08 != 0, 16 << (value & 0x07).min(6))
}

pub(crate) fn block_value(number: u32, more: bool, size: usize) -> u32 {
    let exponent = (size.max(16) / 16).trailing_zeros().min(6);
    number << 4 | u32::from(more) << 3 | exponent
}

pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        CON => "CON",
        NON => "NON",
        ACK => "ACK",
        _ => "RST",
    }
}

pub fn code_name(code: u8) -> String {
    let name = match code {
        0 => "Empty",
        GET => "GET",
        POST => "POST",
        PUT => "PUT",
        DELETE => "DELETE",
        0x05 => "FETCH",
        0x06 => "PATCH",
        0x07 => "iPATCH",
        CREATED => "2.01 Created",
        DELETED => "2.02 Deleted",
        0x43 => "2.03 Valid",
        CHANGED => "2.04 Changed",
        CONTENT => "2.05 Content",
        0x5f => "2.31 Continue",
        BAD_REQUEST => "4.00 Bad Request",
        0x81 => "4.01 Unauthorized",
        0x82 => "4.02 Bad Option",
        0x83 => "4.03 Forbidden",
        NOT_FOUND => "4.04 Not Found",
        METHOD_NOT_ALLOWED => "4.05 Method Not Allowed",
        0x86 => "4.06 Not Acceptable",
        0x88 => "4.08 Request Entity Incomplete",
        0x8c => "4.12 Precondition Failed",
        0x8d => "4.13 Request Entity Too Large",
        0x8f => "4.15 Unsupported Content-Format",
        0xa0 => "5.00 Internal Server Error",
        0xa1 => "5.01 Not Implemented",
        0xa2 => "5.02 Bad Gateway",
        0xa3 => "5.03 Service Unavailable",
        0xa4 => "5.04 Gateway Timeout",
        0xa5 => "5.05 Proxying Not Supported",
        other => return format!("{}.{:02}", other >> 5, other & 0x1f),
    };
    name.into()
}

pub fn format_name(format: u32) -> String {
    match format {
        0 => "text/plain".into(),
        40 => "application/link-format".into(),
        41 => "application/xml".into(),
        42 => "application/octet-stream".into(),
        47 => "application/exi".into(),
        50 => "application/json".into(),
        60 => "application/cbor".into(),
        110 => "application/senml+json".into(),
        112 => "application/senml+cbor".into(),
        11542 => "application/vnd.oma.lwm2m+tlv".into(),
        11543 => "application/vnd.oma.lwm2m+json".into(),
        other => format!("content-format {other}"),
    }
}

/// A content format by its name or number: "json", "text", "cbor", "50".
fn format_number(word: &str) -> Option<u32> {
    match word.to_lowercase().as_str() {
        "text" | "plain" | "text/plain" => Some(0),
        "link" | "link-format" => Some(40),
        "xml" => Some(41),
        "octet" | "binary" | "octet-stream" => Some(42),
        "json" => Some(50),
        "cbor" => Some(60),
        "senml" | "senml+json" => Some(110),
        "tlv" => Some(11542),
        other => other.parse().ok(),
    }
}

fn option_name(number: u16) -> &'static str {
    match number {
        1 => "If-Match",
        3 => "Uri-Host",
        4 => "ETag",
        5 => "If-None-Match",
        OBSERVE => "Observe",
        7 => "Uri-Port",
        8 => "Location-Path",
        URI_PATH => "Uri-Path",
        CONTENT_FORMAT => "Content-Format",
        14 => "Max-Age",
        URI_QUERY => "Uri-Query",
        ACCEPT => "Accept",
        20 => "Location-Query",
        BLOCK2 => "Block2",
        BLOCK1 => "Block1",
        SIZE2 => "Size2",
        35 => "Proxy-Uri",
        39 => "Proxy-Scheme",
        60 => "Size1",
        258 => "No-Response",
        _ => "option",
    }
}

/// A message in one line: its kind, code, path, id, token and the options
/// people look for, then its payload.
pub fn describe(message: &Message) -> String {
    let mut line = format!("{} {}", kind_name(message.kind), code_name(message.code));
    if message.code > 0 && message.code < 0x20 {
        line.push(' ');
        line.push_str(&message.path());
    }
    line.push_str(&format!(" (id {:#06x}", message.id));
    if !message.token.is_empty() {
        line.push_str(&format!(
            ", token {}",
            hex_text(&message.token).replace(' ', "")
        ));
    }
    line.push(')');
    for (number, value) in &message.options {
        let shown = match *number {
            URI_PATH | URI_QUERY => continue,
            OBSERVE => format!("Observe {}", read_uint(value)),
            CONTENT_FORMAT | ACCEPT => {
                format!("{} {}", option_name(*number), format_name(read_uint(value)))
            }
            BLOCK1 | BLOCK2 => {
                let (number_in, more, size) = block(read_uint(value));
                format!(
                    "{} #{number_in}{}, {size} bytes",
                    option_name(*number),
                    if more { " of more" } else { ", the last" }
                )
            }
            3 | 8 | 20 | 35 | 39 => format!(
                "{} {}",
                option_name(*number),
                String::from_utf8_lossy(value)
            ),
            4 | 1 => format!(
                "{} {}",
                option_name(*number),
                hex_text(value).replace(' ', "")
            ),
            _ => format!("{} {}", option_name(*number), read_uint(value)),
        };
        line.push_str(", ");
        line.push_str(&shown);
    }
    if !message.payload.is_empty() {
        line.push_str(": ");
        line.push_str(&payload_text(&message.payload));
    }
    line
}

/// Numbers that change: message ids and tokens. Not for security, only to
/// tell messages apart.
pub(crate) struct Counter(u64);

impl Counter {
    pub(crate) fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |since| since.as_nanos() as u64);
        Self(nanos | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        // xorshift64
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

// ----- The client -----

/// A CoAP client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// Sends requests as NON, which are not sent again, rather than CON.
    pub non: bool,
    /// The bytes of a token: 0 to 8.
    pub token_length: u8,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            non: false,
            token_length: 4,
        }
    }
}

/// A confirmable message waiting for its ACK.
struct Waiting {
    message: Message,
    target: Target,
    sent: Instant,
    timeout: Duration,
    tries: u32,
}

/// A request, by its token, while its answer comes.
struct Request {
    method: u8,
    path: String,
    /// The blocks of a response that comes in blocks, so far.
    body: Vec<u8>,
    observe: bool,
    accept: Option<u32>,
    /// When it went, for how long its answer took.
    sent: Instant,
}

pub struct Client {
    options: ClientOptions,
    counter: Counter,
    next_id: u16,
    waiting: Vec<Waiting>,
    requests: HashMap<Vec<u8>, Request>,
    /// The peer heard from last, to show what is sent beside it.
    server: PeerId,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        let mut counter = Counter::new();
        let next_id = counter.next() as u16;
        Self {
            options,
            counter,
            next_id,
            waiting: Vec::new(),
            requests: HashMap::new(),
            server: 0,
        }
    }

    fn id(&mut self) -> u16 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn token(&mut self) -> Vec<u8> {
        let length = usize::from(self.options.token_length.min(8));
        self.counter.next().to_be_bytes()[..length].to_vec()
    }

    fn send(&mut self, message: Message, io: &mut Io) {
        io.went(self.server, &describe(&message));
        io.send(Target::Default, message.encode());
        if message.kind == CON {
            self.waiting.push(Waiting {
                message,
                target: Target::Default,
                sent: Instant::now(),
                timeout: ACK_TIMEOUT + Duration::from_millis(self.counter.next() % 1000),
                tries: 0,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn request(
        &mut self,
        method: u8,
        path: &str,
        payload: Vec<u8>,
        format: Option<u32>,
        accept: Option<u32>,
        observe: Option<u32>,
        non: bool,
        io: &mut Io,
    ) {
        let token = self.token();
        let mut options = path_options(path);
        if let Some(observe) = observe {
            options.push((OBSERVE, uint(observe)));
        }
        if let Some(format) = format {
            options.push((CONTENT_FORMAT, uint(format)));
        }
        if let Some(accept) = accept {
            options.push((ACCEPT, uint(accept)));
        }
        let message = Message {
            kind: if non { NON } else { CON },
            code: method,
            id: self.id(),
            token: token.clone(),
            options,
            payload,
        };
        io.report(json!({
            "type": "request",
            "token": hex(&token),
            "method": code_name(method),
            "path": path,
            "observe": observe == Some(0),
        }));
        self.requests.insert(
            token,
            Request {
                method,
                path: path.to_string(),
                body: Vec::new(),
                observe: observe == Some(0),
                accept,
                sent: Instant::now(),
            },
        );
        self.send(message, io);
    }

    fn handle(&mut self, peer: PeerId, message: Message, io: &mut Io) {
        // An ACK or a RST ends the wait of the message it answers.
        if message.kind == ACK || message.kind == RST {
            self.waiting
                .retain(|waiting| waiting.message.id != message.id);
        }
        if message.kind == RST {
            // As the answer to a ping is.
            io.report(json!({ "type": "rst" }));
            return;
        }
        // A separate response or a notification sent as CON wants an ACK.
        if message.kind == CON {
            let ack = Message {
                kind: if self.requests.contains_key(&message.token) {
                    ACK
                } else {
                    RST
                },
                code: 0,
                id: message.id,
                ..Message::default()
            };
            io.went(peer, &describe(&ack));
            io.send(Target::Peer(peer), ack.encode());
        }
        if message.code == 0 {
            return;
        }
        let Some(request) = self.requests.get_mut(&message.token) else {
            return;
        };
        let mut payload = message.payload.clone();
        let mut blocks = None;
        // A response in blocks: ask for the next one, and show the whole at the end.
        if let Some(value) = message.uint_option(BLOCK2) {
            let (number, more, size) = block(value);
            request.body.extend_from_slice(&message.payload);
            if more {
                let path = request.path.clone();
                let method = request.method;
                let accept = request.accept;
                let token = message.token.clone();
                let mut options = path_options(&path);
                options.push((BLOCK2, uint(block_value(number + 1, false, size))));
                if let Some(accept) = accept {
                    options.push((ACCEPT, uint(accept)));
                }
                let next = Message {
                    kind: CON,
                    code: method,
                    id: self.id(),
                    token,
                    options,
                    payload: Vec::new(),
                };
                self.send(next, io);
                return;
            }
            let whole = std::mem::take(&mut request.body);
            io.note(&format!(
                "The whole of {} came in {} blocks: {}",
                request.path,
                number + 1,
                payload_text(&whole)
            ));
            payload = whole;
            blocks = Some(number + 1);
        }
        io.report(json!({
            "type": "response",
            "token": hex(&message.token),
            "code": code_name(message.code),
            "class": message.code >> 5,
            "format": message.uint_option(CONTENT_FORMAT).map(format_name),
            "payload": hex(&payload),
            "observe": message.uint_option(OBSERVE),
            "blocks": blocks,
            "ms": request.sent.elapsed().as_secs_f64() * 1000.0,
        }));
        let observing = request.observe && message.option(OBSERVE).is_some();
        if !observing {
            self.requests.remove(&message.token);
        }
    }
}

const CLIENT_HELP: &str = "get <path> [-a json]                   GET; -a for the format wanted back
post <path> [-f json] <payload>        POST; -f for the payload's format: text, json, cbor, link, or a number
put <path> [-f json] <payload>         PUT
delete <path>                          DELETE
observe <path>                         GET with Observe: shows each change
cancel <path>                          stop observing
discover                               GET /.well-known/core: the server's resources
ping                                   an empty CON, which a server answers with RST
Add -n to send a request as NON, not sent again. Paths may have a ?query.";

impl Engine for Client {
    fn help(&self) -> &'static str {
        CLIENT_HELP
    }

    fn joined(&mut self, peer: &Peer, _io: &mut Io) {
        self.server = peer.id;
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        self.server = peer;
        match Message::decode(bytes) {
            Ok(message) => {
                io.came(peer, &describe(&message));
                self.handle(peer, message, io);
            }
            Err(problem) => io.bad(&format!(
                "A datagram is not CoAP: {problem}: {}",
                hex_text(bytes)
            )),
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let command = words.next().unwrap_or_default().to_lowercase();
        let result = (|| -> Result<(), String> {
            let method = match command.as_str() {
                "get" => GET,
                "post" => POST,
                "put" => PUT,
                "delete" | "del" => DELETE,
                "observe" | "obs" => GET,
                "discover" => {
                    let non = self.options.non;
                    self.request(
                        GET,
                        "/.well-known/core",
                        Vec::new(),
                        None,
                        None,
                        None,
                        non,
                        io,
                    );
                    return Ok(());
                }
                "cancel" => {
                    let path = words.need("the path observed")?;
                    let found: Vec<Vec<u8>> = self
                        .requests
                        .iter()
                        .filter(|(_, request)| request.observe && request.path == path)
                        .map(|(token, _)| token.clone())
                        .collect();
                    if found.is_empty() {
                        return Err(format!("{path} is not observed."));
                    }
                    io.report(json!({ "type": "cancelled", "path": path }));
                    for token in found {
                        self.requests.remove(&token);
                        let message = Message {
                            kind: CON,
                            code: GET,
                            id: self.id(),
                            token,
                            options: [path_options(&path), vec![(OBSERVE, uint(1))]].concat(),
                            payload: Vec::new(),
                        };
                        self.send(message, io);
                    }
                    return Ok(());
                }
                "ping" => {
                    let message = Message {
                        kind: CON,
                        code: 0,
                        id: self.id(),
                        ..Message::default()
                    };
                    self.send(message, io);
                    return Ok(());
                }
                other => {
                    return Err(format!(
                        "{other} is not a command here. Type help for the list."
                    ));
                }
            };
            let mut non = self.options.non;
            let mut format = None;
            let mut accept = None;
            let mut path = None;
            // Flags may come before or after the path, and a format after
            // its flag as a word of its own or not: -a json, or -ajson.
            loop {
                let flags = words.flags();
                if flags.is_empty() {
                    if path.is_some() {
                        break;
                    }
                    path = words.next();
                    if path.is_none() {
                        break;
                    }
                    continue;
                }
                for (letter, value) in flags {
                    let value = if value.is_empty() && letter != 'n' {
                        words.next().unwrap_or_default()
                    } else {
                        value
                    };
                    match letter {
                        'n' => non = true,
                        'f' => {
                            format = Some(
                                format_number(&value)
                                    .ok_or(format!("{value} is not a content format."))?,
                            )
                        }
                        'a' => {
                            accept = Some(
                                format_number(&value)
                                    .ok_or(format!("{value} is not a content format."))?,
                            )
                        }
                        other => return Err(format!("-{other} is not a flag here: -n, -f or -a.")),
                    }
                }
            }
            let path = path.ok_or("Missing: the path, such as /sensors/temp.")?;
            let path = if path.starts_with('/') {
                path
            } else {
                format!("/{path}")
            };
            let payload = if method == POST || method == PUT {
                words.rest()
            } else {
                Vec::new()
            };
            let observe = (command == "observe" || command == "obs").then_some(0);
            self.request(method, &path, payload, format, accept, observe, non, io);
            Ok(())
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        let mut again = Vec::new();
        self.waiting.retain_mut(|waiting| {
            if now.duration_since(waiting.sent) < waiting.timeout {
                return true;
            }
            if waiting.tries >= MAX_RETRANSMIT {
                io.bad(&format!(
                    "No answer to {} {} after {} tries: is a CoAP server there?",
                    kind_name(waiting.message.kind),
                    code_name(waiting.message.code),
                    waiting.tries + 1
                ));
                io.report(json!({
                    "type": "timeout",
                    "token": hex(&waiting.message.token),
                    "tries": waiting.tries + 1,
                }));
                return false;
            }
            waiting.tries += 1;
            waiting.sent = now;
            waiting.timeout *= 2;
            again.push((waiting.message.clone(), waiting.target, waiting.tries));
            true
        });
        for (message, target, tries) in again {
            io.went(
                self.server,
                &format!("{} (again, try {})", describe(&message), tries + 1),
            );
            io.send(target, message.encode());
        }
    }
}

// ----- The server -----

/// A CoAP server tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ServerOptions {
    /// Resources it starts with, as "path=value" with commas between, such
    /// as "sensors/temp=21.5, led=off".
    pub resources: String,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            resources: "sensors/temp=21.5, sensors/hum=48, led=off".into(),
        }
    }
}

struct Observer {
    peer: PeerId,
    token: Vec<u8>,
}

struct Resource {
    value: Vec<u8>,
    format: u32,
    observers: Vec<Observer>,
}

pub struct Server {
    resources: BTreeMap<String, Resource>,
    next_id: u16,
    /// The number each notification carries, going up.
    sequence: u32,
    /// Answers sent lately, by peer and message id, sent again for a request
    /// that comes again.
    answered: VecDeque<(PeerId, u16, Vec<u8>)>,
    /// Whether the resources or their observers changed since the view was
    /// told, as it is on the next tick.
    changed: bool,
}

impl Server {
    pub fn new(options: ServerOptions) -> Self {
        let mut resources = BTreeMap::new();
        for item in options.resources.split(',') {
            let Some((path, value)) = item.split_once('=') else {
                continue;
            };
            let path = format!("/{}", path.trim().trim_matches('/'));
            resources.insert(
                path,
                Resource {
                    value: value.trim().as_bytes().to_vec(),
                    format: 0,
                    observers: Vec::new(),
                },
            );
        }
        let mut counter = Counter::new();
        let next_id = counter.next() as u16;
        Self {
            resources,
            next_id,
            sequence: 2,
            answered: VecDeque::new(),
            changed: true,
        }
    }

    /// Tells the view the resources, with their values and observers.
    fn report_resources(&mut self, io: &mut Io) {
        self.changed = false;
        let resources: Vec<serde_json::Value> = self
            .resources
            .iter()
            .map(|(path, resource)| {
                json!({
                    "path": path,
                    "value": hex(&resource.value),
                    "format": format_name(resource.format),
                    "observers": resource.observers.len(),
                })
            })
            .collect();
        io.report(json!({ "type": "resources", "resources": resources }));
    }

    fn link_format(&self) -> Vec<u8> {
        self.resources
            .iter()
            .map(|(path, resource)| {
                let observable = ";obs";
                format!("<{path}>;ct={}{observable}", resource.format)
            })
            .collect::<Vec<_>>()
            .join(",")
            .into_bytes()
    }

    fn answer(&mut self, peer: PeerId, request: &Message, reply: Message, io: &mut Io) {
        io.report(json!({
            "type": "heard",
            "peer": peer,
            "method": code_name(request.code),
            "path": request.plain_path(),
            "payload": hex(&request.payload),
            "observe": request.uint_option(OBSERVE),
            "code": code_name(reply.code),
            "class": reply.code >> 5,
        }));
        // A change, or an observer come or gone, shows in the resources.
        if matches!(request.code, PUT | POST | DELETE) || request.option(OBSERVE).is_some() {
            self.changed = true;
        }
        io.went(peer, &describe(&reply));
        let bytes = reply.encode();
        if request.kind == CON {
            self.answered.push_back((peer, request.id, bytes.clone()));
            if self.answered.len() > 64 {
                self.answered.pop_front();
            }
        }
        io.send(Target::Peer(peer), bytes);
    }

    /// The reply to a request with `code`, a value and its format, cut to the
    /// block asked for when it is bigger than a block.
    fn reply(&mut self, request: &Message, code: u8, value: Option<(&[u8], u32)>) -> Message {
        let (kind, id) = if request.kind == CON {
            (ACK, request.id)
        } else {
            self.next_id = self.next_id.wrapping_add(1);
            (NON, self.next_id)
        };
        let mut reply = Message {
            kind,
            code,
            id,
            token: request.token.clone(),
            ..Message::default()
        };
        if let Some((value, format)) = value {
            reply.options.push((CONTENT_FORMAT, uint(format)));
            let asked = request.uint_option(BLOCK2).map(block);
            if value.len() > BLOCK_SIZE || asked.is_some() {
                let (number, _, size) = asked.unwrap_or((0, false, BLOCK_SIZE));
                let size = size.min(BLOCK_SIZE);
                let start = (number as usize * size).min(value.len());
                let end = (start + size).min(value.len());
                reply
                    .options
                    .push((BLOCK2, uint(block_value(number, end < value.len(), size))));
                if number == 0 {
                    reply.options.push((SIZE2, uint(value.len() as u32)));
                }
                reply.payload = value[start..end].to_vec();
            } else {
                reply.payload = value.to_vec();
            }
        }
        reply
    }

    fn handle(&mut self, peer: PeerId, request: Message, io: &mut Io) {
        if request.kind == ACK || request.kind == RST {
            if request.kind == RST {
                // A RST to a notification ends that observation.
                for resource in self.resources.values_mut() {
                    resource.observers.retain(|observer| observer.peer != peer);
                }
                self.changed = true;
            }
            return;
        }
        // The same request again: the same answer again.
        if request.kind == CON
            && let Some((_, _, bytes)) = self
                .answered
                .iter()
                .find(|(from, id, _)| *from == peer && *id == request.id)
        {
            io.note("The same request came again: the same answer goes again.");
            io.send(Target::Peer(peer), bytes.clone());
            return;
        }
        if request.code == 0 {
            // A ping: an empty CON is answered with RST.
            let reset = Message {
                kind: RST,
                code: 0,
                id: request.id,
                ..Message::default()
            };
            io.went(peer, &describe(&reset));
            io.send(Target::Peer(peer), reset.encode());
            return;
        }
        let path = request.plain_path();
        let reply = match request.code {
            GET if path == "/.well-known/core" => {
                let links = self.link_format();
                self.reply(&request, CONTENT, Some((&links, 40)))
            }
            GET => match self
                .resources
                .get(&path)
                .map(|resource| (resource.value.clone(), resource.format))
            {
                Some((value, format)) => {
                    match request.uint_option(OBSERVE) {
                        Some(0) => {
                            if let Some(resource) = self.resources.get_mut(&path) {
                                resource.observers.retain(|observer| {
                                    !(observer.peer == peer && observer.token == request.token)
                                });
                                resource.observers.push(Observer {
                                    peer,
                                    token: request.token.clone(),
                                });
                            }
                        }
                        Some(1) => {
                            if let Some(resource) = self.resources.get_mut(&path) {
                                resource.observers.retain(|observer| {
                                    !(observer.peer == peer && observer.token == request.token)
                                });
                            }
                        }
                        _ => {}
                    }
                    let mut reply = self.reply(&request, CONTENT, Some((&value, format)));
                    if request.uint_option(OBSERVE) == Some(0) {
                        reply.options.push((OBSERVE, uint(self.sequence)));
                    }
                    reply
                }
                None => self.reply(&request, NOT_FOUND, None),
            },
            PUT | POST => {
                let format = request.uint_option(CONTENT_FORMAT).unwrap_or(0);
                let created = !self.resources.contains_key(&path);
                if path == "/.well-known/core" {
                    self.reply(&request, METHOD_NOT_ALLOWED, None)
                } else {
                    let resource = self.resources.entry(path.clone()).or_insert(Resource {
                        value: Vec::new(),
                        format,
                        observers: Vec::new(),
                    });
                    resource.value = request.payload.clone();
                    resource.format = format;
                    let reply = self.reply(&request, if created { CREATED } else { CHANGED }, None);
                    self.answer(peer, &request, reply, io);
                    self.notify(&path, io);
                    return;
                }
            }
            DELETE => match self.resources.remove(&path) {
                Some(_) => self.reply(&request, DELETED, None),
                None => self.reply(&request, NOT_FOUND, None),
            },
            _ => self.reply(&request, METHOD_NOT_ALLOWED, None),
        };
        self.answer(peer, &request, reply, io);
    }

    /// Sends a resource's value to each of its observers.
    fn notify(&mut self, path: &str, io: &mut Io) {
        let Some(resource) = self.resources.get(path) else {
            return;
        };
        if resource.observers.is_empty() {
            return;
        }
        self.sequence = self.sequence.wrapping_add(1) & 0xff_ffff;
        let sequence = self.sequence;
        let sends: Vec<(PeerId, Message)> = resource
            .observers
            .iter()
            .map(|observer| {
                (
                    observer.peer,
                    Message {
                        kind: NON,
                        code: CONTENT,
                        id: 0,
                        token: observer.token.clone(),
                        options: vec![
                            (OBSERVE, uint(sequence)),
                            (CONTENT_FORMAT, uint(resource.format)),
                        ],
                        payload: resource.value.clone(),
                    },
                )
            })
            .collect();
        for (peer, mut message) in sends {
            self.next_id = self.next_id.wrapping_add(1);
            message.id = self.next_id;
            io.went(peer, &describe(&message));
            io.send(Target::Peer(peer), message.encode());
        }
    }
}

const SERVER_HELP: &str =
    "set <path> <value>        set a resource, made if new, and tell its observers
remove <path>             remove a resource
resources                 the resources and who observes them";

impl Engine for Server {
    fn help(&self) -> &'static str {
        SERVER_HELP
    }

    fn left(&mut self, peer: PeerId, _io: &mut Io) {
        for resource in self.resources.values_mut() {
            resource.observers.retain(|observer| observer.peer != peer);
        }
        self.changed = true;
    }

    fn tick(&mut self, _now: Instant, io: &mut Io) {
        if self.changed {
            self.report_resources(io);
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        match Message::decode(bytes) {
            Ok(message) => {
                io.came(peer, &describe(&message));
                self.handle(peer, message, io);
            }
            Err(problem) => io.bad(&format!(
                "A datagram is not CoAP: {problem}: {}",
                hex_text(bytes)
            )),
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let command = words.next().unwrap_or_default().to_lowercase();
        let result = (|| -> Result<(), String> {
            match command.as_str() {
                "set" => {
                    let path = words.need("the path")?;
                    let path = format!("/{}", path.trim_matches('/'));
                    let value = words.rest();
                    let resource = self.resources.entry(path.clone()).or_insert(Resource {
                        value: Vec::new(),
                        format: 0,
                        observers: Vec::new(),
                    });
                    resource.value = value;
                    let observers = resource.observers.len();
                    io.note(&format!("{path} is set; {observers} observers are told."));
                    self.changed = true;
                    self.notify(&path, io);
                }
                "remove" | "delete" => {
                    let path = words.need("the path")?;
                    let path = format!("/{}", path.trim_matches('/'));
                    if self.resources.remove(&path).is_none() {
                        return Err(format!("There is no {path}."));
                    }
                    self.changed = true;
                    io.note(&format!("{path} is removed."));
                }
                "resources" | "list" => {
                    if self.resources.is_empty() {
                        io.note("No resource yet: set one, or a client can PUT one.");
                    }
                    let lines: Vec<String> = self
                        .resources
                        .iter()
                        .map(|(path, resource)| {
                            format!(
                                "{path} = {} ({}, {} observers)",
                                payload_text(&resource.value),
                                format_name(resource.format),
                                resource.observers.len()
                            )
                        })
                        .collect();
                    for line in lines {
                        io.note(&line);
                    }
                }
                other => {
                    return Err(format!(
                        "{other} is not a command here. Type help for the list."
                    ));
                }
            }
            Ok(())
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }
}

// ----- CoAP over TCP (RFC 8323) -----

const CSM: u8 = code(7, 1);
const PING: u8 = code(7, 2);
const PONG: u8 = code(7, 3);
const RELEASE: u8 = code(7, 4);
const ABORT: u8 = code(7, 5);
/// CSM's options: the largest message taken, and whether blocks are.
const MAX_MESSAGE_SIZE: u16 = 2;
const BLOCK_WISE: u16 = 4;
/// The largest message this end takes, as its CSM says.
const LARGEST: u32 = 8192;

/// A message as TCP carries it (RFC 8323, 3.2): the length of its options
/// and payload first, then its code and token; no type or message id.
fn tcp_frame(message: &Message) -> Vec<u8> {
    let udp = message.encode();
    let body = &udp[4 + message.token.len()..];
    let length = body.len();
    let (nibble, extended): (u8, Vec<u8>) = if length < 13 {
        (length as u8, Vec::new())
    } else if length < 269 {
        (13, vec![(length - 13) as u8])
    } else if length < 65805 {
        (14, ((length - 269) as u16).to_be_bytes().to_vec())
    } else {
        (15, ((length - 65805) as u32).to_be_bytes().to_vec())
    };
    let mut out = vec![nibble << 4 | message.token.len() as u8];
    out.extend(extended);
    out.push(message.code);
    out.extend_from_slice(&message.token);
    out.extend_from_slice(body);
    out
}

/// Takes the first whole message off a TCP stream, as one of `kind` and
/// `id` would come over UDP.
fn tcp_take(buffer: &mut Vec<u8>, kind: u8, id: u16) -> Result<Option<Message>, String> {
    let Some(first) = buffer.first().copied() else {
        return Ok(None);
    };
    let token_length = usize::from(first & 0x0f);
    if token_length > 8 {
        return Err("a token is longer than 8 bytes".into());
    }
    let extended = match first >> 4 {
        13 => 1,
        14 => 2,
        15 => 4,
        _ => 0,
    };
    let head = 1 + extended + 1 + token_length;
    if buffer.len() < head {
        return Ok(None);
    }
    let extra = buffer[1..1 + extended]
        .iter()
        .fold(0usize, |value, byte| value << 8 | usize::from(*byte));
    let length = match first >> 4 {
        13 => extra + 13,
        14 => extra + 269,
        15 => extra + 65805,
        nibble => usize::from(nibble),
    };
    if length > 16 * 1024 * 1024 {
        return Err(format!(
            "a message of {length} bytes is more than netNIMA takes"
        ));
    }
    if buffer.len() < head + length {
        return Ok(None);
    }
    let code = buffer[1 + extended];
    let mut udp = vec![0x40 | kind << 4 | first & 0x0f, code];
    udp.extend_from_slice(&id.to_be_bytes());
    udp.extend_from_slice(&buffer[2 + extended..head + length]);
    buffer.drain(..head + length);
    Message::decode(&udp).map(Some)
}

/// A signal (7.xx) in a line.
fn describe_signal(message: &Message) -> String {
    match message.code {
        CSM => {
            let size = message
                .uint_option(MAX_MESSAGE_SIZE)
                .map_or_else(|| "1152, the least".to_string(), |size| size.to_string());
            let blocks = if message.option(BLOCK_WISE).is_some() {
                ", block-wise"
            } else {
                ""
            };
            format!("7.01 CSM: messages up to {size} bytes{blocks}")
        }
        PING => "7.02 Ping".into(),
        PONG => "7.03 Pong".into(),
        RELEASE => "7.04 Release".into(),
        ABORT => format!("7.05 Abort: {}", payload_text(&message.payload)),
        other => format!("signal {}", code_name(other)),
    }
}

/// A CoAP client or server over TCP, or TLS: the engine inside speaks CoAP
/// as over UDP, and this end changes the framing. Each end sends its CSM
/// first; TCP is reliable, so what the engine sends as CON is taken as
/// acknowledged at once, and what comes goes to it as CON for requests and
/// NON for responses. Lines show the messages as UDP would carry them.
pub struct OverTcp<E> {
    inner: E,
    buffers: BTreeMap<PeerId, Vec<u8>>,
    next_id: u16,
    last: Option<PeerId>,
    /// Over WebSocket (RFC 8323, 4): each message is what came at once, and
    /// its length field is 0.
    websocket: bool,
}

impl<E: Engine> OverTcp<E> {
    pub fn new(inner: E) -> Self {
        Self {
            inner,
            buffers: BTreeMap::new(),
            next_id: 0x7000,
            last: None,
            websocket: false,
        }
    }

    /// CoAP over WebSocket: under a carrier that gives each WebSocket
    /// message whole.
    pub fn over_websocket(inner: E) -> Self {
        Self {
            websocket: true,
            ..Self::new(inner)
        }
    }

    fn frame(&self, peer: PeerId, message: &Message, io: &mut Io) {
        if message.code >> 5 == 7 {
            io.went(peer, &describe_signal(message));
        }
        let mut framed = tcp_frame(message);
        if self.websocket {
            // No length: the WebSocket message says where it ends.
            let extended = match framed[0] >> 4 {
                13 => 1,
                14 => 2,
                15 => 4,
                _ => 0,
            };
            framed.drain(1..1 + extended);
            framed[0] &= 0x0f;
        }
        io.send(Target::Peer(peer), framed);
    }

    /// Runs the engine inside, then sends what it sent, framed for TCP. Its
    /// CON messages are acknowledged at once, as TCP carries them surely.
    fn inside(&mut self, io: &mut Io, run: impl FnOnce(&mut E, &mut Io)) {
        let mut held = Vec::new();
        run(&mut self.inner, &mut io.holding(&mut held));
        let mut acks = Vec::new();
        for (target, bytes) in held {
            let Ok(message) = Message::decode(&bytes) else {
                continue;
            };
            let peers: Vec<PeerId> = match target {
                Target::Peer(peer) => vec![peer],
                Target::All => self.buffers.keys().copied().collect(),
                Target::Default => self
                    .last
                    .or_else(|| self.buffers.keys().next().copied())
                    .into_iter()
                    .collect(),
            };
            for peer in peers {
                if message.code == 0 {
                    // A CoAP ping (an empty CON) is TCP's Ping; ACKs and RSTs
                    // are not needed.
                    if message.kind == CON {
                        let ping = Message {
                            code: PING,
                            ..Message::default()
                        };
                        self.frame(peer, &ping, io);
                        acks.push((peer, message.id, RST));
                    }
                    continue;
                }
                self.frame(peer, &message, io);
                if message.kind == CON {
                    acks.push((peer, message.id, ACK));
                }
            }
        }
        // These never went over TCP, so they show no line.
        for (peer, id, kind) in acks {
            let ack = Message {
                kind,
                id,
                ..Message::default()
            }
            .encode();
            let mut ignored = Vec::new();
            let mut quiet = |_: crate::net::Event| {};
            let mut silent = Io {
                socket: io.socket,
                tell: &mut quiet,
                held: Some(&mut ignored),
            };
            self.inner.received(peer, &ack, &mut silent);
        }
    }
}

impl<E: Engine> Engine for OverTcp<E> {
    fn help(&self) -> &'static str {
        self.inner.help()
    }

    fn joined(&mut self, peer: &Peer, io: &mut Io) {
        self.buffers.insert(peer.id, Vec::new());
        self.last = Some(peer.id);
        let csm = Message {
            code: CSM,
            options: vec![(MAX_MESSAGE_SIZE, uint(LARGEST)), (BLOCK_WISE, Vec::new())],
            ..Message::default()
        };
        self.frame(peer.id, &csm, io);
        let joined = peer.clone();
        self.inside(io, |inner, io| inner.joined(&joined, io));
    }

    fn left(&mut self, peer: PeerId, io: &mut Io) {
        self.buffers.remove(&peer);
        if self.last == Some(peer) {
            self.last = None;
        }
        self.inside(io, |inner, io| inner.left(peer, io));
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        self.last = Some(peer);
        let mut messages = Vec::new();
        if self.websocket {
            // One message, its length what came: it is put as TCP would carry it.
            self.next_id = self.next_id.wrapping_add(1);
            let Some(first) = bytes.first().copied() else {
                return;
            };
            let length = bytes.len().saturating_sub(2 + usize::from(first & 0x0f));
            let mut framed = Vec::with_capacity(bytes.len() + 4);
            let (nibble, extended): (u8, Vec<u8>) = if length < 13 {
                (length as u8, Vec::new())
            } else if length < 269 {
                (13, vec![(length - 13) as u8])
            } else if length < 65805 {
                (14, ((length - 269) as u16).to_be_bytes().to_vec())
            } else {
                (15, ((length - 65805) as u32).to_be_bytes().to_vec())
            };
            framed.push(nibble << 4 | first & 0x0f);
            framed.extend(extended);
            framed.extend_from_slice(&bytes[1..]);
            match tcp_take(&mut framed, CON, self.next_id) {
                Ok(Some(message)) => messages.push(message),
                Ok(None) | Err(_) => {
                    io.bad("Not CoAP over WebSocket: a message that cannot be read.");
                    return;
                }
            }
        } else {
            let buffer = self.buffers.entry(peer).or_default();
            buffer.extend_from_slice(bytes);
            loop {
                self.next_id = self.next_id.wrapping_add(1);
                match tcp_take(buffer, CON, self.next_id) {
                    Ok(Some(message)) => messages.push(message),
                    Ok(None) => break,
                    Err(problem) => {
                        io.bad(&format!("Not CoAP over TCP: {problem}."));
                        buffer.clear();
                        break;
                    }
                }
            }
        }
        for mut message in messages {
            match message.code {
                CSM | PONG => io.came(peer, &describe_signal(&message)),
                PING => {
                    io.came(peer, &describe_signal(&message));
                    let pong = Message {
                        code: PONG,
                        token: message.token.clone(),
                        ..Message::default()
                    };
                    self.frame(peer, &pong, io);
                }
                RELEASE | ABORT => {
                    io.came(peer, &describe_signal(&message));
                    io.drop_peer(peer);
                }
                code if code >> 5 == 7 => io.came(peer, &describe_signal(&message)),
                code => {
                    // Requests come to the engine as CON; responses as NON,
                    // which it takes by their token.
                    if code >> 5 != 0 {
                        message.kind = NON;
                    }
                    let bytes = message.encode();
                    self.inside(io, |inner, io| inner.received(peer, &bytes, io));
                }
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        self.inside(io, |inner, io| inner.command(words, io));
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        self.inside(io, |inner, io| inner.tick(now, io));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{listening, shown, start, udp_on_loopback};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn tcp_frames_read_back_with_every_length() {
        for size in [0, 5, 12, 13, 200, 268, 269, 2000, 70_000] {
            let message = Message {
                kind: CON,
                code: PUT,
                id: 7,
                token: vec![1, 2],
                options: vec![(URI_PATH, b"led".to_vec())],
                payload: vec![b'x'; size],
            };
            let mut stream = tcp_frame(&message);
            stream.extend_from_slice(&tcp_frame(&message));
            let first = tcp_take(&mut stream, CON, 7).unwrap().unwrap();
            assert_eq!(first, message, "{size}");
            assert!(tcp_take(&mut stream, CON, 7).unwrap().is_some());
            assert!(stream.is_empty());
        }
        // RFC 8323's own sizes: 13 bytes take one more byte for the length.
        let message = Message {
            code: GET,
            payload: vec![0; 12],
            ..Message::default()
        };
        assert_eq!(tcp_frame(&message)[0] >> 4, 13);
        let mut half = tcp_frame(&message);
        half.truncate(5);
        assert!(tcp_take(&mut half, CON, 1).unwrap().is_none());
    }

    #[test]
    fn a_client_and_a_server_talk_over_tcp() {
        use crate::proto::tests::{client_to, server_on_loopback};
        let (_server, server_events) = start(
            Box::new(OverTcp::new(Server::new(ServerOptions::default()))),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(OverTcp::new(Client::new(ClientOptions::default()))),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        shown(
            &client_events,
            "7.01 CSM: messages up to 8192 bytes, block-wise",
        );
        client.command("get /sensors/temp");
        shown(&client_events, ": 21.5");
        client.command("observe /led");
        shown(&client_events, "Observe 2");
        client.command("put /led on");
        shown(&client_events, "2.04 Changed");
        shown(&client_events, ": on");
        let big = "x".repeat(1300);
        client.command(&format!("put /big {big}"));
        client.command("get /big");
        shown(&client_events, "came in 3 blocks");
        client.command("ping");
        shown(&client_events, "7.03 Pong");
        shown(&server_events, "7.02 Ping");
    }

    #[test]
    fn a_client_and_a_server_talk_over_websocket() {
        use crate::proto::tests::{client_to, server_on_loopback};
        use crate::proto::{SocketKind, engine};
        let (server_engine, _) = engine("coap_ws_server", serde_json::Value::Null).unwrap();
        let (_server, server_events) = start(
            server_engine,
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client_engine, _) = engine(
            "coap_ws_client",
            serde_json::json!({"host": "127.0.0.1", "port": port}),
        )
        .unwrap();
        let (client, client_events) = start(
            client_engine,
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        let text = shown(&client_events, "101 Switching Protocols");
        assert!(text.contains("GET /.well-known/coap"), "{text}");
        shown(&client_events, "7.01 CSM");
        client.command("get /sensors/temp");
        shown(&client_events, ": 21.5");
        let big = "x".repeat(700);
        client.command(&format!("put /big {big}"));
        client.command("get /big");
        shown(&client_events, "came in 2 blocks");
        client.command("ping");
        shown(&client_events, "7.03 Pong");
    }

    #[test]
    fn messages_read_back_as_they_were_written() {
        let message = Message {
            kind: CON,
            code: GET,
            id: 0x1234,
            token: vec![1, 2, 3, 4],
            options: vec![
                (URI_PATH, b"sensors".to_vec()),
                (URI_PATH, b"temp".to_vec()),
                (BLOCK2, uint(block_value(2, true, 64))),
                (300, vec![9; 300]),
            ],
            payload: b"21.5".to_vec(),
        };
        let decoded = Message::decode(&message.encode()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.path(), "/sensors/temp");
        assert_eq!(block(decoded.uint_option(BLOCK2).unwrap()), (2, true, 64));
        assert!(
            Message::decode(&[0x80, 1, 0, 0])
                .unwrap_err()
                .contains("version")
        );
        assert!(
            describe(&decoded).starts_with("CON GET /sensors/temp (id 0x1234, token 01020304)")
        );
    }

    #[test]
    fn a_client_gets_puts_observes_and_follows_blocks() {
        let (server, server_events) = start(
            Box::new(Server::new(ServerOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&client_events);
        client.command("get /sensors/temp");
        let text = shown(&client_events, ": 21.5");
        assert!(text.contains("ACK 2.05 Content"), "{text}");
        // A format after its flag as a word of its own, as help writes it, or not.
        client.command("get /sensors/temp -a json");
        shown(&client_events, "Accept application/json");
        client.command("get -n -acbor /sensors/temp");
        let text = shown(&client_events, "NON GET /sensors/temp");
        assert!(text.contains("Accept application/cbor"), "{text}");
        client.command("get /nothing");
        shown(&client_events, "4.04 Not Found");
        client.command("discover");
        shown(&client_events, "</sensors/temp>;ct=0;obs");

        client.command("observe /led");
        shown(&client_events, "Observe 2");
        client.command("put /led on");
        shown(&client_events, "2.04 Changed");
        shown(&client_events, "NON 2.05 Content");
        server.command("set led blinking");
        shown(&client_events, ": blinking");

        let big = "x".repeat(1300);
        server.command(&format!("set big {big}"));
        client.command("get /big");
        let text = shown(&client_events, "came in 3 blocks");
        assert!(text.contains("Block2 #2, the last"), "{text}");
        client.command("delete /big");
        shown(&client_events, "2.02 Deleted");
        client.command("ping");
        shown(&client_events, "RST Empty");
    }

    #[test]
    fn coaps_with_a_psk() {
        let dtls = crate::net::DtlsOptions {
            psk: true,
            psk_identity: "board".into(),
            psk_key: "00112233445566778899aabbccddeeff".into(),
            ..crate::net::DtlsOptions::default()
        };
        let (_server, server_events) = start(
            Box::new(Server::new(ServerOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                dtls: Some(dtls.clone()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                dtls: Some(dtls),
                ..SocketSetup::default()
            },
        );
        crate::net::tests::expect(&client_events, "DTLS", |event| {
            matches!(event, crate::net::Event::Secure { .. })
        });
        client.command("get /sensors/hum");
        let text = shown(&client_events, ": 48");
        assert!(text.contains("ACK 2.05 Content"), "{text}");
    }

    #[test]
    fn a_request_not_answered_is_sent_again() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = silent.local_addr().unwrap().port();
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&client_events);
        client.command("get /x");
        let mut buf = [0; 64];
        silent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (first, _) = silent.recv_from(&mut buf).unwrap();
        let first = buf[..first].to_vec();
        let (second, _) = silent.recv_from(&mut buf).unwrap();
        assert_eq!(
            &buf[..second],
            first.as_slice(),
            "the same message, the same id"
        );
        shown(&client_events, "(again, try 2)");
    }

    #[test]
    fn the_view_hears_requests_answers_and_resources() {
        use crate::proto::tests::reported;
        let (_server, server_events) = start(
            Box::new(Server::new(ServerOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        // The server tells its resources as it starts, and when they change.
        let resources = reported(&server_events, "resources");
        let paths: Vec<&str> = resources["resources"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|resource| resource["path"].as_str())
            .collect();
        assert_eq!(paths, ["/led", "/sensors/hum", "/sensors/temp"]);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&client_events);

        // Each request with its token, and the answer to it with the same.
        client.command("get /sensors/temp");
        let request = reported(&client_events, "request");
        assert_eq!(request["path"], "/sensors/temp");
        let answer = reported(&client_events, "response");
        assert_eq!(answer["token"], request["token"]);
        assert_eq!(answer["code"], "2.05 Content");
        assert_eq!(answer["payload"], hex(b"21.5"));
        assert_eq!(answer["format"], "text/plain");
        let heard = reported(&server_events, "heard");
        assert_eq!(
            (&heard["method"], &heard["code"]),
            (&json!("GET"), &json!("2.05 Content"))
        );

        client.command("put /led on");
        assert_eq!(reported(&client_events, "response")["code"], "2.04 Changed");
        let after = reported(&server_events, "resources");
        let led = after["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|resource| resource["path"] == "/led")
            .unwrap()
            .clone();
        assert_eq!(led["value"], hex(b"on"));

        // Observing: the first answer and each change carry an Observe number.
        client.command("observe /led");
        assert!(reported(&client_events, "response")["observe"].is_number());
        assert_eq!(
            reported(&server_events, "resources")["resources"][0]["observers"],
            1
        );
        client.command("ping");
        reported(&client_events, "rst");
    }
}
