//! LwM2M 1.1 over CoAP: a server that devices register with and that reads,
//! writes, executes and observes their resources, and a client that is such
//! a device, with the Server, Device, Firmware Update, Temperature and Light
//! Control objects. The server is a bootstrap server too when told what to
//! hand out, and pushes firmware to devices; the device can bootstrap first.
//!
//! Both are CoAP endpoints that send requests and answer them on one socket,
//! over UDP, or over DTLS with a PSK as most devices do. Values go as TLV,
//! SenML JSON, SenML CBOR, CBOR or plain text.

use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use super::cbor::Cbor;
use super::coap::{
    self, ACCEPT, ACK, ACK_TIMEOUT, BLOCK1, CON, CONTENT, CONTENT_FORMAT, Counter, DELETE, GET,
    MAX_RETRANSMIT, Message, NON, NOT_FOUND, OBSERVE, POST, PUT, RST, URI_QUERY, block,
    block_value, path_options, uint,
};
use super::smp::mcuboot_version;
use super::{Engine, Io, Words, hex, hex_text};
use crate::net::{Peer, PeerId, Target};

const TEXT: u32 = 0;
const LINKS: u32 = 40;
const OPAQUE: u32 = 42;
const TLV: u32 = 11542;
const SENML_JSON: u32 = 110;
/// One resource's value as CBOR.
const CBOR: u32 = 60;
const SENML_CBOR: u32 = 112;

const CREATED: u8 = coap::code(2, 1);
const DELETED: u8 = coap::code(2, 2);
const CHANGED: u8 = coap::code(2, 4);
const CONTINUE: u8 = coap::code(2, 31);
const BAD_REQUEST: u8 = coap::code(4, 0);
const UNAUTHORIZED: u8 = coap::code(4, 1);
const NOT_ALLOWED: u8 = coap::code(4, 5);
const NOT_ACCEPTABLE: u8 = coap::code(4, 6);
const INCOMPLETE: u8 = coap::code(4, 8);

/// The size of each block of a firmware image a server sends.
const BLOCK_SIZE: usize = 512;

/// Firmware Update's states (/5/0/3).
const IDLE: i64 = 0;
const DOWNLOADING: i64 = 1;
const DOWNLOADED: i64 = 2;
const UPDATING: i64 = 3;

/// A file named in a command: as it is when absolute, in Downloads otherwise.
fn file_path(name: &str) -> PathBuf {
    let path = PathBuf::from(name.trim());
    if path.is_absolute() {
        return path;
    }
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join("Downloads")
        .join(path)
}

/// Where a coap:// or coaps:// address is, its default port when it has none.
fn uri_address(uri: &str) -> Option<SocketAddr> {
    let (scheme, rest) = uri.trim().split_once("://")?;
    let default = if scheme.eq_ignore_ascii_case("coaps") {
        5684
    } else {
        5683
    };
    let authority = rest.split('/').next()?;
    let (host, port) = match authority.strip_prefix('[') {
        Some(inner) => {
            let (host, after) = inner.split_once(']')?;
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse().ok()?,
                None => default,
            };
            (host, port)
        }
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (authority, default),
        },
    };
    let found: Vec<SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    found
        .iter()
        .find(|at| at.is_ipv4())
        .or(found.first())
        .copied()
}

/// The query of a request, such as ep=board&lt=300, by name.
fn query(request: &Message) -> BTreeMap<String, String> {
    request
        .options
        .iter()
        .filter(|(number, _)| *number == URI_QUERY)
        .filter_map(|(_, value)| {
            let text = String::from_utf8_lossy(value).into_owned();
            text.split_once('=')
                .map(|(name, value)| (name.to_string(), value.to_string()))
        })
        .collect()
}

/// The type of a Security (0) or Server (1) resource a bootstrap server
/// writes, to read its TLV as.
fn bootstrap_kind(object: u16, resource: u16) -> Value {
    match (object, resource) {
        (0, 0) | (1, 7) => Value::Text(String::new()),
        (0, 1) | (1, 6) => Value::Bool(false),
        (0, 3..=5) => Value::Opaque(Vec::new()),
        _ => Value::Int(0),
    }
}

// ----- Values and TLV -----

/// A resource's value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Text(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Opaque(Vec<u8>),
}

impl Value {
    fn to_text(&self) -> String {
        match self {
            Value::Text(text) => text.clone(),
            Value::Int(value) => value.to_string(),
            Value::Float(value) => value.to_string(),
            Value::Bool(value) => u8::from(*value).to_string(),
            Value::Opaque(bytes) => hex_text(bytes),
        }
    }

    fn to_cbor(&self) -> Cbor {
        match self {
            Value::Text(text) => Cbor::Text(text.clone()),
            Value::Int(value) => Cbor::Int(i128::from(*value)),
            Value::Float(value) => Cbor::Float(*value),
            Value::Bool(value) => Cbor::Bool(*value),
            Value::Opaque(bytes) => Cbor::Bytes(bytes.clone()),
        }
    }

    /// SenML's label for the value: v (2), vs (3), vb (4) or vd (8).
    fn senml_label(&self) -> i128 {
        match self {
            Value::Int(_) | Value::Float(_) => 2,
            Value::Text(_) => 3,
            Value::Bool(_) => 4,
            Value::Opaque(_) => 8,
        }
    }

    fn tlv_bytes(&self) -> Vec<u8> {
        match self {
            Value::Text(text) => text.as_bytes().to_vec(),
            Value::Int(value) => {
                if let Ok(small) = i8::try_from(*value) {
                    small.to_be_bytes().to_vec()
                } else if let Ok(small) = i16::try_from(*value) {
                    small.to_be_bytes().to_vec()
                } else if let Ok(small) = i32::try_from(*value) {
                    small.to_be_bytes().to_vec()
                } else {
                    value.to_be_bytes().to_vec()
                }
            }
            Value::Float(value) => value.to_be_bytes().to_vec(),
            Value::Bool(value) => vec![u8::from(*value)],
            Value::Opaque(bytes) => bytes.clone(),
        }
    }

    /// A value typed in, as the resource's present value is: a number for a
    /// number, 0 or 1 for a boolean, text for text.
    fn parse_like(&self, text: &str) -> Result<Value, String> {
        let text = text.trim();
        match self {
            Value::Int(_) => text
                .parse()
                .map(Value::Int)
                .map_err(|_| format!("{text} is not a whole number.")),
            Value::Float(_) => text
                .parse()
                .map(Value::Float)
                .map_err(|_| format!("{text} is not a number.")),
            Value::Bool(_) => match text {
                "1" | "true" | "on" => Ok(Value::Bool(true)),
                "0" | "false" | "off" => Ok(Value::Bool(false)),
                _ => Err(format!("{text} is not 0 or 1.")),
            },
            Value::Text(_) => Ok(Value::Text(text.to_string())),
            Value::Opaque(_) => Ok(Value::Opaque(text.as_bytes().to_vec())),
        }
    }
}

/// One TLV item: what it is, its id, and its value or the items inside it.
#[derive(Clone, Debug, PartialEq)]
pub struct Tlv {
    /// 0 object instance, 1 resource instance, 2 multiple resource, 3 resource.
    pub kind: u8,
    pub id: u16,
    pub value: Vec<u8>,
}

pub fn tlv_encode(kind: u8, id: u16, value: &[u8]) -> Vec<u8> {
    let mut first = kind << 6;
    if id > 0xff {
        first |= 0x20;
    }
    let length = value.len();
    let length_bytes: Vec<u8> = if length < 8 {
        first |= length as u8;
        Vec::new()
    } else if length <= 0xff {
        first |= 0x08;
        vec![length as u8]
    } else if length <= 0xffff {
        first |= 0x10;
        (length as u16).to_be_bytes().to_vec()
    } else {
        first |= 0x18;
        (length as u32).to_be_bytes()[1..].to_vec()
    };
    let mut out = vec![first];
    if id > 0xff {
        out.extend_from_slice(&id.to_be_bytes());
    } else {
        out.push(id as u8);
    }
    out.extend(length_bytes);
    out.extend_from_slice(value);
    out
}

pub fn tlv_decode(mut bytes: &[u8]) -> Result<Vec<Tlv>, String> {
    let mut items = Vec::new();
    while !bytes.is_empty() {
        let first = bytes[0];
        let mut at = 1;
        let id = if first & 0x20 != 0 {
            let id = u16::from_be_bytes([
                *bytes.get(1).ok_or("a TLV is cut short")?,
                *bytes.get(2).ok_or("a TLV is cut short")?,
            ]);
            at += 2;
            id
        } else {
            let id = u16::from(*bytes.get(1).ok_or("a TLV is cut short")?);
            at += 1;
            id
        };
        let length = match (first >> 3) & 3 {
            0 => usize::from(first & 7),
            size => {
                let field = bytes
                    .get(at..at + usize::from(size))
                    .ok_or("a TLV is cut short")?;
                at += usize::from(size);
                field
                    .iter()
                    .fold(0usize, |length, byte| length << 8 | usize::from(*byte))
            }
        };
        let value = bytes
            .get(at..at + length)
            .ok_or("a TLV's value is cut short")?
            .to_vec();
        items.push(Tlv {
            kind: first >> 6,
            id,
            value,
        });
        bytes = &bytes[at + length..];
    }
    Ok(items)
}

/// The kind of value a well-known resource has, to show its TLV bytes.
fn resource_kind(object: u16, resource: u16) -> char {
    match (object, resource) {
        (3, 0..=3 | 14..=19) | (1, 7) | (3303, 5701) | (3311, 5701 | 5750) => 's',
        (3303, 5700 | 5601 | 5602 | 5603 | 5604) | (3311, 5820 | 5805) => 'f',
        (3311, 5850) => 'b',
        (3, 4..=6 | 12) | (1, 4 | 8) => 'x',
        _ => 'i',
    }
}

fn tlv_value_text(object: u16, resource: u16, value: &[u8]) -> String {
    match resource_kind(object, resource) {
        's' => String::from_utf8_lossy(value).into_owned(),
        'b' => (value.first() == Some(&1)).to_string(),
        'f' if value.len() == 4 => {
            f32::from_be_bytes(value.try_into().unwrap_or_default()).to_string()
        }
        'f' if value.len() == 8 => {
            f64::from_be_bytes(value.try_into().unwrap_or_default()).to_string()
        }
        _ if matches!(value.len(), 1 | 2 | 4 | 8) => {
            let mut wide = [if value[0] & 0x80 != 0 { 0xff } else { 0 }; 8];
            wide[8 - value.len()..].copy_from_slice(value);
            i64::from_be_bytes(wide).to_string()
        }
        _ => match std::str::from_utf8(value) {
            Ok(text) if !text.is_empty() && text.chars().all(|c| !c.is_control()) => {
                text.to_string()
            }
            _ => hex_text(value),
        },
    }
}

/// A TLV payload as lines of "/3/0/1 = model", given the path asked for.
fn tlv_text(path: &[u16], bytes: &[u8]) -> Result<String, String> {
    let mut lines = Vec::new();
    let object = path.first().copied().unwrap_or(0);
    let base = path
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("/");
    for item in tlv_decode(bytes)? {
        match item.kind {
            0 => {
                for inner in tlv_decode(&item.value)? {
                    lines.push(resource_line(
                        object,
                        &format!("/{object}/{}", item.id),
                        &inner,
                    )?);
                }
            }
            _ => {
                let prefix = if path.len() >= 2 {
                    format!(
                        "/{}",
                        path[..2]
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join("/")
                    )
                } else {
                    format!("/{base}")
                };
                lines.push(resource_line(object, &prefix, &item)?);
            }
        }
    }
    Ok(lines.join("\n"))
}

fn resource_line(object: u16, prefix: &str, item: &Tlv) -> Result<String, String> {
    if item.kind == 2 {
        let values: Vec<String> = tlv_decode(&item.value)?
            .iter()
            .map(|instance| {
                format!(
                    "[{}] {}",
                    instance.id,
                    tlv_value_text(object, item.id, &instance.value)
                )
            })
            .collect();
        return Ok(format!("{prefix}/{} = {}", item.id, values.join(", ")));
    }
    Ok(format!(
        "{prefix}/{} = {}",
        item.id,
        tlv_value_text(object, item.id, &item.value)
    ))
}

/// A payload as people read it, by its content format.
fn payload_text(format: Option<u32>, path: &[u16], payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    match format {
        Some(TLV) => tlv_text(path, payload)
            .unwrap_or_else(|problem| format!("TLV that cannot be read: {problem}")),
        Some(SENML_JSON) | Some(11543) => String::from_utf8_lossy(payload).into_owned(),
        Some(SENML_CBOR) => senml_cbor_text(payload)
            .unwrap_or_else(|problem| format!("SenML CBOR that cannot be read: {problem}")),
        Some(CBOR) => Cbor::decode(payload)
            .map(|(value, _)| value.to_string())
            .unwrap_or_else(|problem| format!("CBOR that cannot be read: {problem}")),
        Some(OPAQUE) => hex_text(payload),
        _ => super::payload_text(payload),
    }
}

/// SenML CBOR records (RFC 8428), a line each, as "/3/0/0 = netNIMA": the
/// base name (-2) before each name (0), and the value v, vs, vb or vd.
fn senml_cbor_text(payload: &[u8]) -> Result<String, String> {
    let (records, _) = Cbor::decode(payload)?;
    let Cbor::Array(records) = records else {
        return Err("it is not an array of records".into());
    };
    let mut base = String::new();
    let mut lines = Vec::new();
    for record in &records {
        let Cbor::Map(fields) = record else {
            continue;
        };
        let field = |label: i128| {
            fields
                .iter()
                .find(|(key, _)| *key == Cbor::Int(label))
                .map(|(_, value)| value)
        };
        if let Some(Cbor::Text(name)) = field(-2) {
            base = name.clone();
        }
        let name = match field(0) {
            Some(Cbor::Text(name)) => format!("{base}{name}"),
            _ => base.clone(),
        };
        let value = [2, 3, 4, 8]
            .iter()
            .find_map(|label| field(*label))
            .map(|value| match value {
                Cbor::Text(text) => text.clone(),
                Cbor::Bytes(bytes) => hex_text(bytes),
                other => other.to_string(),
            })
            .unwrap_or_default();
        lines.push(format!("{name} = {value}"));
    }
    Ok(lines.join("\n"))
}

/// "/3/0/1" as numbers.
fn parse_path(path: &str) -> Result<Vec<u16>, String> {
    let parts: Vec<&str> = path
        .trim()
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err(format!("{path} is not an LwM2M path, such as /3/0/1."));
    }
    parts
        .iter()
        .map(|part| {
            part.parse::<u16>()
                .map_err(|_| format!("{path} is not an LwM2M path, such as /3/0/1."))
        })
        .collect()
}

fn path_text(path: &[u16]) -> String {
    format!(
        "/{}",
        path.iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("/")
    )
}

/// A content format's short name, for the views.
fn format_short(format: u32) -> String {
    match format {
        TEXT => "text".into(),
        LINKS => "link".into(),
        OPAQUE => "opaque".into(),
        TLV => "TLV".into(),
        SENML_JSON => "SenML JSON".into(),
        11543 => "LwM2M JSON".into(),
        CBOR => "CBOR".into(),
        SENML_CBOR => "SenML CBOR".into(),
        other => other.to_string(),
    }
}

/// The resources' values in an answer, as (path, value) pairs, whatever
/// its format: what the views lay out. One resource read as text or CBOR
/// is the path asked for.
fn answer_values(format: Option<u32>, path: &[u16], payload: &[u8]) -> Vec<(String, String)> {
    let lines = |text: String| {
        text.lines()
            .filter_map(|line| line.split_once(" = "))
            .map(|(path, value)| (path.to_string(), value.to_string()))
            .collect::<Vec<_>>()
    };
    if payload.is_empty() {
        return Vec::new();
    }
    match format {
        Some(TLV) => tlv_text(path, payload).map(lines).unwrap_or_default(),
        Some(SENML_CBOR) => senml_cbor_text(payload).map(lines).unwrap_or_default(),
        Some(SENML_JSON) | Some(11543) => senml_json_values(payload),
        Some(CBOR) if path.len() >= 3 => Cbor::decode(payload)
            .map(|(value, _)| {
                let text = match value {
                    Cbor::Text(text) => text,
                    Cbor::Bytes(bytes) => hex_text(&bytes),
                    other => other.to_string(),
                };
                vec![(path_text(path), text)]
            })
            .unwrap_or_default(),
        Some(TEXT) | None if path.len() >= 3 => {
            vec![(
                path_text(path),
                String::from_utf8_lossy(payload).into_owned(),
            )]
        }
        Some(OPAQUE) if path.len() >= 3 => vec![(path_text(path), hex_text(payload))],
        _ => Vec::new(),
    }
}

/// SenML JSON records (RFC 8428) as (name, value) pairs: the base name
/// (bn) before each name (n), and the value v, vs, vb or vd.
fn senml_json_values(payload: &[u8]) -> Vec<(String, String)> {
    let Ok(serde_json::Value::Array(records)) = serde_json::from_slice(payload) else {
        return Vec::new();
    };
    let mut base = String::new();
    let mut values = Vec::new();
    for record in &records {
        if let Some(name) = record["bn"].as_str() {
            base = name.to_string();
        }
        let name = format!("{base}{}", record["n"].as_str().unwrap_or_default());
        let value = ["v", "vs", "vb", "vd"]
            .iter()
            .map(|label| &record[*label])
            .find(|value| !value.is_null())
            .map(|value| match value {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        values.push((name, value));
    }
    values
}

/// A Discover answer's links, such as </3/0/1>;pmin=2: each path and what
/// follows it.
fn discovered_links(payload: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(payload)
        .split(',')
        .filter_map(|link| {
            let link = link.trim();
            let (target, attributes) = link.strip_prefix('<')?.split_once('>')?;
            Some(json!({
                "path": target,
                "attributes": attributes.trim_start_matches(';'),
            }))
        })
        .collect()
}

fn format_number(word: &str) -> Option<u32> {
    match word.to_lowercase().as_str() {
        "tlv" => Some(TLV),
        "senml" | "json" | "senml+json" => Some(SENML_JSON),
        "senml-cbor" | "senml+cbor" | "senmlcbor" => Some(SENML_CBOR),
        "text" | "plain" => Some(TEXT),
        "opaque" => Some(OPAQUE),
        "cbor" => Some(CBOR),
        "link" | "links" => Some(LINKS),
        other => other.parse().ok(),
    }
}

// ----- A CoAP endpoint that sends requests and answers them -----

/// A confirmable message sent, until its ACK comes.
struct Pending {
    message: Message,
    target: Target,
    shown: PeerId,
    sent: Instant,
    timeout: Duration,
    tries: u32,
}

/// What both ends share: message ids, tokens, and sending again.
struct Endpoint {
    counter: Counter,
    next_id: u16,
    pending: Vec<Pending>,
    /// Answers sent lately, by peer and id, sent again for a request that comes again.
    answered: Vec<(PeerId, u16, Vec<u8>)>,
}

impl Endpoint {
    fn new() -> Self {
        let mut counter = Counter::new();
        let next_id = counter.next() as u16;
        Self {
            counter,
            next_id,
            pending: Vec::new(),
            answered: Vec::new(),
        }
    }

    fn id(&mut self) -> u16 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn token(&mut self) -> Vec<u8> {
        self.counter.next().to_be_bytes()[..4].to_vec()
    }

    /// Sends a request as CON, kept until its ACK comes.
    fn request(&mut self, target: Target, shown: PeerId, message: Message, io: &mut Io) {
        io.went(shown, &coap::describe(&message));
        self.request_quietly(target, shown, message, io);
    }

    /// Sends a request as `request` does, without a line for it: for the
    /// blocks of a firmware upload, whose progress is shown instead.
    fn request_quietly(&mut self, target: Target, shown: PeerId, message: Message, io: &mut Io) {
        io.send(target, message.encode());
        let timeout = ACK_TIMEOUT + Duration::from_millis(self.counter.next() % 1000);
        self.pending.push(Pending {
            message,
            target,
            shown,
            sent: Instant::now(),
            timeout,
            tries: 0,
        });
    }

    /// Answers a request: piggybacked on the ACK for CON, as NON for NON.
    #[allow(clippy::too_many_arguments)]
    fn answer(
        &mut self,
        peer: PeerId,
        request: &Message,
        code: u8,
        format: Option<u32>,
        payload: Vec<u8>,
        extra: Vec<(u16, Vec<u8>)>,
        io: &mut Io,
    ) {
        let mut options = extra;
        if let Some(format) = format {
            options.push((CONTENT_FORMAT, uint(format)));
        }
        let reply = Message {
            kind: if request.kind == CON { ACK } else { NON },
            code,
            id: if request.kind == CON {
                request.id
            } else {
                self.id()
            },
            token: request.token.clone(),
            options,
            payload,
        };
        // The view hears each request answered: of a block-wise write, the
        // first block and the last.
        let middle_block = request
            .uint_option(BLOCK1)
            .map(block)
            .is_some_and(|(number, more, _)| number > 0 && more);
        if !middle_block {
            let plain = request.plain_path();
            let path = parse_path(&plain).unwrap_or_default();
            let format = request.uint_option(CONTENT_FORMAT);
            let payload = match format {
                Some(OPAQUE) => format!("{} bytes", request.payload.len()),
                _ => payload_text(format, &path, &request.payload),
            };
            io.report(json!({
                "type": "heard",
                "peer": peer,
                "method": coap::code_name(request.code),
                "path": plain,
                "query": query(request),
                "observe": request.uint_option(OBSERVE),
                "format": format.map(format_short),
                "payload": payload,
                "code": coap::code_name(code),
                "class": code >> 5,
            }));
        }
        io.went(peer, &coap::describe(&reply));
        let bytes = reply.encode();
        if request.kind == CON {
            self.answered.push((peer, request.id, bytes.clone()));
            if self.answered.len() > 32 {
                self.answered.remove(0);
            }
        }
        io.send(Target::Peer(peer), bytes);
    }

    /// Whether a request came again; its answer goes again if so.
    fn again(&self, peer: PeerId, message: &Message, io: &mut Io) -> bool {
        if message.kind != CON {
            return false;
        }
        match self
            .answered
            .iter()
            .find(|(from, id, _)| *from == peer && *id == message.id)
        {
            Some((_, _, bytes)) => {
                io.send(Target::Peer(peer), bytes.clone());
                true
            }
            None => false,
        }
    }

    /// Takes an ACK or RST for what was sent; true when the message was one.
    fn settle(&mut self, message: &Message) -> bool {
        if message.kind == ACK || message.kind == RST {
            self.pending
                .retain(|pending| pending.message.id != message.id);
        }
        message.kind == RST || (message.kind == ACK && message.code == 0)
    }

    /// Sends again what waited too long for its ACK; gives back the tokens
    /// of the requests given up.
    fn tick(&mut self, now: Instant, io: &mut Io) -> Vec<Vec<u8>> {
        let mut again = Vec::new();
        let mut given_up = Vec::new();
        self.pending.retain_mut(|pending| {
            if now.duration_since(pending.sent) < pending.timeout {
                return true;
            }
            if pending.tries >= MAX_RETRANSMIT {
                io.bad(&format!(
                    "No answer to {}: given up.",
                    coap::describe(&pending.message)
                ));
                given_up.push(pending.message.token.clone());
                return false;
            }
            pending.tries += 1;
            pending.sent = now;
            pending.timeout *= 2;
            again.push((
                pending.target,
                pending.shown,
                pending.message.encode(),
                pending.tries,
            ));
            true
        });
        for (target, shown, bytes, tries) in again {
            io.went(shown, &format!("(sent again, try {})", tries + 1));
            io.send(target, bytes);
        }
        given_up
    }
}

// ----- The server -----

/// A device registered with the server.
struct Registration {
    endpoint: String,
    peer: PeerId,
    lifetime: u64,
    objects: String,
    binding: String,
    version: String,
    updated: Instant,
}

/// What a request the server sent was, to show its answer.
struct Asked {
    /// The device's location, its key in `clients`.
    location: String,
    method: u8,
    path: Vec<u16>,
    observe: bool,
    sent: Instant,
}

/// An LwM2M server tab's settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServerOptions {
    /// The format reads ask for: "tlv", "senml" or "text".
    pub format: String,
    /// As a bootstrap server too: the LwM2M server's address it gives the
    /// devices that ask, such as coap://192.168.1.10:5683; empty for none.
    pub bootstrap: String,
    /// For a coaps:// address: the PSK it gives with it, as hex digits or
    /// text in quotes. A device's PSK identity is its name.
    pub bootstrap_key: String,
}

/// One step of a bootstrap: a request's method, path, format and payload.
type Step = (u8, String, Option<u32>, Vec<u8>);

/// What waits for the answer to a request the server sent.
enum Job {
    /// The rest of a device's bootstrap, sent one at a time: Bootstrap-Finish last.
    Bootstrap {
        peer: PeerId,
        endpoint: String,
        rest: Vec<Step>,
    },
    /// A firmware image going to /5/0/0, a block at a time.
    Upload {
        client: String,
        image: Arc<Vec<u8>>,
        number: u32,
        /// The share sent, in percent, last shown.
        shown: usize,
    },
}

/// Takes registrations and manages the devices registered; gives devices
/// their server's address as a bootstrap server, when it is one.
pub struct Server {
    endpoint: Endpoint,
    accept: u32,
    clients: BTreeMap<String, Registration>,
    asked: HashMap<Vec<u8>, Asked>,
    next_location: u32,
    bootstrap: String,
    bootstrap_key: String,
    /// By the token of the request whose answer each waits for.
    jobs: HashMap<Vec<u8>, Job>,
    /// Whether the devices registered changed since the view was told, as
    /// it is on the next tick.
    changed: bool,
}

impl Server {
    pub fn new(options: ServerOptions) -> Self {
        Self {
            endpoint: Endpoint::new(),
            accept: format_number(&options.format).unwrap_or(TLV),
            clients: BTreeMap::new(),
            asked: HashMap::new(),
            next_location: 0,
            bootstrap: options.bootstrap.trim().to_string(),
            bootstrap_key: options.bootstrap_key,
            jobs: HashMap::new(),
            changed: true,
        }
    }

    /// Tells the view the devices registered, each with its objects and the
    /// seconds of its lifetime left.
    fn report_devices(&mut self, io: &mut Io) {
        self.changed = false;
        let devices: Vec<serde_json::Value> = self
            .clients
            .iter()
            .map(|(location, registration)| {
                let objects: Vec<String> = registration
                    .objects
                    .split(',')
                    .filter_map(|link| {
                        let link = link.trim();
                        Some(link.strip_prefix('<')?.split_once('>')?.0.to_string())
                    })
                    .collect();
                json!({
                    "location": location,
                    "endpoint": registration.endpoint,
                    "peer": registration.peer,
                    "version": registration.version,
                    "binding": registration.binding,
                    "lifetime": registration.lifetime,
                    "left": registration
                        .lifetime
                        .saturating_sub(registration.updated.elapsed().as_secs()),
                    "objects": objects,
                })
            })
            .collect();
        io.report(json!({ "type": "devices", "devices": devices }));
    }

    /// Tells the view how a firmware upload goes.
    fn report_firmware(
        &self,
        client: &str,
        sent: usize,
        total: usize,
        problem: Option<String>,
        io: &mut Io,
    ) {
        io.report(json!({
            "type": "firmware",
            "location": client,
            "endpoint": self.clients.get(client).map(|registration| registration.endpoint.clone()),
            "sent": sent,
            "total": total,
            "done": problem.is_none() && sent >= total,
            "problem": problem,
        }));
    }

    /// A device asking for bootstrap (POST /bs): its servers go, the one set
    /// in the tab's settings comes, then Bootstrap-Finish.
    fn bootstrap(&mut self, peer: PeerId, request: &Message, io: &mut Io) {
        if self.bootstrap.is_empty() {
            io.note("A device asked for bootstrap: give the LwM2M server's address in the tab's settings to be its bootstrap server.");
            self.endpoint
                .answer(peer, request, NOT_FOUND, None, Vec::new(), Vec::new(), io);
            return;
        }
        let Some(endpoint) = query(request).get("ep").cloned() else {
            self.endpoint
                .answer(peer, request, BAD_REQUEST, None, Vec::new(), Vec::new(), io);
            return;
        };
        let uri = self.bootstrap.clone();
        let secure = uri.to_ascii_lowercase().starts_with("coaps://");
        let key = if secure {
            match crate::net::psk_key(&self.bootstrap_key) {
                Ok(key) => Some(key),
                Err(problem) => {
                    io.bad(&format!("The PSK to give with {uri}: {problem}"));
                    self.endpoint.answer(
                        peer,
                        request,
                        coap::code(5, 0),
                        None,
                        Vec::new(),
                        Vec::new(),
                        io,
                    );
                    return;
                }
            }
        } else {
            None
        };
        self.endpoint
            .answer(peer, request, CHANGED, None, Vec::new(), Vec::new(), io);
        // The Security instance for the server: its address, not a bootstrap
        // server, PSK or no security, and Short Server ID 1.
        let mut security = vec![
            tlv_encode(3, 0, uri.as_bytes()),
            tlv_encode(3, 1, &[0]),
            tlv_encode(3, 2, &[if secure { 0 } else { 3 }]),
        ];
        if let Some(key) = key {
            security.push(tlv_encode(3, 3, endpoint.as_bytes()));
            security.push(tlv_encode(3, 5, &key));
        }
        security.push(tlv_encode(3, 10, &[1]));
        // The Server instance: Short Server ID 1, its lifetime and binding.
        let server = [
            tlv_encode(3, 0, &[1]),
            tlv_encode(3, 1, &Value::Int(300).tlv_bytes()),
            tlv_encode(3, 7, b"U"),
        ]
        .concat();
        let steps = vec![
            (DELETE, "/".to_string(), None, Vec::new()),
            (PUT, "/0/1".to_string(), Some(TLV), security.concat()),
            (PUT, "/1/0".to_string(), Some(TLV), server),
            (POST, "/bs".to_string(), None, Vec::new()),
        ];
        io.note(&format!(
            "{endpoint} asked for bootstrap: it is given {uri}."
        ));
        self.next_step(peer, endpoint, steps, io);
    }

    /// Sends a bootstrap's next step, or says it ended.
    fn next_step(&mut self, peer: PeerId, endpoint: String, mut steps: Vec<Step>, io: &mut Io) {
        if steps.is_empty() {
            io.note(&format!(
                "{endpoint} is bootstrapped: it registers at its server next."
            ));
            return;
        }
        let (method, path, format, payload) = steps.remove(0);
        let token = self.endpoint.token();
        let mut options = path_options(&path);
        if let Some(format) = format {
            options.push((CONTENT_FORMAT, uint(format)));
        }
        let message = Message {
            kind: CON,
            code: method,
            id: self.endpoint.id(),
            token: token.clone(),
            options,
            payload,
        };
        self.jobs.insert(
            token,
            Job::Bootstrap {
                peer,
                endpoint,
                rest: steps,
            },
        );
        self.endpoint.request(Target::Peer(peer), peer, message, io);
    }

    /// Sends one block of a firmware image to /5/0/0.
    fn send_block(
        &mut self,
        client: String,
        image: Arc<Vec<u8>>,
        number: u32,
        shown: usize,
        io: &mut Io,
    ) {
        let start = number as usize * BLOCK_SIZE;
        let Some(peer) = self
            .clients
            .get(&client)
            .map(|registration| registration.peer)
        else {
            io.bad("The device is gone: the firmware upload stopped.");
            self.report_firmware(
                &client,
                start,
                image.len(),
                Some("The device is gone.".into()),
                io,
            );
            return;
        };
        let end = (start + BLOCK_SIZE).min(image.len());
        let more = end < image.len();
        let token = self.endpoint.token();
        let mut options = path_options("/5/0/0");
        options.push((CONTENT_FORMAT, uint(OPAQUE)));
        options.push((BLOCK1, uint(block_value(number, more, BLOCK_SIZE))));
        let message = Message {
            kind: CON,
            code: PUT,
            id: self.endpoint.id(),
            token: token.clone(),
            options,
            payload: image[start..end].to_vec(),
        };
        self.jobs.insert(
            token,
            Job::Upload {
                client,
                image,
                number,
                shown,
            },
        );
        self.endpoint
            .request_quietly(Target::Peer(peer), peer, message, io);
    }

    /// The answer to a bootstrap's step or an upload's block: the next one goes.
    fn job_answered(&mut self, peer: PeerId, job: Job, answer: &Message, io: &mut Io) {
        let failed = answer.code >= 0x80;
        match job {
            Job::Bootstrap {
                peer: device,
                endpoint,
                rest,
            } => {
                io.came(peer, &coap::describe(answer));
                if failed {
                    io.bad(&format!(
                        "{endpoint}'s bootstrap stopped: it answered {}.",
                        coap::code_name(answer.code)
                    ));
                } else {
                    self.next_step(device, endpoint, rest, io);
                }
            }
            Job::Upload {
                client,
                image,
                number,
                shown,
            } => {
                let total = image.len();
                let sent = ((number as usize + 1) * BLOCK_SIZE).min(total);
                let name = self
                    .clients
                    .get(&client)
                    .map(|registration| registration.endpoint.clone())
                    .unwrap_or_default();
                if failed {
                    io.came(peer, &coap::describe(answer));
                    io.bad(&format!(
                        "The firmware upload stopped at block {number}: {name} answered {}.",
                        coap::code_name(answer.code)
                    ));
                    self.report_firmware(
                        &client,
                        number as usize * BLOCK_SIZE,
                        total,
                        Some(format!("{name} answered {}.", coap::code_name(answer.code))),
                        io,
                    );
                } else if sent < total {
                    let percent = sent * 100 / total;
                    // The view hears each percent; the lines, each tenth.
                    if percent != number as usize * BLOCK_SIZE * 100 / total {
                        self.report_firmware(&client, sent, total, None, io);
                    }
                    let shown = if percent / 10 > shown / 10 {
                        io.note(&format!(
                            "Firmware: {percent}% sent, {sent} of {total} bytes."
                        ));
                        percent
                    } else {
                        shown
                    };
                    self.send_block(client, image, number + 1, shown, io);
                } else {
                    io.came(peer, &coap::describe(answer));
                    io.note(&format!(
                        "Firmware: all {total} bytes are on {name}. Execute /5/0/2 on it to update."
                    ));
                    self.report_firmware(&client, total, total, None, io);
                }
            }
        }
    }

    /// A registered device by its name, its location or its number in `clients`.
    fn find(&self, word: &str) -> Option<String> {
        if self.clients.contains_key(word) {
            return Some(word.to_string());
        }
        if let Some((location, _)) = self
            .clients
            .iter()
            .find(|(_, registration)| registration.endpoint == word)
        {
            return Some(location.clone());
        }
        word.parse::<usize>()
            .ok()
            .and_then(|index| self.clients.keys().nth(index.saturating_sub(1)).cloned())
    }

    fn register(&mut self, peer: PeerId, request: &Message, io: &mut Io) {
        let query: BTreeMap<String, String> = request
            .options
            .iter()
            .filter(|(number, _)| *number == URI_QUERY)
            .filter_map(|(_, value)| {
                let text = String::from_utf8_lossy(value).into_owned();
                text.split_once('=')
                    .map(|(name, value)| (name.to_string(), value.to_string()))
            })
            .collect();
        let Some(endpoint) = query.get("ep").cloned() else {
            self.endpoint
                .answer(peer, request, BAD_REQUEST, None, Vec::new(), Vec::new(), io);
            return;
        };
        // The same device again: its old registration goes.
        self.clients
            .retain(|_, registration| registration.endpoint != endpoint);
        self.next_location += 1;
        let location = format!("{}", self.next_location);
        let objects = String::from_utf8_lossy(&request.payload).into_owned();
        let registration = Registration {
            endpoint: endpoint.clone(),
            peer,
            lifetime: query
                .get("lt")
                .and_then(|lifetime| lifetime.parse().ok())
                .unwrap_or(86400),
            objects: objects.clone(),
            binding: query.get("b").cloned().unwrap_or_else(|| "U".into()),
            version: query.get("lwm2m").cloned().unwrap_or_else(|| "1.0".into()),
            updated: Instant::now(),
        };
        io.note(&format!(
            "{endpoint} registered as /rd/{location}: LwM2M {}, lifetime {} s, binding {}, objects {objects}",
            registration.version, registration.lifetime, registration.binding
        ));
        self.clients.insert(location.clone(), registration);
        self.changed = true;
        let extra = vec![(8, b"rd".to_vec()), (8, location.into_bytes())];
        self.endpoint
            .answer(peer, request, CREATED, None, Vec::new(), extra, io);
    }

    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        client: &str,
        method: u8,
        path: &[u16],
        options: Vec<(u16, Vec<u8>)>,
        payload: Vec<u8>,
        observe: bool,
        io: &mut Io,
    ) {
        let Some((peer, endpoint)) = self
            .clients
            .get(client)
            .map(|registration| (registration.peer, registration.endpoint.clone()))
        else {
            return;
        };
        let token = self.endpoint.token();
        let mut all = path_options(&path_text(path));
        all.extend(options);
        let message = Message {
            kind: CON,
            code: method,
            id: self.endpoint.id(),
            token: token.clone(),
            options: all,
            payload,
        };
        io.report(json!({
            "type": "asked",
            "token": hex(&token),
            "location": client,
            "endpoint": endpoint,
            "method": coap::code_name(method),
            "path": path_text(path),
            "observe": message.uint_option(OBSERVE),
            "accept": message.uint_option(ACCEPT).map(format_short),
            "format": message.uint_option(CONTENT_FORMAT).map(format_short),
            "query": message
                .options
                .iter()
                .filter(|(number, _)| *number == URI_QUERY)
                .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
                .collect::<Vec<_>>()
                .join("&"),
            "payload": String::from_utf8_lossy(&message.payload),
        }));
        self.asked.insert(
            token,
            Asked {
                location: client.to_string(),
                method,
                path: path.to_vec(),
                observe,
                sent: Instant::now(),
            },
        );
        self.endpoint.request(Target::Peer(peer), peer, message, io);
    }
}

const SERVER_HELP: &str = "clients                          the devices registered, numbered from 1
read <client> <path> [-f tlv]   read, such as read 1 /3/0; -f tlv, senml or text
write <client> <path> <value>   write one resource, such as write 1 /3311/0/5850 1
execute <client> <path> [args]  execute, such as execute 1 /3/0/4 to reboot
discover <client> <path>        the resources and attributes there
observe <client> <path>         get each change, such as observe 1 /3303/0/5700
cancel <client> <path>          stop observing
attributes <client> <path> <q>  write attributes, such as attributes 1 /3303/0/5700 pmin=2&pmax=10
firmware <client> <file>        push a firmware image to /5/0/0, a block at a time; then execute <client> /5/0/2
firmware <client> uri <uri>     have the device fetch it from <uri> (/5/0/1)
A client is its number, its name, or its location. A file without a folder is in Downloads.";

impl Engine for Server {
    fn help(&self) -> &'static str {
        SERVER_HELP
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let message = match Message::decode(bytes) {
            Ok(message) => message,
            Err(problem) => {
                io.bad(&format!("Not CoAP: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        let format = message.uint_option(CONTENT_FORMAT);
        // An answer, or a notification, to what the server asked.
        if message.code >= 0x40 || message.code == 0 {
            if self.endpoint.settle(&message) {
                io.came(peer, &coap::describe(&message));
                return;
            }
            // A bootstrap's step or an upload's block waits for this answer.
            if let Some(job) = self.jobs.remove(&message.token) {
                if message.kind == CON {
                    let ack = Message {
                        kind: ACK,
                        code: 0,
                        id: message.id,
                        ..Message::default()
                    };
                    io.send(Target::Peer(peer), ack.encode());
                }
                self.job_answered(peer, job, &message, io);
                return;
            }
            let path = self
                .asked
                .get(&message.token)
                .map(|asked| asked.path.clone())
                .unwrap_or_default();
            let mut line = coap::describe(&message);
            if let Some(cut) = line.find(": ") {
                line.truncate(cut);
            }
            let body = payload_text(format, &path, &message.payload);
            if let Some(asked) = self.asked.get(&message.token) {
                let values: Vec<serde_json::Value> = answer_values(format, &path, &message.payload)
                    .into_iter()
                    .map(|(path, value)| json!({ "path": path, "value": value }))
                    .collect();
                let links = if format == Some(LINKS) {
                    discovered_links(&message.payload)
                } else {
                    Vec::new()
                };
                io.report(json!({
                    "type": "answer",
                    "token": hex(&message.token),
                    "location": asked.location,
                    "method": coap::code_name(asked.method),
                    "path": path_text(&path),
                    "code": coap::code_name(message.code),
                    "class": message.code >> 5,
                    "format": format.map(format_short),
                    "text": body,
                    "values": values,
                    "links": links,
                    "observe": message.uint_option(OBSERVE),
                    "ms": asked.sent.elapsed().as_secs_f64() * 1000.0,
                }));
            }
            io.came(
                peer,
                &if body.is_empty() {
                    line
                } else {
                    format!("{line}\n{body}")
                },
            );
            if message.kind == CON {
                let ack = Message {
                    kind: ACK,
                    code: 0,
                    id: message.id,
                    ..Message::default()
                };
                io.send(Target::Peer(peer), ack.encode());
            }
            let observing = self
                .asked
                .get(&message.token)
                .is_some_and(|asked| asked.observe)
                && message.option(OBSERVE).is_some();
            if !observing {
                self.asked.remove(&message.token);
            }
            return;
        }
        io.came(peer, &coap::describe(&message));
        if self.endpoint.again(peer, &message, io) {
            return;
        }
        let path = message.plain_path();
        match (message.code, path.as_str()) {
            (POST, "/rd") => self.register(peer, &message, io),
            (POST, "/bs") => self.bootstrap(peer, &message, io),
            (POST, location) if location.starts_with("/rd/") => {
                let key = location.trim_start_matches("/rd/").to_string();
                match self.clients.get_mut(&key) {
                    Some(registration) => {
                        registration.updated = Instant::now();
                        registration.peer = peer;
                        // An update may bring a new lifetime, binding or objects.
                        let query = query(&message);
                        if let Some(lifetime) = query.get("lt").and_then(|lt| lt.parse().ok()) {
                            registration.lifetime = lifetime;
                        }
                        if let Some(binding) = query.get("b") {
                            registration.binding = binding.clone();
                        }
                        if !message.payload.is_empty() {
                            registration.objects =
                                String::from_utf8_lossy(&message.payload).into_owned();
                        }
                        self.changed = true;
                        let endpoint = registration.endpoint.clone();
                        io.note(&format!("{endpoint} updated its registration."));
                        self.endpoint.answer(
                            peer,
                            &message,
                            CHANGED,
                            None,
                            Vec::new(),
                            Vec::new(),
                            io,
                        );
                    }
                    None => self.endpoint.answer(
                        peer,
                        &message,
                        NOT_FOUND,
                        None,
                        Vec::new(),
                        Vec::new(),
                        io,
                    ),
                }
            }
            (DELETE, location) if location.starts_with("/rd/") => {
                let key = location.trim_start_matches("/rd/").to_string();
                match self.clients.remove(&key) {
                    Some(registration) => {
                        self.changed = true;
                        io.note(&format!("{} deregistered.", registration.endpoint));
                        self.endpoint.answer(
                            peer,
                            &message,
                            DELETED,
                            None,
                            Vec::new(),
                            Vec::new(),
                            io,
                        );
                    }
                    None => self.endpoint.answer(
                        peer,
                        &message,
                        NOT_FOUND,
                        None,
                        Vec::new(),
                        Vec::new(),
                        io,
                    ),
                }
            }
            _ => self
                .endpoint
                .answer(peer, &message, NOT_FOUND, None, Vec::new(), Vec::new(), io),
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            let command = words.next().unwrap_or_default().to_lowercase();
            if command == "clients" {
                if self.clients.is_empty() {
                    io.note("No device is registered yet.");
                }
                let lines: Vec<String> = self
                    .clients
                    .iter()
                    .enumerate()
                    .map(|(index, (location, registration))| {
                        let left = registration.lifetime.saturating_sub(registration.updated.elapsed().as_secs());
                        format!(
                            "{}: {} at /rd/{location}, LwM2M {}, {left} s of its lifetime left, objects {}",
                            index + 1,
                            registration.endpoint,
                            registration.version,
                            registration.objects
                        )
                    })
                    .collect();
                for line in lines {
                    io.note(&line);
                }
                return Ok(());
            }
            let who = words.need("the client: its number, as clients shows it")?;
            let client = self
                .find(&who)
                .ok_or(format!("No device {who} is registered."))?;
            if command == "firmware" || command == "fw" {
                let what = words.need("the image's file, or uri and an address")?;
                if what.eq_ignore_ascii_case("uri") {
                    let uri = words.rest_text();
                    self.send(
                        &client,
                        PUT,
                        &[5, 0, 1],
                        vec![(CONTENT_FORMAT, uint(TEXT))],
                        uri.into_bytes(),
                        false,
                        io,
                    );
                    return Ok(());
                }
                let name = format!("{what} {}", words.rest_text());
                let path = file_path(&name);
                let image = std::fs::read(&path)
                    .map_err(|error| format!("Could not read {}: {error}", path.display()))?;
                if image.is_empty() {
                    return Err(format!("{} is empty.", path.display()));
                }
                let version = mcuboot_version(&image)
                    .map(|version| format!(", version {version} in its MCUboot header"))
                    .unwrap_or_default();
                io.note(&format!(
                    "Firmware: sending {} bytes of {}{version}, in blocks of {BLOCK_SIZE}.",
                    image.len(),
                    path.display()
                ));
                self.report_firmware(&client, 0, image.len(), None, io);
                self.send_block(client, Arc::new(image), 0, 0, io);
                return Ok(());
            }
            let path = parse_path(&words.need("the path, such as /3/0")?)?;
            match command.as_str() {
                "read" => {
                    let mut accept = self.accept;
                    // -f tlv, or -ftlv.
                    if let Some(word) = words.next() {
                        let value = match word.strip_prefix("-f") {
                            Some("") => words.next().unwrap_or_default(),
                            Some(value) => value.to_string(),
                            None => {
                                return Err(format!(
                                    "{word} is not a flag here: -f tlv, senml or text."
                                ));
                            }
                        };
                        accept = format_number(&value)
                            .ok_or(format!("{value} is not a format: tlv, senml or text."))?;
                    }
                    // One resource reads well as text.
                    let accept = if path.len() >= 3 && accept == TLV && self.accept == TLV {
                        TEXT
                    } else {
                        accept
                    };
                    self.send(
                        &client,
                        GET,
                        &path,
                        vec![(ACCEPT, uint(accept))],
                        Vec::new(),
                        false,
                        io,
                    );
                }
                "write" => {
                    if path.len() < 3 {
                        return Err("write takes one resource's path, such as /3/0/13.".into());
                    }
                    let value = words.rest_text();
                    self.send(
                        &client,
                        PUT,
                        &path,
                        vec![(CONTENT_FORMAT, uint(TEXT))],
                        value.into_bytes(),
                        false,
                        io,
                    );
                }
                "execute" | "exec" => {
                    let arguments = words.rest_text();
                    self.send(
                        &client,
                        POST,
                        &path,
                        Vec::new(),
                        arguments.into_bytes(),
                        false,
                        io,
                    );
                }
                "discover" => self.send(
                    &client,
                    GET,
                    &path,
                    vec![(ACCEPT, uint(LINKS))],
                    Vec::new(),
                    false,
                    io,
                ),
                "observe" => {
                    let accept = if path.len() >= 3 { TEXT } else { self.accept };
                    self.send(
                        &client,
                        GET,
                        &path,
                        vec![(OBSERVE, uint(0)), (ACCEPT, uint(accept))],
                        Vec::new(),
                        true,
                        io,
                    );
                }
                "cancel" => {
                    self.asked.retain(|_, asked| {
                        !(asked.observe && asked.path == path && asked.location == client)
                    });
                    self.send(
                        &client,
                        GET,
                        &path,
                        vec![(OBSERVE, uint(1))],
                        Vec::new(),
                        false,
                        io,
                    );
                }
                "attributes" | "attr" => {
                    let query = words.rest_text();
                    let options = query
                        .split('&')
                        .filter(|part| !part.is_empty())
                        .map(|part| (URI_QUERY, part.as_bytes().to_vec()))
                        .collect();
                    self.send(&client, PUT, &path, options, Vec::new(), false, io);
                }
                "delete" => self.send(&client, DELETE, &path, Vec::new(), Vec::new(), false, io),
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

    fn tick(&mut self, now: Instant, io: &mut Io) {
        for token in self.endpoint.tick(now, io) {
            if let Some(Job::Upload {
                client,
                image,
                number,
                ..
            }) = self.jobs.remove(&token)
            {
                self.report_firmware(
                    &client,
                    number as usize * BLOCK_SIZE,
                    image.len(),
                    Some("The device did not answer.".into()),
                    io,
                );
            }
            if self.asked.remove(&token).is_some() {
                io.report(json!({ "type": "timeout", "token": hex(&token) }));
            }
        }
        // A device that did not update within its lifetime is gone.
        let late: Vec<String> = self
            .clients
            .iter()
            .filter(|(_, registration)| {
                now.duration_since(registration.updated).as_secs() > registration.lifetime
            })
            .map(|(location, _)| location.clone())
            .collect();
        for location in late {
            if let Some(registration) = self.clients.remove(&location) {
                io.note(&format!(
                    "{} did not update within its lifetime: it is gone.",
                    registration.endpoint
                ));
                self.changed = true;
            }
        }
        if self.changed {
            self.report_devices(io);
        }
    }
}

// ----- The client -----

/// An LwM2M client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// The name it registers with.
    pub endpoint: String,
    /// How long its registration lasts, in seconds; it updates before then.
    pub lifetime: u32,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    /// Asks the server it is set to for bootstrap first (POST /bs), and
    /// registers where it is told.
    pub bootstrap: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            endpoint: "netnima-device".into(),
            lifetime: 300,
            manufacturer: "netNIMA".into(),
            model: "Simulated board".into(),
            serial: "0001".into(),
            firmware: "1.0.0".into(),
            bootstrap: false,
        }
    }
}

/// A device that registers with an LwM2M server and answers it.
pub struct Client {
    options: ClientOptions,
    endpoint: Endpoint,
    /// Each resource's value, by object, instance and resource.
    resources: BTreeMap<(u16, u16, u16), Value>,
    /// Where its registration is, once made: "/rd/5".
    location: Option<String>,
    register_token: Option<Vec<u8>>,
    next_update: Option<Instant>,
    observers: Vec<(PeerId, Vec<u8>, Vec<u16>, u32)>,
    /// When the temperature changes next.
    next_reading: Instant,
    sequence: u32,
    server: PeerId,
    /// The firmware coming to /5/0/0, and the number of the block it waits for.
    package: Vec<u8>,
    package_next: u32,
    /// When the firmware update going on ends.
    updating_until: Option<Instant>,
    /// Bootstrap asked for, and not finished yet.
    bootstrapping: bool,
    bootstrapped: bool,
    bootstrap_token: Option<Vec<u8>>,
    /// What the view was told last, to tell it again when it differs.
    reported: Option<serde_json::Value>,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        let mut resources = BTreeMap::new();
        resources.insert((1, 0, 0), Value::Int(1));
        resources.insert((1, 0, 1), Value::Int(i64::from(options.lifetime)));
        resources.insert((1, 0, 7), Value::Text("U".into()));
        resources.insert((3, 0, 0), Value::Text(options.manufacturer.clone()));
        resources.insert((3, 0, 1), Value::Text(options.model.clone()));
        resources.insert((3, 0, 2), Value::Text(options.serial.clone()));
        resources.insert((3, 0, 3), Value::Text(options.firmware.clone()));
        resources.insert((3, 0, 9), Value::Int(95));
        resources.insert((3, 0, 11), Value::Int(0));
        resources.insert((3, 0, 13), Value::Int(chrono::Utc::now().timestamp()));
        resources.insert((3, 0, 16), Value::Text("U".into()));
        // Firmware Update: idle, nothing tried yet, firmware pushed to it.
        resources.insert((5, 0, 1), Value::Text(String::new()));
        resources.insert((5, 0, 3), Value::Int(IDLE));
        resources.insert((5, 0, 5), Value::Int(0));
        resources.insert((5, 0, 6), Value::Text(String::new()));
        resources.insert((5, 0, 7), Value::Text(String::new()));
        resources.insert((5, 0, 9), Value::Int(1));
        resources.insert((3303, 0, 5700), Value::Float(21.5));
        resources.insert((3303, 0, 5701), Value::Text("Cel".into()));
        resources.insert((3311, 0, 5850), Value::Bool(false));
        resources.insert((3311, 0, 5851), Value::Int(100));
        Self {
            options,
            endpoint: Endpoint::new(),
            resources,
            location: None,
            register_token: None,
            next_update: Some(Instant::now()),
            observers: Vec::new(),
            next_reading: Instant::now() + Duration::from_secs(5),
            sequence: 2,
            server: 0,
            package: Vec::new(),
            package_next: 0,
            updating_until: None,
            bootstrapping: false,
            bootstrapped: false,
            bootstrap_token: None,
            reported: None,
        }
    }

    /// What the view shows: whether it is registered, and its resources with
    /// the paths the server observes.
    fn snapshot(&self) -> serde_json::Value {
        let resources: Vec<serde_json::Value> = self
            .resources
            .iter()
            .map(|((object, instance, resource), value)| {
                json!({
                    "path": format!("/{object}/{instance}/{resource}"),
                    "value": value.to_text(),
                    "kind": match value {
                        Value::Text(_) => "text",
                        Value::Int(_) => "integer",
                        Value::Float(_) => "float",
                        Value::Bool(_) => "boolean",
                        Value::Opaque(_) => "opaque",
                    },
                })
            })
            .collect();
        let mut observed: Vec<String> = self
            .observers
            .iter()
            .map(|(_, _, path, _)| path_text(path))
            .collect();
        observed.sort();
        observed.dedup();
        json!({
            "type": "device",
            "endpoint": self.options.endpoint,
            "lifetime": self.options.lifetime,
            "location": self.location,
            "registering": self.register_token.is_some(),
            "bootstrapping": self.bootstrapping,
            "bootstrapped": self.bootstrapped,
            "resources": resources,
            "observed": observed,
        })
    }

    /// Tells the view the device's state when it changed since it was told.
    fn report_if_changed(&mut self, io: &mut Io) {
        let now = self.snapshot();
        if self.reported.as_ref() != Some(&now) {
            io.report(now.clone());
            self.reported = Some(now);
        }
    }

    fn objects(&self) -> String {
        // The Security object is never listed (LwM2M 1.1, 6.2.1).
        let mut instances: Vec<(u16, u16)> = self
            .resources
            .keys()
            .filter(|(object, _, _)| *object != 0)
            .map(|(object, instance, _)| (*object, *instance))
            .collect();
        instances.dedup();
        instances
            .iter()
            .map(|(object, instance)| format!("</{object}/{instance}>"))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn register(&mut self, io: &mut Io) {
        let token = self.endpoint.token();
        let mut options = path_options(&format!(
            "/rd?ep={}&lt={}&lwm2m=1.1&b=U",
            self.options.endpoint, self.options.lifetime
        ));
        options.push((CONTENT_FORMAT, uint(LINKS)));
        let message = Message {
            kind: CON,
            code: POST,
            id: self.endpoint.id(),
            token: token.clone(),
            options,
            payload: self.objects().into_bytes(),
        };
        self.register_token = Some(token);
        self.endpoint.request(Target::Default, 0, message, io);
    }

    /// Asks the server it is set to for bootstrap: POST /bs?ep=name.
    fn ask_bootstrap(&mut self, io: &mut Io) {
        self.bootstrapping = true;
        let token = self.endpoint.token();
        let message = Message {
            kind: CON,
            code: POST,
            id: self.endpoint.id(),
            token: token.clone(),
            options: path_options(&format!("/bs?ep={}", self.options.endpoint)),
            payload: Vec::new(),
        };
        self.bootstrap_token = Some(token);
        self.endpoint.request(Target::Default, 0, message, io);
    }

    /// A bootstrap server's Delete or Write, of the Security (0) and Server
    /// (1) objects. A Delete of "/" takes their instances; its sensors stay.
    fn bootstrap_write(&mut self, peer: PeerId, path: &[u16], request: &Message, io: &mut Io) {
        if request.code == DELETE {
            let under = |key: &(u16, u16, u16)| {
                key.0 <= 1
                    && path
                        .iter()
                        .zip([key.0, key.1, key.2])
                        .all(|(want, have)| *want == have)
            };
            self.resources.retain(|key, _| !under(key));
            let what = if path.is_empty() {
                "/".to_string()
            } else {
                path_text(path)
            };
            io.note(&format!("The bootstrap server deleted {what}."));
            self.endpoint
                .answer(peer, request, DELETED, None, Vec::new(), Vec::new(), io);
            return;
        }
        let Ok(items) = tlv_decode(&request.payload) else {
            self.endpoint
                .answer(peer, request, BAD_REQUEST, None, Vec::new(), Vec::new(), io);
            return;
        };
        let object = path[0];
        // (instance, resource, value), from an object's instances, an
        // instance's resources, or one resource.
        let mut written: Vec<(u16, u16, Vec<u8>)> = Vec::new();
        match path.len() {
            1 => {
                for instance in items.iter().filter(|item| item.kind == 0) {
                    for resource in tlv_decode(&instance.value).unwrap_or_default() {
                        written.push((instance.id, resource.id, resource.value));
                    }
                }
            }
            2 => {
                let resources = if items.len() == 1 && items[0].kind == 0 {
                    tlv_decode(&items[0].value).unwrap_or_default()
                } else {
                    items
                };
                for resource in resources {
                    written.push((path[1], resource.id, resource.value));
                }
            }
            _ => {
                for resource in items {
                    written.push((path[1], path[2], resource.value));
                }
            }
        }
        for (instance, resource, bytes) in written {
            let value = decode_tlv_like(&bootstrap_kind(object, resource), &bytes);
            self.resources.insert((object, instance, resource), value);
        }
        io.note(&format!("The bootstrap server wrote {}.", path_text(path)));
        self.endpoint
            .answer(peer, request, CHANGED, None, Vec::new(), Vec::new(), io);
    }

    /// Bootstrap-Finish: it registers at the server it was given.
    fn bootstrap_finish(&mut self, peer: PeerId, request: &Message, io: &mut Io) {
        self.bootstrapping = false;
        self.bootstrapped = true;
        self.endpoint
            .answer(peer, request, CHANGED, None, Vec::new(), Vec::new(), io);
        // The LwM2M server's account: a Security instance that is not the
        // bootstrap server's.
        let account = self
            .resources
            .iter()
            .find_map(|((object, instance, resource), value)| {
                (*object == 0
                    && *resource == 0
                    && self.resources.get(&(0, *instance, 1)) != Some(&Value::Bool(true)))
                .then(|| value.to_text())
            });
        let Some(uri) = account else {
            io.bad("Bootstrap finished without an LwM2M server's address: it does not register.");
            return;
        };
        if let Some(Value::Int(lifetime)) = self
            .resources
            .iter()
            .find(|((object, _, resource), _)| *object == 1 && *resource == 1)
            .map(|(_, value)| value)
            && let Ok(lifetime) = u32::try_from(*lifetime)
        {
            self.options.lifetime = lifetime.max(10);
        }
        io.note(&format!("Bootstrapped: its server is {uri}."));
        match uri_address(&uri) {
            Some(at) => {
                if !io.retarget(at) {
                    io.note("Over DTLS it stays with the server it is connected to: set this address in the tab's settings to register there.");
                }
            }
            None => io.bad(&format!("{uri} is not an address it can reach.")),
        }
        self.location = None;
        self.register(io);
    }

    /// A Package URI written to /5/0/1: empty starts over; an address is not
    /// fetched, as this device takes the firmware pushed to it.
    fn package_uri(&mut self, io: &mut Io) {
        let uri = self
            .resources
            .get(&(5, 0, 1))
            .map(Value::to_text)
            .unwrap_or_default();
        if uri.trim().is_empty() {
            self.package.clear();
            self.package_next = 0;
            self.resources.insert((5, 0, 5), Value::Int(0));
            self.firmware_state(IDLE, io);
            return;
        }
        io.note(&format!(
            "This device takes firmware pushed to /5/0/0 (its delivery method, /5/0/9, is 1: push), so it does not fetch {uri}."
        ));
        // Update Result 9: unsupported protocol.
        self.resources.insert((5, 0, 5), Value::Int(9));
        self.notify((5, 0, 5), io);
    }

    /// Firmware Update's state (/5/0/3), with its observers told.
    fn firmware_state(&mut self, state: i64, io: &mut Io) {
        self.resources.insert((5, 0, 3), Value::Int(state));
        self.notify((5, 0, 3), io);
    }

    /// A block of firmware written to /5/0/0 (Block1, RFC 7959), or all of it.
    fn firmware_block(&mut self, peer: PeerId, request: &Message, io: &mut Io) {
        let (number, more, size) = request.uint_option(BLOCK1).map(block).unwrap_or((
            0,
            false,
            request.payload.len().max(16),
        ));
        if number == 0 {
            self.package.clear();
            self.package_next = 0;
            self.resources.insert((5, 0, 5), Value::Int(0));
            self.firmware_state(DOWNLOADING, io);
        }
        if number != self.package_next {
            self.endpoint
                .answer(peer, request, INCOMPLETE, None, Vec::new(), Vec::new(), io);
            return;
        }
        self.package.extend_from_slice(&request.payload);
        self.package_next = number + 1;
        let echo = vec![(BLOCK1, uint(block_value(number, more, size)))];
        if more {
            self.endpoint
                .answer(peer, request, CONTINUE, None, Vec::new(), echo, io);
            return;
        }
        let version = mcuboot_version(&self.package).unwrap_or_default();
        self.resources
            .insert((5, 0, 6), Value::Text("firmware".into()));
        self.resources
            .insert((5, 0, 7), Value::Text(version.clone()));
        io.note(&format!(
            "Firmware received: {} bytes{}.",
            self.package.len(),
            if version.is_empty() {
                String::new()
            } else {
                format!(", version {version}")
            }
        ));
        self.endpoint
            .answer(peer, request, CHANGED, None, Vec::new(), echo, io);
        self.firmware_state(DOWNLOADED, io);
    }

    fn update(&mut self, io: &mut Io) {
        let Some(location) = self.location.clone() else {
            return self.register(io);
        };
        let message = Message {
            kind: CON,
            code: POST,
            id: self.endpoint.id(),
            token: self.endpoint.token(),
            options: path_options(&location),
            payload: Vec::new(),
        };
        self.endpoint.request(Target::Default, 0, message, io);
    }

    /// The resources under a path, as TLV.
    fn read_tlv(&self, path: &[u16]) -> Option<Vec<u8>> {
        let chosen: Vec<(&(u16, u16, u16), &Value)> = self
            .resources
            .iter()
            .filter(|((object, instance, resource), _)| {
                [*object, *instance, *resource]
                    .iter()
                    .zip(path)
                    .all(|(have, want)| have == want)
            })
            .collect();
        if chosen.is_empty() {
            return None;
        }
        if path.len() <= 1 {
            let mut out = Vec::new();
            let mut instances: Vec<u16> = chosen
                .iter()
                .map(|((_, instance, _), _)| *instance)
                .collect();
            instances.dedup();
            for instance in instances {
                let inner: Vec<u8> = chosen
                    .iter()
                    .filter(|((_, have, _), _)| *have == instance)
                    .flat_map(|((_, _, resource), value)| {
                        tlv_encode(3, *resource, &value.tlv_bytes())
                    })
                    .collect();
                out.extend(tlv_encode(0, instance, &inner));
            }
            return Some(out);
        }
        Some(
            chosen
                .iter()
                .flat_map(|((_, _, resource), value)| tlv_encode(3, *resource, &value.tlv_bytes()))
                .collect(),
        )
    }

    /// The resources under a path, as SenML JSON.
    fn read_senml(&self, path: &[u16]) -> Option<Vec<u8>> {
        let records: Vec<String> = self
            .resources
            .iter()
            .filter(|((object, instance, resource), _)| {
                [*object, *instance, *resource]
                    .iter()
                    .zip(path)
                    .all(|(have, want)| have == want)
            })
            .map(|((object, instance, resource), value)| {
                let field = match value {
                    Value::Text(text) => {
                        format!("\"vs\":{}", serde_json::Value::String(text.clone()))
                    }
                    Value::Int(number) => format!("\"v\":{number}"),
                    Value::Float(number) => format!("\"v\":{number}"),
                    Value::Bool(on) => format!("\"vb\":{on}"),
                    Value::Opaque(bytes) => {
                        format!("\"vd\":\"{}\"", super::websocket::base64(bytes))
                    }
                };
                format!("{{\"n\":\"/{object}/{instance}/{resource}\",{field}}}")
            })
            .collect();
        (!records.is_empty()).then(|| format!("[{}]", records.join(",")).into_bytes())
    }

    /// The resources under a path, as SenML CBOR: a name (0) and a value each.
    fn read_senml_cbor(&self, path: &[u16]) -> Option<Vec<u8>> {
        let records: Vec<Cbor> = self
            .resources
            .iter()
            .filter(|((object, instance, resource), _)| {
                [*object, *instance, *resource]
                    .iter()
                    .zip(path)
                    .all(|(have, want)| have == want)
            })
            .map(|((object, instance, resource), value)| {
                Cbor::Map(vec![
                    (
                        Cbor::Int(0),
                        Cbor::Text(format!("/{object}/{instance}/{resource}")),
                    ),
                    (Cbor::Int(value.senml_label()), value.to_cbor()),
                ])
            })
            .collect();
        (!records.is_empty()).then(|| Cbor::Array(records).encode())
    }

    fn read(&self, path: &[u16], accept: Option<u32>) -> Result<(u32, Vec<u8>), u8> {
        let single = path.len() >= 3;
        match accept {
            Some(TEXT) | None if single => {
                let value = self
                    .resources
                    .get(&(path[0], path[1], path[2]))
                    .ok_or(NOT_FOUND)?;
                Ok((TEXT, value.to_text().into_bytes()))
            }
            Some(TEXT) => Err(NOT_ACCEPTABLE),
            Some(SENML_JSON) => self
                .read_senml(path)
                .map(|bytes| (SENML_JSON, bytes))
                .ok_or(NOT_FOUND),
            Some(SENML_CBOR) => self
                .read_senml_cbor(path)
                .map(|bytes| (SENML_CBOR, bytes))
                .ok_or(NOT_FOUND),
            Some(CBOR) if single => {
                let value = self
                    .resources
                    .get(&(path[0], path[1], path[2]))
                    .ok_or(NOT_FOUND)?;
                Ok((CBOR, value.to_cbor().encode()))
            }
            Some(TLV) | None => self
                .read_tlv(path)
                .map(|bytes| (TLV, bytes))
                .ok_or(NOT_FOUND),
            Some(LINKS) => {
                let links: Vec<String> = self
                    .resources
                    .keys()
                    .filter(|(object, instance, resource)| {
                        [*object, *instance, *resource]
                            .iter()
                            .zip(path)
                            .all(|(have, want)| have == want)
                    })
                    .map(|(object, instance, resource)| {
                        format!("</{object}/{instance}/{resource}>")
                    })
                    .collect();
                if links.is_empty() {
                    return Err(NOT_FOUND);
                }
                Ok((LINKS, links.join(",").into_bytes()))
            }
            Some(_) => Err(NOT_ACCEPTABLE),
        }
    }

    /// Tells each observer of a path under which `key` is what it now reads.
    fn notify(&mut self, key: (u16, u16, u16), io: &mut Io) {
        let changed = [key.0, key.1, key.2];
        let observers: Vec<(PeerId, Vec<u8>, Vec<u16>, u32)> = self
            .observers
            .iter()
            .filter(|(_, _, path, _)| {
                path.iter()
                    .zip(changed.iter())
                    .all(|(want, have)| want == have)
            })
            .cloned()
            .collect();
        for (peer, token, path, accept) in observers {
            let Ok((format, payload)) = self.read(&path, Some(accept)) else {
                continue;
            };
            self.sequence = self.sequence.wrapping_add(1);
            let message = Message {
                kind: NON,
                code: CONTENT,
                id: self.endpoint.id(),
                token,
                options: vec![
                    (OBSERVE, uint(self.sequence)),
                    (CONTENT_FORMAT, uint(format)),
                ],
                payload,
            };
            io.went(peer, &coap::describe(&message));
            io.send(Target::Peer(peer), message.encode());
        }
    }

    fn handle_request(&mut self, peer: PeerId, request: &Message, io: &mut Io) {
        let plain = request.plain_path();
        if self.bootstrapping {
            if request.code == POST && plain == "/bs" {
                self.bootstrap_finish(peer, request, io);
                return;
            }
            if request.code == DELETE && plain.trim_matches('/').is_empty() {
                self.bootstrap_write(peer, &[], request, io);
                return;
            }
        }
        let Ok(path) = parse_path(&plain) else {
            self.endpoint
                .answer(peer, request, NOT_FOUND, None, Vec::new(), Vec::new(), io);
            return;
        };
        if path == [5, 0, 0] && matches!(request.code, PUT | POST) {
            self.firmware_block(peer, request, io);
            return;
        }
        if self.bootstrapping && matches!(request.code, PUT | DELETE) && path[0] <= 1 {
            self.bootstrap_write(peer, &path, request, io);
            return;
        }
        // The Security object is the bootstrap server's alone.
        if path[0] == 0 {
            self.endpoint.answer(
                peer,
                request,
                UNAUTHORIZED,
                None,
                Vec::new(),
                Vec::new(),
                io,
            );
            return;
        }
        let accept = request.uint_option(ACCEPT);
        match request.code {
            GET => {
                let observe = request.uint_option(OBSERVE);
                match self.read(&path, accept) {
                    Ok((format, payload)) => {
                        let mut extra = Vec::new();
                        match observe {
                            Some(0) => {
                                self.observers.retain(|(from, token, _, _)| {
                                    !(*from == peer && *token == request.token)
                                });
                                self.observers.push((
                                    peer,
                                    request.token.clone(),
                                    path.clone(),
                                    format,
                                ));
                                extra.push((OBSERVE, uint(self.sequence)));
                            }
                            Some(1) => self.observers.retain(|(from, token, _, _)| {
                                !(*from == peer && *token == request.token)
                            }),
                            _ => {}
                        }
                        self.endpoint.answer(
                            peer,
                            request,
                            CONTENT,
                            Some(format),
                            payload,
                            extra,
                            io,
                        );
                    }
                    Err(code) => {
                        self.endpoint
                            .answer(peer, request, code, None, Vec::new(), Vec::new(), io)
                    }
                }
            }
            PUT if path.len() >= 3 && request.payload.is_empty() => {
                // Write-Attributes: taken, as they only change when notifications go.
                self.endpoint
                    .answer(peer, request, CHANGED, None, Vec::new(), Vec::new(), io);
            }
            PUT | POST if path.len() >= 3 && !(request.code == POST && is_executable(&path)) => {
                let key = (path[0], path[1], path[2]);
                let Some(present) = self.resources.get(&key).cloned() else {
                    self.endpoint.answer(
                        peer,
                        request,
                        NOT_FOUND,
                        None,
                        Vec::new(),
                        Vec::new(),
                        io,
                    );
                    return;
                };
                let format = request.uint_option(CONTENT_FORMAT).unwrap_or(TEXT);
                let parsed = if format == TLV {
                    tlv_decode(&request.payload)
                        .ok()
                        .and_then(|items| items.into_iter().next())
                        .map(|item| decode_tlv_like(&present, &item.value))
                        .ok_or_else(|| "TLV that cannot be read".to_string())
                } else {
                    present.parse_like(&String::from_utf8_lossy(&request.payload))
                };
                match parsed {
                    Ok(value) => {
                        io.note(&format!("{} = {}", path_text(&path), value.to_text()));
                        self.resources.insert(key, value);
                        self.endpoint.answer(
                            peer,
                            request,
                            CHANGED,
                            None,
                            Vec::new(),
                            Vec::new(),
                            io,
                        );
                        self.notify(key, io);
                        if key == (5, 0, 1) {
                            self.package_uri(io);
                        }
                    }
                    Err(problem) => {
                        io.bad(&problem);
                        self.endpoint.answer(
                            peer,
                            request,
                            BAD_REQUEST,
                            None,
                            Vec::new(),
                            Vec::new(),
                            io,
                        );
                    }
                }
            }
            POST if is_executable(&path) && (path[0], path[2]) == (5, 2) => {
                if self.resources.get(&(5, 0, 3)) != Some(&Value::Int(DOWNLOADED)) {
                    io.note("The server asked to update the firmware, and none is downloaded: turned down.");
                    self.endpoint.answer(
                        peer,
                        request,
                        NOT_ALLOWED,
                        None,
                        Vec::new(),
                        Vec::new(),
                        io,
                    );
                    return;
                }
                io.note("The server asked to update the firmware: updating.");
                self.endpoint
                    .answer(peer, request, CHANGED, None, Vec::new(), Vec::new(), io);
                self.firmware_state(UPDATING, io);
                self.updating_until = Some(Instant::now() + Duration::from_secs(2));
            }
            POST if is_executable(&path) => {
                let what = match (path[0], path[2]) {
                    (3, 4) => "reboot",
                    (3, 5) => "factory reset",
                    (3, 12) => "reset the error code",
                    (1, 8) => "update the registration",
                    _ => "execute",
                };
                io.note(&format!("The server asked to {what}."));
                self.endpoint
                    .answer(peer, request, CHANGED, None, Vec::new(), Vec::new(), io);
                if (path[0], path[2]) == (1, 8) {
                    self.update(io);
                }
                if (path[0], path[2]) == (3, 12) {
                    self.resources.insert((3, 0, 11), Value::Int(0));
                }
            }
            DELETE => {
                self.endpoint
                    .answer(peer, request, NOT_ALLOWED, None, Vec::new(), Vec::new(), io)
            }
            _ => self
                .endpoint
                .answer(peer, request, NOT_ALLOWED, None, Vec::new(), Vec::new(), io),
        }
    }
}

fn is_executable(path: &[u16]) -> bool {
    path.len() >= 3 && matches!((path[0], path[2]), (3, 4 | 5 | 12) | (1, 4 | 8) | (5, 2))
}

/// A TLV value read as the resource's present value is.
fn decode_tlv_like(present: &Value, bytes: &[u8]) -> Value {
    match present {
        Value::Text(_) => Value::Text(String::from_utf8_lossy(bytes).into_owned()),
        Value::Bool(_) => Value::Bool(bytes.first() == Some(&1)),
        Value::Float(_) if bytes.len() == 4 => Value::Float(f64::from(f32::from_be_bytes(
            bytes.try_into().unwrap_or_default(),
        ))),
        Value::Float(_) if bytes.len() == 8 => {
            Value::Float(f64::from_be_bytes(bytes.try_into().unwrap_or_default()))
        }
        Value::Int(_) | Value::Float(_) if matches!(bytes.len(), 1 | 2 | 4 | 8) => {
            let mut wide = [if bytes[0] & 0x80 != 0 { 0xff } else { 0 }; 8];
            wide[8 - bytes.len()..].copy_from_slice(bytes);
            Value::Int(i64::from_be_bytes(wide))
        }
        _ => Value::Opaque(bytes.to_vec()),
    }
}

const CLIENT_HELP: &str = "register             register with the server again
bootstrap            ask the server for bootstrap, then register where it says
update               update the registration now
deregister           leave the server
set <path> <value>   change a resource, such as set /3303/0/5700 30.5; observers are told
objects              the resources and their values
It registers by itself, and its temperature, /3303/0/5700, changes every 5 s.
Firmware pushed to /5/0/0 is taken; executing /5/0/2 updates to it.";

impl Engine for Client {
    fn help(&self) -> &'static str {
        CLIENT_HELP
    }

    fn joined(&mut self, peer: &Peer, _io: &mut Io) {
        self.server = peer.id;
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let message = match Message::decode(bytes) {
            Ok(message) => message,
            Err(problem) => {
                io.bad(&format!("Not CoAP: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        io.came(peer, &coap::describe(&message));
        if message.code >= 0x40 || message.code == 0 {
            if message.kind == RST {
                self.observers.retain(|(from, _, _, _)| *from != peer);
            }
            self.endpoint.settle(&message);
            if message.code != 0 && self.bootstrap_token.as_ref() == Some(&message.token) {
                self.bootstrap_token = None;
                if message.code < 0x80 {
                    io.note("Bootstrap asked for: the server writes its settings next.");
                } else {
                    io.bad("The bootstrap server turned it down: is this its address?");
                    self.bootstrapping = false;
                }
                return;
            }
            if self.register_token.as_ref() == Some(&message.token) && message.code == CREATED {
                let location: Vec<String> = message
                    .options
                    .iter()
                    .filter(|(number, _)| *number == 8)
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
                    .collect();
                let location = format!("/{}", location.join("/"));
                io.note(&format!("Registered at {location}."));
                self.location = Some(location);
                self.register_token = None;
                let every = Duration::from_secs(u64::from(self.options.lifetime.max(10)) * 8 / 10);
                self.next_update = Some(Instant::now() + every);
            } else if message.code >= 0x80 && self.register_token.as_ref() == Some(&message.token) {
                io.bad("The server turned the registration down.");
                self.register_token = None;
                self.next_update = Some(Instant::now() + Duration::from_secs(30));
            } else if message.code == NOT_FOUND && self.location.is_some() {
                // The server forgot it: register again.
                self.location = None;
                self.next_update = Some(Instant::now());
            }
            return;
        }
        if self.endpoint.again(peer, &message, io) {
            return;
        }
        self.handle_request(peer, &message, io);
        self.report_if_changed(io);
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        self.command_line(words, io);
        self.report_if_changed(io);
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        for token in self.endpoint.tick(now, io) {
            if self.register_token.as_ref() == Some(&token) {
                self.register_token = None;
            }
            if self.bootstrap_token.as_ref() == Some(&token) {
                self.bootstrap_token = None;
                self.bootstrapping = false;
            }
        }
        self.timers(now, io);
        self.report_if_changed(io);
    }
}

impl Client {
    fn command_line(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.next().unwrap_or_default().to_lowercase().as_str() {
                "register" => {
                    self.location = None;
                    self.register(io);
                }
                "bootstrap" => {
                    self.bootstrapped = false;
                    self.location = None;
                    self.ask_bootstrap(io);
                }
                "update" => self.update(io),
                "deregister" => {
                    let location = self.location.take().ok_or("It is not registered.")?;
                    let message = Message {
                        kind: CON,
                        code: DELETE,
                        id: self.endpoint.id(),
                        token: self.endpoint.token(),
                        options: path_options(&location),
                        payload: Vec::new(),
                    };
                    self.next_update = None;
                    self.endpoint.request(Target::Default, 0, message, io);
                }
                "set" => {
                    let path = parse_path(&words.need("the path, such as /3303/0/5700")?)?;
                    if path.len() != 3 {
                        return Err("set takes one resource's path, such as /3303/0/5700.".into());
                    }
                    let key = (path[0], path[1], path[2]);
                    let present = self
                        .resources
                        .get(&key)
                        .cloned()
                        .ok_or(format!("There is no {}.", path_text(&path)))?;
                    let value = present.parse_like(&words.rest_text())?;
                    self.resources.insert(key, value);
                    self.notify(key, io);
                }
                "objects" => {
                    let lines: Vec<String> = self
                        .resources
                        .iter()
                        .map(|((object, instance, resource), value)| {
                            format!("/{object}/{instance}/{resource} = {}", value.to_text())
                        })
                        .collect();
                    io.note(&lines.join("\n"));
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

    /// Updates when its registration is due, ends a firmware update, and
    /// moves the temperature.
    fn timers(&mut self, now: Instant, io: &mut Io) {
        if self.next_update.is_some_and(|at| now >= at) {
            self.next_update =
                Some(now + Duration::from_secs(u64::from(self.options.lifetime.max(10)) * 8 / 10));
            if self.options.bootstrap && !self.bootstrapped {
                self.ask_bootstrap(io);
            } else {
                self.update(io);
            }
        }
        if self.updating_until.is_some_and(|at| now >= at) {
            self.updating_until = None;
            let version = self
                .resources
                .get(&(5, 0, 7))
                .map(Value::to_text)
                .filter(|version| !version.is_empty());
            match &version {
                Some(version) => {
                    self.resources
                        .insert((3, 0, 3), Value::Text(version.clone()));
                    io.note(&format!("Firmware updated: it runs {version} now."));
                }
                None => io
                    .note("Firmware updated. Its image has no MCUboot header to tell its version."),
            }
            self.package.clear();
            self.package_next = 0;
            // Update Result 1: success.
            self.resources.insert((5, 0, 5), Value::Int(1));
            self.firmware_state(IDLE, io);
            self.notify((5, 0, 5), io);
            self.notify((3, 0, 3), io);
            self.update(io);
        }
        if now >= self.next_reading {
            self.next_reading = now + Duration::from_secs(5);
            let key = (3303, 0, 5700);
            if let Some(Value::Float(temperature)) = self.resources.get(&key).cloned() {
                // A slow walk between 18 and 28 degrees.
                let step = (self.endpoint.counter.next() % 11) as f64 / 10.0 - 0.5;
                let next = ((temperature + step).clamp(18.0, 28.0) * 10.0).round() / 10.0;
                self.resources.insert(key, Value::Float(next));
                self.resources
                    .insert((3, 0, 13), Value::Int(chrono::Utc::now().timestamp()));
                self.notify(key, io);
            }
        }
        let _ = self.server;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{listening, reported, shown, start, udp_on_loopback};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn a_device_registers_over_dtls_with_a_psk() {
        let dtls = crate::net::DtlsOptions {
            psk: true,
            psk_identity: "netnima-device".into(),
            psk_key: "000102030405060708090a0b0c0d0e0f".into(),
            ..crate::net::DtlsOptions::default()
        };
        let (_server, server_events) = start(
            Box::new(Server::new(ServerOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                dtls: Some(crate::net::DtlsOptions {
                    psk_identity: String::new(),
                    ..dtls.clone()
                }),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (_client, client_events) = start(
            Box::new(Client::new(ClientOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                dtls: Some(dtls),
                ..SocketSetup::default()
            },
        );
        shown(&client_events, "Registered at /rd/1.");
        shown(&server_events, "netnima-device registered");
    }

    #[test]
    fn tlv_reads_back_as_it_was_written() {
        let inner = [
            tlv_encode(3, 0, b"netNIMA"),
            tlv_encode(3, 9, &[95]),
            tlv_encode(3, 5700, &21.5f64.to_be_bytes()),
        ]
        .concat();
        let bytes = tlv_encode(0, 0, &inner);
        let items = tlv_decode(&bytes).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(tlv_decode(&items[0].value).unwrap().len(), 3);
        assert_eq!(
            tlv_text(
                &[3],
                &tlv_encode(
                    0,
                    0,
                    &[tlv_encode(3, 0, b"netNIMA"), tlv_encode(3, 9, &[95])].concat()
                )
            )
            .unwrap(),
            "/3/0/0 = netNIMA\n/3/0/9 = 95"
        );
        let long = tlv_encode(3, 1, &[7u8; 300]);
        assert_eq!(tlv_decode(&long).unwrap()[0].value.len(), 300);
    }

    #[test]
    fn a_device_registers_and_is_read_written_observed_and_executed() {
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
        shown(&server_events, "netnima-device registered as /rd/1");
        shown(&client_events, "Registered at /rd/1.");
        server.command("read 1 /3/0");
        let text = shown(&server_events, "/3/0/1 = Simulated board");
        assert!(text.contains("/3/0/0 = netNIMA"), "{text}");
        server.command("read 1 /3/0/3");
        shown(&server_events, "1.0.0");
        server.command("write 1 /3311/0/5850 1");
        shown(&server_events, "2.04 Changed");
        shown(&client_events, "/3311/0/5850 = 1");
        server.command("observe 1 /3303/0/5700");
        shown(&server_events, "Observe 2");
        client.command("set /3303/0/5700 30.5");
        shown(&server_events, "30.5");
        server.command("read 1 /3303 -f senml");
        shown(&server_events, r#""n":"/3303/0/5700","v":30.5"#);
        server.command("read 1 /3/0 -f senml-cbor");
        let text = shown(&server_events, "/3/0/1 = Simulated board");
        assert!(text.contains("/3/0/0 = netNIMA"), "{text}");
        server.command("read 1 /3303/0/5700 -f cbor");
        shown(&server_events, "30.5");
        server.command("execute 1 /3/0/4");
        shown(&client_events, "The server asked to reboot.");
        server.command("discover 1 /3311");
        shown(&server_events, "</3311/0/5850>");
        client.command("deregister");
        shown(&server_events, "netnima-device deregistered.");
    }

    /// The first report of type `kind` that `wanted` takes.
    fn reported_when(
        events: &std::sync::mpsc::Receiver<crate::net::Event>,
        kind: &str,
        wanted: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        loop {
            let report = crate::proto::tests::reported(events, kind);
            if wanted(&report) {
                return report;
            }
        }
    }

    #[test]
    fn answers_read_out_of_each_format() {
        let values = |format, path: &[u16], payload: &[u8]| answer_values(format, path, payload);
        let tlv = tlv_encode(
            0,
            0,
            &[tlv_encode(3, 0, b"netNIMA"), tlv_encode(3, 9, &[95])].concat(),
        );
        assert_eq!(
            values(Some(TLV), &[3], &tlv),
            [
                ("/3/0/0".to_string(), "netNIMA".to_string()),
                ("/3/0/9".to_string(), "95".to_string())
            ]
        );
        assert_eq!(
            values(
                Some(SENML_JSON),
                &[3303, 0],
                br#"[{"bn":"/3303/0/","n":"5700","v":21.5},{"n":"5701","vs":"Cel"}]"#
            ),
            [
                ("/3303/0/5700".to_string(), "21.5".to_string()),
                ("/3303/0/5701".to_string(), "Cel".to_string())
            ]
        );
        assert_eq!(
            values(
                Some(CBOR),
                &[3, 0, 0],
                &Cbor::Text("netNIMA".into()).encode()
            ),
            [("/3/0/0".to_string(), "netNIMA".to_string())]
        );
        assert_eq!(
            values(Some(TEXT), &[3, 0, 3], b"1.0.0"),
            [("/3/0/3".to_string(), "1.0.0".to_string())]
        );
        assert!(values(Some(TEXT), &[3, 0], b"1.0.0").is_empty());
        assert_eq!(
            discovered_links(b"</3311/0>,</3311/0/5850>;pmin=2;pmax=10"),
            [
                json!({ "path": "/3311/0", "attributes": "" }),
                json!({ "path": "/3311/0/5850", "attributes": "pmin=2;pmax=10" })
            ]
        );
    }

    #[test]
    fn the_views_hear_the_devices_the_answers_and_the_requests() {
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
        // The server's view: the device, with its objects.
        let devices = reported_when(&server_events, "devices", |report| {
            report["devices"]
                .as_array()
                .is_some_and(|all| !all.is_empty())
        });
        let device = &devices["devices"][0];
        assert_eq!(device["endpoint"], "netnima-device");
        assert_eq!(device["location"], "1");
        assert_eq!(device["lifetime"], 300);
        assert!(
            device["objects"]
                .as_array()
                .unwrap()
                .contains(&json!("/3303/0"))
        );
        // The device's view: registered, with its resources.
        let state = reported_when(&client_events, "device", |report| {
            report["location"] == "/rd/1"
        });
        assert_eq!(state["registering"], false);
        let resources = state["resources"].as_array().unwrap();
        assert!(resources.contains(&json!({
            "path": "/3303/0/5701",
            "value": "Cel",
            "kind": "text",
        })));

        server.command("read 1 /3/0");
        let asked = reported(&server_events, "asked");
        assert_eq!(asked["method"], "GET");
        assert_eq!(asked["path"], "/3/0");
        assert_eq!(asked["accept"], "TLV");
        let answer = reported(&server_events, "answer");
        assert_eq!(answer["token"], asked["token"]);
        assert_eq!(answer["location"], "1");
        assert_eq!(answer["code"], "2.05 Content");
        assert_eq!(answer["format"], "TLV");
        assert!(
            answer["values"]
                .as_array()
                .unwrap()
                .contains(&json!({ "path": "/3/0/1", "value": "Simulated board" })),
            "{answer}"
        );
        let heard = reported(&client_events, "heard");
        assert_eq!(heard["method"], "GET");
        assert_eq!(heard["path"], "/3/0");
        assert_eq!(heard["code"], "2.05 Content");

        // An observation: its first answer, then the change the device makes.
        server.command("observe 1 /3311/0/5851");
        let asked = reported(&server_events, "asked");
        assert_eq!(asked["observe"], 0);
        let first = reported(&server_events, "answer");
        assert_eq!(
            first["values"],
            json!([{ "path": "/3311/0/5851", "value": "100" }])
        );
        client.command("set /3311/0/5851 40");
        let state = reported_when(&client_events, "device", |report| {
            report["resources"].as_array().unwrap().contains(&json!({
                "path": "/3311/0/5851",
                "value": "40",
                "kind": "integer",
            }))
        });
        assert_eq!(state["observed"], json!(["/3311/0/5851"]));
        let change = reported_when(&server_events, "answer", |report| {
            report["values"][0]["value"] == "40"
        });
        assert_eq!(change["token"], first["token"]);
        assert!(change["observe"].as_u64().is_some());

        server.command("discover 1 /3311");
        let links = reported(&server_events, "answer");
        assert!(
            links["links"]
                .as_array()
                .unwrap()
                .contains(&json!({ "path": "/3311/0/5850", "attributes": "" })),
            "{links}"
        );
        client.command("deregister");
        reported_when(&server_events, "devices", |report| {
            report["devices"].as_array().is_some_and(Vec::is_empty)
        });
        reported_when(&client_events, "device", |report| {
            report["location"].is_null()
        });
    }

    #[test]
    fn a_device_bootstraps_then_takes_firmware_and_updates() {
        let udp = |port| SocketSetup {
            udp: Some(udp_on_loopback(port)),
            ..SocketSetup::default()
        };
        let (server, server_events) = start(
            Box::new(Server::new(ServerOptions::default())),
            SocketKind::Udp,
            udp(0),
        );
        let port = listening(&server_events);
        let (_bootstrap, bootstrap_events) = start(
            Box::new(Server::new(ServerOptions {
                bootstrap: format!("coap://127.0.0.1:{port}"),
                ..ServerOptions::default()
            })),
            SocketKind::Udp,
            udp(0),
        );
        let bootstrap_port = listening(&bootstrap_events);
        let (_client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                bootstrap: true,
                ..ClientOptions::default()
            })),
            SocketKind::Udp,
            udp(bootstrap_port),
        );
        shown(&bootstrap_events, "netnima-device is bootstrapped");
        shown(&client_events, "Registered at /rd/1.");
        shown(&server_events, "netnima-device registered as /rd/1");
        // An image with an MCUboot header: magic, then version 1.2.3+4.
        let mut image = vec![0u8; 3000];
        image[..4].copy_from_slice(&0x96f3_b83d_u32.to_le_bytes());
        image[20] = 1;
        image[21] = 2;
        image[22..24].copy_from_slice(&3u16.to_le_bytes());
        image[24..28].copy_from_slice(&4u32.to_le_bytes());
        let folder = crate::certs::tests::scratch("lwm2m-fw");
        std::fs::create_dir_all(&folder).unwrap();
        let file = folder.join("app.bin");
        std::fs::write(&file, &image).unwrap();
        server.command("execute 1 /5/0/2");
        shown(&client_events, "none is downloaded: turned down");
        server.command(&format!("firmware 1 {}", file.display()));
        shown(
            &client_events,
            "Firmware received: 3000 bytes, version 1.2.3+4.",
        );
        let pushed = reported_when(&server_events, "firmware", |report| report["done"] == true);
        assert_eq!(pushed["sent"], 3000);
        assert_eq!(pushed["total"], 3000);
        assert_eq!(pushed["endpoint"], "netnima-device");
        assert!(pushed["problem"].is_null());
        server.command("execute 1 /5/0/2");
        shown(&client_events, "Firmware updated: it runs 1.2.3+4 now.");
        server.command("read 1 /3/0/3");
        shown(&server_events, "1.2.3+4");
        let _ = std::fs::remove_dir_all(folder);
    }
}
