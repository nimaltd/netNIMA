//! MQTT 3.1.1 and 5.0: the packets, a client, and a broker, so one PC can
//! try a device's MQTT either way round.
//!
//! The client connects as soon as its socket does, subscribes to what its
//! settings list, keeps the connection alive and answers QoS 1 and 2. The
//! broker takes many clients, keeps retained messages, sends each
//! subscriber what matches its filters, and publishes a client's will when
//! it goes without saying goodbye.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use super::{Engine, Io, Words, hex, payload_text};
use crate::net::{Peer, PeerId, Target};

/// The most a packet may be: more is taken as a broken stream.
const MOST: usize = 16 * 1024 * 1024;

// The kinds of packet, by their number in the fixed header.
const CONNECT: u8 = 1;
const CONNACK: u8 = 2;
const PUBLISH: u8 = 3;
const PUBACK: u8 = 4;
const PUBREC: u8 = 5;
const PUBREL: u8 = 6;
const PUBCOMP: u8 = 7;
const SUBSCRIBE: u8 = 8;
const SUBACK: u8 = 9;
const UNSUBSCRIBE: u8 = 10;
const UNSUBACK: u8 = 11;
const PINGREQ: u8 = 12;
const PINGRESP: u8 = 13;
const DISCONNECT: u8 = 14;
const AUTH: u8 = 15;

/// A property of an MQTT 5 packet's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Byte(u8),
    Short(u16),
    Long(u32),
    Var(u32),
    Text(String),
    Binary(Vec<u8>),
    Pair(String, String),
}

/// An MQTT 5 packet's properties, by their numbers, in the order they came.
pub type Props = Vec<(u8, Value)>;

/// A will, or a message published.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
    pub props: Props,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Connect {
    /// 3 for 3.1, 4 for 3.1.1, 5 for 5.0.
    pub version: u8,
    pub client_id: String,
    pub clean: bool,
    pub keep_alive: u16,
    pub username: Option<String>,
    pub password: Option<Vec<u8>>,
    pub will: Option<Message>,
    pub props: Props,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    Connect(Connect),
    ConnAck {
        session_present: bool,
        code: u8,
        props: Props,
    },
    Publish {
        message: Message,
        dup: bool,
        id: u16,
    },
    /// PUBACK, PUBREC, PUBREL or PUBCOMP: `kind` says which.
    Ack {
        kind: u8,
        id: u16,
        code: u8,
        props: Props,
    },
    Subscribe {
        id: u16,
        filters: Vec<(String, u8)>,
        props: Props,
    },
    SubAck {
        id: u16,
        codes: Vec<u8>,
        props: Props,
    },
    Unsubscribe {
        id: u16,
        filters: Vec<String>,
        props: Props,
    },
    UnsubAck {
        id: u16,
        codes: Vec<u8>,
        props: Props,
    },
    PingReq,
    PingResp,
    Disconnect {
        code: u8,
        props: Props,
    },
    Auth {
        code: u8,
        props: Props,
    },
}

// ----- Writing packets -----

fn put_var(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn put_text(out: &mut Vec<u8>, text: &str) {
    put_binary(out, text.as_bytes());
}

fn put_binary(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = bytes.len().min(u16::MAX as usize);
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.extend_from_slice(&bytes[..length]);
}

fn put_props(out: &mut Vec<u8>, props: &Props) {
    let mut body = Vec::new();
    for (id, value) in props {
        put_var(&mut body, u32::from(*id));
        match value {
            Value::Byte(byte) => body.push(*byte),
            Value::Short(short) => body.extend_from_slice(&short.to_be_bytes()),
            Value::Long(long) => body.extend_from_slice(&long.to_be_bytes()),
            Value::Var(var) => put_var(&mut body, *var),
            Value::Text(text) => put_text(&mut body, text),
            Value::Binary(bytes) => put_binary(&mut body, bytes),
            Value::Pair(name, value) => {
                put_text(&mut body, name);
                put_text(&mut body, value);
            }
        }
    }
    put_var(out, body.len() as u32);
    out.extend_from_slice(&body);
}

fn packet(kind: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(kind << 4 | flags);
    put_var(&mut out, body.len() as u32);
    out.extend_from_slice(body);
    out
}

impl Packet {
    /// The packet's bytes, for MQTT `version` (4 or 5).
    pub fn encode(&self, version: u8) -> Vec<u8> {
        let v5 = version >= 5;
        let mut body = Vec::new();
        match self {
            Packet::Connect(connect) => {
                if connect.version == 3 {
                    put_text(&mut body, "MQIsdp");
                } else {
                    put_text(&mut body, "MQTT");
                }
                body.push(connect.version);
                let mut flags = 0u8;
                if connect.username.is_some() {
                    flags |= 0x80;
                }
                if connect.password.is_some() {
                    flags |= 0x40;
                }
                if let Some(will) = &connect.will {
                    flags |= 0x04 | (will.qos & 3) << 3;
                    if will.retain {
                        flags |= 0x20;
                    }
                }
                if connect.clean {
                    flags |= 0x02;
                }
                body.push(flags);
                body.extend_from_slice(&connect.keep_alive.to_be_bytes());
                if v5 {
                    put_props(&mut body, &connect.props);
                }
                put_text(&mut body, &connect.client_id);
                if let Some(will) = &connect.will {
                    if v5 {
                        put_props(&mut body, &will.props);
                    }
                    put_text(&mut body, &will.topic);
                    put_binary(&mut body, &will.payload);
                }
                if let Some(username) = &connect.username {
                    put_text(&mut body, username);
                }
                if let Some(password) = &connect.password {
                    put_binary(&mut body, password);
                }
                packet(CONNECT, 0, &body)
            }
            Packet::ConnAck {
                session_present,
                code,
                props,
            } => {
                body.push(u8::from(*session_present));
                body.push(*code);
                if v5 {
                    put_props(&mut body, props);
                }
                packet(CONNACK, 0, &body)
            }
            Packet::Publish { message, dup, id } => {
                put_text(&mut body, &message.topic);
                if message.qos > 0 {
                    body.extend_from_slice(&id.to_be_bytes());
                }
                if v5 {
                    put_props(&mut body, &message.props);
                }
                body.extend_from_slice(&message.payload);
                let flags =
                    (u8::from(*dup) << 3) | (message.qos & 3) << 1 | u8::from(message.retain);
                packet(PUBLISH, flags, &body)
            }
            Packet::Ack {
                kind,
                id,
                code,
                props,
            } => {
                body.extend_from_slice(&id.to_be_bytes());
                if v5 && (*code != 0 || !props.is_empty()) {
                    body.push(*code);
                    if !props.is_empty() {
                        put_props(&mut body, props);
                    }
                }
                packet(*kind, if *kind == PUBREL { 2 } else { 0 }, &body)
            }
            Packet::Subscribe { id, filters, props } => {
                body.extend_from_slice(&id.to_be_bytes());
                if v5 {
                    put_props(&mut body, props);
                }
                for (filter, options) in filters {
                    put_text(&mut body, filter);
                    body.push(*options);
                }
                packet(SUBSCRIBE, 2, &body)
            }
            Packet::SubAck { id, codes, props } => {
                body.extend_from_slice(&id.to_be_bytes());
                if v5 {
                    put_props(&mut body, props);
                }
                body.extend_from_slice(codes);
                packet(SUBACK, 0, &body)
            }
            Packet::Unsubscribe { id, filters, props } => {
                body.extend_from_slice(&id.to_be_bytes());
                if v5 {
                    put_props(&mut body, props);
                }
                for filter in filters {
                    put_text(&mut body, filter);
                }
                packet(UNSUBSCRIBE, 2, &body)
            }
            Packet::UnsubAck { id, codes, props } => {
                body.extend_from_slice(&id.to_be_bytes());
                if v5 {
                    put_props(&mut body, props);
                    body.extend_from_slice(codes);
                }
                packet(UNSUBACK, 0, &body)
            }
            Packet::PingReq => packet(PINGREQ, 0, &[]),
            Packet::PingResp => packet(PINGRESP, 0, &[]),
            Packet::Disconnect { code, props } => {
                if v5 && (*code != 0 || !props.is_empty()) {
                    body.push(*code);
                    put_props(&mut body, props);
                }
                packet(DISCONNECT, 0, &body)
            }
            Packet::Auth { code, props } => {
                body.push(*code);
                put_props(&mut body, props);
                packet(AUTH, 0, &body)
            }
        }
    }
}

// ----- Reading packets -----

/// Reads the parts of one packet's body.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

type Read<T> = Result<T, String>;

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn take(&mut self, count: usize) -> Read<&'a [u8]> {
        if self.left() < count {
            return Err("the packet ends too soon".into());
        }
        let taken = &self.bytes[self.at..self.at + count];
        self.at += count;
        Ok(taken)
    }

    fn byte(&mut self) -> Read<u8> {
        Ok(self.take(1)?[0])
    }

    fn short(&mut self) -> Read<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn long(&mut self) -> Read<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn var(&mut self) -> Read<u32> {
        let mut value = 0u32;
        for shift in 0..4 {
            let byte = self.byte()?;
            value |= u32::from(byte & 0x7f) << (7 * shift);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("a length is longer than 4 bytes".into())
    }

    fn binary(&mut self) -> Read<Vec<u8>> {
        let length = self.short()? as usize;
        Ok(self.take(length)?.to_vec())
    }

    fn text(&mut self) -> Read<String> {
        let bytes = self.binary()?;
        String::from_utf8(bytes).map_err(|_| "a string is not UTF-8".into())
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.bytes[self.at..];
        self.at = self.bytes.len();
        rest
    }

    fn props(&mut self) -> Read<Props> {
        let length = self.var()? as usize;
        let mut inner = Reader::new(self.take(length)?);
        let mut props = Vec::new();
        while inner.left() > 0 {
            let id = inner.var()? as u8;
            let value = match id {
                0x01 | 0x17 | 0x19 | 0x24 | 0x25 | 0x28 | 0x29 | 0x2A => Value::Byte(inner.byte()?),
                0x13 | 0x21 | 0x22 | 0x23 => Value::Short(inner.short()?),
                0x02 | 0x11 | 0x18 | 0x27 => Value::Long(inner.long()?),
                0x0B => Value::Var(inner.var()?),
                0x03 | 0x08 | 0x12 | 0x15 | 0x1A | 0x1C | 0x1F => Value::Text(inner.text()?),
                0x09 | 0x16 => Value::Binary(inner.binary()?),
                0x26 => Value::Pair(inner.text()?, inner.text()?),
                other => return Err(format!("property {other:#04x} is not one MQTT 5 has")),
            };
            props.push((id, value));
        }
        Ok(props)
    }
}

/// Takes the first whole packet off `buffer`, if one is there. `version`
/// is the one spoken on the connection, for MQTT 5's extra fields.
pub fn take(buffer: &mut Vec<u8>, version: u8) -> Result<Option<Packet>, String> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let mut length = 0usize;
    let mut header = 1;
    loop {
        let Some(&byte) = buffer.get(header) else {
            return Ok(None);
        };
        length |= usize::from(byte & 0x7f) << (7 * (header - 1));
        header += 1;
        if byte & 0x80 == 0 {
            break;
        }
        if header > 4 {
            return Err("the length of a packet is longer than 4 bytes: is this MQTT?".into());
        }
    }
    if length > MOST {
        return Err(format!(
            "a packet of {length} bytes is more than netNIMA takes"
        ));
    }
    if buffer.len() < header + length {
        return Ok(None);
    }
    let first = buffer[0];
    let body: Vec<u8> = buffer[header..header + length].to_vec();
    buffer.drain(..header + length);
    decode(first, &body, version).map(Some)
}

fn decode(first: u8, body: &[u8], version: u8) -> Result<Packet, String> {
    let kind = first >> 4;
    let flags = first & 0x0f;
    let v5 = version >= 5;
    let mut read = Reader::new(body);
    let packet = match kind {
        CONNECT => {
            let name = read.text()?;
            let level = read.byte()?;
            if name != "MQTT" && name != "MQIsdp" {
                return Err(format!("the protocol name is {name:?}, not MQTT"));
            }
            let connect_flags = read.byte()?;
            let keep_alive = read.short()?;
            let props = if level >= 5 {
                read.props()?
            } else {
                Vec::new()
            };
            let client_id = read.text()?;
            let will = if connect_flags & 0x04 != 0 {
                let props = if level >= 5 {
                    read.props()?
                } else {
                    Vec::new()
                };
                let topic = read.text()?;
                let payload = read.binary()?;
                Some(Message {
                    topic,
                    payload,
                    qos: (connect_flags >> 3) & 3,
                    retain: connect_flags & 0x20 != 0,
                    props,
                })
            } else {
                None
            };
            let username = if connect_flags & 0x80 != 0 {
                Some(read.text()?)
            } else {
                None
            };
            let password = if connect_flags & 0x40 != 0 {
                Some(read.binary()?)
            } else {
                None
            };
            Packet::Connect(Connect {
                version: level,
                client_id,
                clean: connect_flags & 0x02 != 0,
                keep_alive,
                username,
                password,
                will,
                props,
            })
        }
        CONNACK => {
            let session_present = read.byte()? & 1 != 0;
            let code = read.byte()?;
            let props = if v5 && read.left() > 0 {
                read.props()?
            } else {
                Vec::new()
            };
            Packet::ConnAck {
                session_present,
                code,
                props,
            }
        }
        PUBLISH => {
            let qos = (flags >> 1) & 3;
            if qos == 3 {
                return Err("a PUBLISH has QoS 3, which MQTT does not have".into());
            }
            let topic = read.text()?;
            let id = if qos > 0 { read.short()? } else { 0 };
            let props = if v5 { read.props()? } else { Vec::new() };
            Packet::Publish {
                message: Message {
                    topic,
                    payload: read.rest().to_vec(),
                    qos,
                    retain: flags & 1 != 0,
                    props,
                },
                dup: flags & 8 != 0,
                id,
            }
        }
        PUBACK | PUBREC | PUBREL | PUBCOMP => {
            let id = read.short()?;
            let code = if v5 && read.left() > 0 {
                read.byte()?
            } else {
                0
            };
            let props = if v5 && read.left() > 0 {
                read.props()?
            } else {
                Vec::new()
            };
            Packet::Ack {
                kind,
                id,
                code,
                props,
            }
        }
        SUBSCRIBE => {
            let id = read.short()?;
            let props = if v5 { read.props()? } else { Vec::new() };
            let mut filters = Vec::new();
            while read.left() > 0 {
                let filter = read.text()?;
                filters.push((filter, read.byte()?));
            }
            Packet::Subscribe { id, filters, props }
        }
        SUBACK => {
            let id = read.short()?;
            let props = if v5 { read.props()? } else { Vec::new() };
            Packet::SubAck {
                id,
                codes: read.rest().to_vec(),
                props,
            }
        }
        UNSUBSCRIBE => {
            let id = read.short()?;
            let props = if v5 { read.props()? } else { Vec::new() };
            let mut filters = Vec::new();
            while read.left() > 0 {
                filters.push(read.text()?);
            }
            Packet::Unsubscribe { id, filters, props }
        }
        UNSUBACK => {
            let id = read.short()?;
            let props = if v5 && read.left() > 0 {
                read.props()?
            } else {
                Vec::new()
            };
            Packet::UnsubAck {
                id,
                codes: read.rest().to_vec(),
                props,
            }
        }
        PINGREQ => Packet::PingReq,
        PINGRESP => Packet::PingResp,
        DISCONNECT => {
            let code = if read.left() > 0 { read.byte()? } else { 0 };
            let props = if read.left() > 0 {
                read.props()?
            } else {
                Vec::new()
            };
            Packet::Disconnect { code, props }
        }
        AUTH => {
            let code = if read.left() > 0 { read.byte()? } else { 0 };
            let props = if read.left() > 0 {
                read.props()?
            } else {
                Vec::new()
            };
            Packet::Auth { code, props }
        }
        other => return Err(format!("packet type {other} is not one MQTT has")),
    };
    Ok(packet)
}

// ----- Showing packets -----

fn version_name(version: u8) -> &'static str {
    match version {
        3 => "MQTT 3.1",
        4 => "MQTT 3.1.1",
        5 => "MQTT 5.0",
        _ => "MQTT of an unknown version",
    }
}

fn prop_name(id: u8) -> &'static str {
    match id {
        0x01 => "payload format",
        0x02 => "message expiry",
        0x03 => "content type",
        0x08 => "response topic",
        0x09 => "correlation data",
        0x0B => "subscription id",
        0x11 => "session expiry",
        0x12 => "assigned client id",
        0x13 => "server keep-alive",
        0x15 => "auth method",
        0x16 => "auth data",
        0x17 => "request problem info",
        0x18 => "will delay",
        0x19 => "request response info",
        0x1A => "response info",
        0x1C => "server reference",
        0x1F => "reason",
        0x21 => "receive maximum",
        0x22 => "topic alias maximum",
        0x23 => "topic alias",
        0x24 => "maximum QoS",
        0x25 => "retain available",
        0x26 => "user property",
        0x27 => "maximum packet size",
        0x28 => "wildcards available",
        0x29 => "subscription ids available",
        0x2A => "shared subscriptions available",
        _ => "property",
    }
}

fn props_text(props: &Props) -> String {
    props
        .iter()
        .map(|(id, value)| {
            let value = match value {
                Value::Byte(byte) => byte.to_string(),
                Value::Short(short) => short.to_string(),
                Value::Long(long) => long.to_string(),
                Value::Var(var) => var.to_string(),
                Value::Text(text) => format!("{text:?}"),
                Value::Binary(bytes) => payload_text(bytes),
                Value::Pair(name, value) => format!("{name:?}={value:?}"),
            };
            format!("{} {value}", prop_name(*id))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a reason code says: the same numbers mean the same in CONNACK for
/// 3.1.1 when below 6, and in every MQTT 5 packet.
fn reason(code: u8, version: u8) -> String {
    if version < 5 {
        return match code {
            0 => "accepted".into(),
            1 => "refused: the broker does not speak this MQTT version".into(),
            2 => "refused: the client id is not allowed".into(),
            3 => "refused: the broker cannot serve now".into(),
            4 => "refused: wrong user name or password".into(),
            5 => "refused: not allowed".into(),
            other => format!("code {other}"),
        };
    }
    let text = match code {
        0x00 => "success",
        0x01 => "granted QoS 1",
        0x02 => "granted QoS 2",
        0x04 => "disconnect with will",
        0x10 => "no matching subscribers",
        0x11 => "no subscription existed",
        0x18 => "continue authentication",
        0x80 => "unspecified error",
        0x81 => "malformed packet",
        0x82 => "protocol error",
        0x83 => "implementation specific error",
        0x84 => "unsupported protocol version",
        0x85 => "client id not valid",
        0x86 => "bad user name or password",
        0x87 => "not authorized",
        0x88 => "server unavailable",
        0x89 => "server busy",
        0x8A => "banned",
        0x8B => "server shutting down",
        0x8C => "bad authentication method",
        0x8D => "keep-alive timeout",
        0x8E => "session taken over",
        0x8F => "topic filter invalid",
        0x90 => "topic name invalid",
        0x91 => "packet id in use",
        0x92 => "packet id not found",
        0x93 => "receive maximum exceeded",
        0x94 => "topic alias invalid",
        0x95 => "packet too large",
        0x96 => "message rate too high",
        0x97 => "quota exceeded",
        0x98 => "administrative action",
        0x99 => "payload format invalid",
        0x9A => "retain not supported",
        0x9B => "QoS not supported",
        0x9C => "use another server",
        0x9D => "server moved",
        0x9E => "shared subscriptions not supported",
        0x9F => "connection rate exceeded",
        0xA0 => "maximum connect time",
        0xA1 => "subscription ids not supported",
        0xA2 => "wildcard subscriptions not supported",
        _ => return format!("code {code:#04x}"),
    };
    text.into()
}

fn grant_text(code: u8, version: u8) -> String {
    match code {
        0..=2 => format!("QoS {code}"),
        0x80 if version < 5 => "refused".into(),
        other => reason(other, version),
    }
}

fn ack_name(kind: u8) -> &'static str {
    match kind {
        PUBACK => "PUBACK",
        PUBREC => "PUBREC",
        PUBREL => "PUBREL",
        _ => "PUBCOMP",
    }
}

/// A packet in one line, with its properties on a second when it has some.
pub fn describe(packet: &Packet, version: u8) -> String {
    let with_props = |line: String, props: &Props| {
        if props.is_empty() {
            line
        } else {
            format!("{line}\n{}", props_text(props))
        }
    };
    match packet {
        Packet::Connect(connect) => {
            let mut line = format!(
                "CONNECT {}, {}, keep-alive {} s",
                if connect.client_id.is_empty() {
                    "(no client id)"
                } else {
                    &connect.client_id
                },
                version_name(connect.version),
                connect.keep_alive
            );
            line.push_str(if connect.clean {
                ", clean"
            } else {
                ", keeps its session"
            });
            if let Some(username) = &connect.username {
                line.push_str(&format!(", user {username}"));
            }
            if connect.password.is_some() {
                line.push_str(", with a password");
            }
            if let Some(will) = &connect.will {
                line.push_str(&format!(
                    ", will {} (QoS {}{}): {}",
                    will.topic,
                    will.qos,
                    if will.retain { ", retained" } else { "" },
                    payload_text(&will.payload)
                ));
            }
            with_props(line, &connect.props)
        }
        Packet::ConnAck {
            session_present,
            code,
            props,
        } => with_props(
            format!(
                "CONNACK {}{}",
                reason(*code, version),
                if *session_present {
                    ", session kept"
                } else {
                    ""
                }
            ),
            props,
        ),
        Packet::Publish { message, dup, id } => {
            let mut about = vec![format!("QoS {}", message.qos)];
            if message.qos > 0 {
                about.push(format!("id {id}"));
            }
            if message.retain {
                about.push("retained".into());
            }
            if *dup {
                about.push("again".into());
            }
            with_props(
                format!(
                    "PUBLISH {} ({}): {}",
                    message.topic,
                    about.join(", "),
                    payload_text(&message.payload)
                ),
                &message.props,
            )
        }
        Packet::Ack {
            kind,
            id,
            code,
            props,
        } => {
            let code = if *code == 0 {
                String::new()
            } else {
                format!(", {}", reason(*code, 5))
            };
            with_props(format!("{} id {id}{code}", ack_name(*kind)), props)
        }
        Packet::Subscribe { id, filters, props } => {
            let list: Vec<String> = filters
                .iter()
                .map(|(filter, options)| format!("{filter} (QoS {})", options & 3))
                .collect();
            with_props(format!("SUBSCRIBE id {id}: {}", list.join(", ")), props)
        }
        Packet::SubAck { id, codes, props } => {
            let list: Vec<String> = codes
                .iter()
                .map(|code| grant_text(*code, version))
                .collect();
            with_props(format!("SUBACK id {id}: {}", list.join(", ")), props)
        }
        Packet::Unsubscribe { id, filters, props } => with_props(
            format!("UNSUBSCRIBE id {id}: {}", filters.join(", ")),
            props,
        ),
        Packet::UnsubAck { id, codes, props } => {
            let list: Vec<String> = codes.iter().map(|code| reason(*code, 5)).collect();
            let list = if list.is_empty() {
                String::new()
            } else {
                format!(": {}", list.join(", "))
            };
            with_props(format!("UNSUBACK id {id}{list}"), props)
        }
        Packet::PingReq => "PINGREQ".into(),
        Packet::PingResp => "PINGRESP".into(),
        Packet::Disconnect { code, props } => {
            let code = if *code == 0 {
                String::new()
            } else {
                format!(": {}", reason(*code, 5))
            };
            with_props(format!("DISCONNECT{code}"), props)
        }
        Packet::Auth { code, props } => with_props(format!("AUTH {}", reason(*code, 5)), props),
    }
}

// ----- Topics -----

/// Whether a topic matches a subscription's filter, with + for one level and
/// # for the rest. Topics starting with $ match only filters that name it.
pub fn matches(filter: &str, topic: &str) -> bool {
    if topic.starts_with('$') && (filter.starts_with('+') || filter.starts_with('#')) {
        return false;
    }
    let mut filter_levels = filter.split('/');
    let mut topic_levels = topic.split('/');
    loop {
        match (filter_levels.next(), topic_levels.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(level), Some(topic_level)) if level == topic_level => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// What is wrong with a filter, if anything.
fn filter_problem(filter: &str) -> Option<String> {
    if filter.is_empty() {
        return Some("A topic filter cannot be empty.".into());
    }
    let levels: Vec<&str> = filter.split('/').collect();
    for (index, level) in levels.iter().enumerate() {
        if level.contains('#') && (*level != "#" || index + 1 != levels.len()) {
            return Some(format!(
                "In {filter}, # must be a level of its own, the last."
            ));
        }
        if level.contains('+') && *level != "+" {
            return Some(format!("In {filter}, + must be a level of its own."));
        }
    }
    None
}

/// A shared subscription's filter without its "$share/group/" in front.
fn plain_filter(filter: &str) -> &str {
    filter
        .strip_prefix("$share/")
        .and_then(|rest| rest.split_once('/'))
        .map_or(filter, |(_, filter)| filter)
}

/// A client id when none is set: netnima- and a few hex digits.
fn made_up_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    format!(
        "netnima-{:06x}",
        (nanos ^ std::process::id().rotate_left(13)) & 0xff_ffff
    )
}

/// QoS and retain from flags such as -q1 -r; the defaults otherwise.
fn publish_flags(words: &mut Words, mut qos: u8) -> Result<(u8, bool), String> {
    let mut retain = false;
    for (letter, value) in words.flags() {
        match letter {
            'q' => {
                qos = value
                    .parse()
                    .ok()
                    .filter(|qos: &u8| *qos <= 2)
                    .ok_or("QoS is 0, 1 or 2, as in -q1.")?;
            }
            'r' => retain = true,
            other => return Err(format!("-{other} is not a flag here: -q0, -q1, -q2 or -r.")),
        }
    }
    Ok((qos, retain))
}

// ----- The client -----

/// An MQTT client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// 4 for 3.1.1, 5 for 5.0, 3 for 3.1.
    pub version: u8,
    /// Empty for one made up.
    pub client_id: String,
    pub username: String,
    pub password: String,
    /// Seconds; 0 for none.
    pub keep_alive: u16,
    /// Starts a new session rather than taking up the last one.
    pub clean: bool,
    /// MQTT 5: how long the broker keeps the session after the connection, in seconds.
    pub session_expiry: u32,
    pub will_topic: String,
    pub will_payload: String,
    pub will_qos: u8,
    pub will_retain: bool,
    /// Filters subscribed to as soon as it connects, with commas between.
    pub subscribe: String,
    /// The QoS those subscriptions and `pub` use unless told.
    pub qos: u8,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            version: 4,
            client_id: String::new(),
            username: String::new(),
            password: String::new(),
            keep_alive: 60,
            clean: true,
            session_expiry: 0,
            will_topic: String::new(),
            will_payload: String::new(),
            will_qos: 0,
            will_retain: false,
            subscribe: String::new(),
            qos: 0,
        }
    }
}

pub struct Client {
    options: ClientOptions,
    client_id: String,
    version: u8,
    /// The connection's peer, while it is up.
    peer: Option<PeerId>,
    buffer: Vec<u8>,
    /// After CONNACK said yes.
    accepted: bool,
    next_id: u16,
    /// QoS 1 and 2 messages sent and not finished, by id.
    unacked: BTreeMap<u16, (String, Instant)>,
    /// The filters of each SUBSCRIBE and UNSUBSCRIBE not answered yet, by
    /// id, so the view learns which its answer is for.
    subscribing: BTreeMap<u16, Vec<(String, u8)>>,
    unsubscribing: BTreeMap<u16, Vec<String>>,
    last_sent: Instant,
    ping_sent: Option<Instant>,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        let client_id = if options.client_id.trim().is_empty() {
            made_up_id()
        } else {
            options.client_id.trim().to_string()
        };
        let version = match options.version {
            3..=5 => options.version,
            _ => 4,
        };
        Self {
            options,
            client_id,
            version,
            peer: None,
            buffer: Vec::new(),
            accepted: false,
            next_id: 0,
            unacked: BTreeMap::new(),
            subscribing: BTreeMap::new(),
            unsubscribing: BTreeMap::new(),
            last_sent: Instant::now(),
            ping_sent: None,
        }
    }

    fn id(&mut self) -> u16 {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.next_id
    }

    fn send(&mut self, packet: Packet, io: &mut Io) {
        let Some(peer) = self.peer else {
            io.bad("Not connected: nothing was sent.");
            return;
        };
        io.went(peer, &describe(&packet, self.version));
        io.send(Target::Default, packet.encode(self.version));
        self.last_sent = Instant::now();
    }

    fn connect_packet(&self) -> Packet {
        let options = &self.options;
        let will = (!options.will_topic.trim().is_empty()).then(|| Message {
            topic: options.will_topic.trim().to_string(),
            payload: options.will_payload.as_bytes().to_vec(),
            qos: options.will_qos.min(2),
            retain: options.will_retain,
            props: Vec::new(),
        });
        let mut props = Vec::new();
        if self.version >= 5 && options.session_expiry > 0 {
            props.push((0x11, Value::Long(options.session_expiry)));
        }
        Packet::Connect(Connect {
            version: self.version,
            client_id: self.client_id.clone(),
            clean: options.clean,
            keep_alive: options.keep_alive,
            username: (!options.username.is_empty()).then(|| options.username.clone()),
            password: (!options.password.is_empty()).then(|| options.password.as_bytes().to_vec()),
            will,
            props,
        })
    }

    fn subscribe(&mut self, filters: Vec<String>, qos: u8, io: &mut Io) {
        for filter in &filters {
            if let Some(problem) = filter_problem(filter) {
                io.bad(&problem);
                return;
            }
        }
        let id = self.id();
        let filters: Vec<(String, u8)> = filters.into_iter().map(|filter| (filter, qos)).collect();
        if self.peer.is_some() {
            self.subscribing.insert(id, filters.clone());
        }
        self.send(
            Packet::Subscribe {
                id,
                filters,
                props: Vec::new(),
            },
            io,
        );
    }

    fn handle(&mut self, packet: Packet, io: &mut Io) {
        match packet {
            Packet::ConnAck {
                code,
                session_present,
                ..
            } => {
                self.accepted = code == 0;
                io.report(json!({
                    "type": "connack",
                    "accepted": self.accepted,
                    "reason": reason(code, self.version),
                    "session_present": session_present,
                }));
                if self.accepted {
                    let filters: Vec<String> = self
                        .options
                        .subscribe
                        .split(',')
                        .map(|filter| filter.trim().to_string())
                        .filter(|filter| !filter.is_empty())
                        .collect();
                    if !filters.is_empty() {
                        self.subscribe(filters, self.options.qos.min(2), io);
                    }
                    // Sent again after a new connection: the broker never saw them finished.
                    if !self.unacked.is_empty() {
                        io.note(&format!(
                            "{} QoS 1 or 2 messages sent before were not finished.",
                            self.unacked.len()
                        ));
                        self.unacked.clear();
                    }
                } else {
                    io.problem(format!(
                        "The broker said no: {}.",
                        reason(code, self.version)
                    ));
                }
            }
            Packet::Publish { message, id, dup } => {
                io.report(json!({
                    "type": "message",
                    "topic": message.topic,
                    "payload": hex(&message.payload),
                    "qos": message.qos,
                    "retain": message.retain,
                    "dup": dup,
                }));
                match message.qos {
                    1 => self.send(
                        Packet::Ack {
                            kind: PUBACK,
                            id,
                            code: 0,
                            props: Vec::new(),
                        },
                        io,
                    ),
                    2 => self.send(
                        Packet::Ack {
                            kind: PUBREC,
                            id,
                            code: 0,
                            props: Vec::new(),
                        },
                        io,
                    ),
                    _ => {}
                }
            }
            Packet::SubAck { id, codes, .. } => {
                let filters = self.subscribing.remove(&id).unwrap_or_default();
                // A code of 0x80 or more says no; below, it is the QoS granted.
                let answers: Vec<serde_json::Value> = filters
                    .iter()
                    .zip(&codes)
                    .map(|((filter, qos), code)| {
                        json!({
                            "filter": filter,
                            "qos": qos,
                            "granted": (*code < 0x80).then_some(*code),
                            "reason": grant_text(*code, self.version),
                        })
                    })
                    .collect();
                io.report(json!({ "type": "suback", "filters": answers }));
            }
            Packet::UnsubAck { id, .. } => {
                let filters = self.unsubscribing.remove(&id).unwrap_or_default();
                io.report(json!({ "type": "unsuback", "filters": filters }));
            }
            Packet::Ack { kind, id, .. } => match kind {
                PUBACK | PUBCOMP => {
                    if let Some((topic, sent)) = self.unacked.remove(&id) {
                        io.report(json!({
                            "type": "delivered",
                            "id": id,
                            "topic": topic,
                            "ms": sent.elapsed().as_secs_f64() * 1000.0,
                        }));
                    }
                }
                PUBREC => self.send(
                    Packet::Ack {
                        kind: PUBREL,
                        id,
                        code: 0,
                        props: Vec::new(),
                    },
                    io,
                ),
                PUBREL => self.send(
                    Packet::Ack {
                        kind: PUBCOMP,
                        id,
                        code: 0,
                        props: Vec::new(),
                    },
                    io,
                ),
                _ => {}
            },
            Packet::PingResp => self.ping_sent = None,
            Packet::Disconnect { .. } => self.accepted = false,
            _ => {}
        }
    }
}

const CLIENT_HELP: &str = "pub [-q0|-q1|-q2] [-r] <topic> <payload>   publish; -q0 -q1 -q2 for QoS, -r to retain; \\r \\n \\xHH in the payload
sub [-q0|-q1|-q2] <filter> [<filter>...]   subscribe, with + and # in filters
unsub <filter> [<filter>...]               unsubscribe
ping                                       send PINGREQ
disconnect                                 say goodbye and close; it connects again if set to
connect                                    close and connect again";

impl Engine for Client {
    fn help(&self) -> &'static str {
        CLIENT_HELP
    }

    fn joined(&mut self, peer: &Peer, io: &mut Io) {
        self.peer = Some(peer.id);
        self.buffer.clear();
        self.accepted = false;
        self.ping_sent = None;
        self.subscribing.clear();
        self.unsubscribing.clear();
        let connect = self.connect_packet();
        self.send(connect, io);
    }

    fn left(&mut self, _peer: PeerId, io: &mut Io) {
        self.peer = None;
        self.accepted = false;
        self.ping_sent = None;
        io.report(json!({ "type": "closed" }));
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        self.buffer.extend_from_slice(bytes);
        loop {
            match take(&mut self.buffer, self.version) {
                Ok(Some(packet)) => {
                    io.came(peer, &describe(&packet, self.version));
                    self.handle(packet, io);
                }
                Ok(None) => break,
                Err(problem) => {
                    io.bad(&format!("What came cannot be read as MQTT: {problem}."));
                    self.buffer.clear();
                    io.drop_peer(peer);
                    break;
                }
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let command = words.next().unwrap_or_default().to_lowercase();
        let done = match command.as_str() {
            "pub" | "publish" => (|| {
                let (qos, retain) = publish_flags(words, self.options.qos.min(2))?;
                let topic = words.need("the topic")?;
                if topic.contains(['+', '#']) {
                    return Err("A topic to publish to has no + or #.".to_string());
                }
                let payload = words.rest();
                let id = if qos > 0 { self.id() } else { 0 };
                if qos > 0 && self.peer.is_some() {
                    self.unacked.insert(id, (topic.clone(), Instant::now()));
                }
                if self.peer.is_some() {
                    io.report(json!({
                        "type": "sent",
                        "id": id,
                        "topic": topic,
                        "qos": qos,
                        "retain": retain,
                    }));
                }
                self.send(
                    Packet::Publish {
                        message: Message {
                            topic,
                            payload,
                            qos,
                            retain,
                            props: Vec::new(),
                        },
                        dup: false,
                        id,
                    },
                    io,
                );
                Ok(())
            })(),
            "sub" | "subscribe" => (|| {
                let (qos, _) = publish_flags(words, self.options.qos.min(2))?;
                let mut filters = Vec::new();
                while let Some(filter) = words.next() {
                    filters.push(filter);
                }
                if filters.is_empty() {
                    return Err("Missing: a topic filter, such as sensors/#.".into());
                }
                self.subscribe(filters, qos, io);
                Ok(())
            })(),
            "unsub" | "unsubscribe" => {
                let mut filters = Vec::new();
                while let Some(filter) = words.next() {
                    filters.push(filter);
                }
                if filters.is_empty() {
                    Err("Missing: a topic filter.".into())
                } else {
                    let id = self.id();
                    if self.peer.is_some() {
                        self.unsubscribing.insert(id, filters.clone());
                    }
                    self.send(
                        Packet::Unsubscribe {
                            id,
                            filters,
                            props: Vec::new(),
                        },
                        io,
                    );
                    Ok(())
                }
            }
            "ping" => {
                self.ping_sent = Some(Instant::now());
                self.send(Packet::PingReq, io);
                Ok(())
            }
            "disconnect" | "bye" => {
                self.send(
                    Packet::Disconnect {
                        code: 0,
                        props: Vec::new(),
                    },
                    io,
                );
                if let Some(peer) = self.peer {
                    io.drop_peer(peer);
                }
                Ok(())
            }
            "connect" | "reconnect" => {
                match self.peer {
                    Some(peer) => io.drop_peer(peer),
                    None => io.note("It connects as soon as the broker answers."),
                }
                Ok(())
            }
            other => Err(format!(
                "{other} is not a command here. Type help for the list."
            )),
        };
        if let Err(problem) = done {
            io.bad(&problem);
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        let keep_alive = Duration::from_secs(u64::from(self.options.keep_alive));
        if !self.accepted || keep_alive.is_zero() {
            return;
        }
        if let Some(sent) = self.ping_sent {
            if now.duration_since(sent) >= keep_alive {
                io.problem("The broker did not answer PINGREQ: the connection may be gone.");
                self.ping_sent = None;
                if let Some(peer) = self.peer {
                    io.drop_peer(peer);
                }
            }
            return;
        }
        if now.duration_since(self.last_sent) >= keep_alive {
            self.ping_sent = Some(now);
            self.send(Packet::PingReq, io);
        }
    }
}

// ----- The broker -----

/// An MQTT broker tab's settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct BrokerOptions {
    /// The user name and password clients must give; empty for anyone.
    pub username: String,
    pub password: String,
}

struct Subscription {
    filter: String,
    qos: u8,
    /// MQTT 5: not sent its own messages.
    no_local: bool,
}

/// A client of the broker.
struct Session {
    /// Where it connected from, for the view.
    address: String,
    buffer: Vec<u8>,
    /// Until CONNECT came, 4.
    version: u8,
    client_id: String,
    connected: bool,
    keep_alive: u16,
    last_heard: Instant,
    will: Option<Message>,
    /// Said goodbye with DISCONNECT, so its will is not published.
    clean_goodbye: bool,
    subscriptions: Vec<Subscription>,
    next_id: u16,
    /// MQTT 5 topic aliases the client set.
    aliases: HashMap<u16, String>,
}

impl Session {
    fn new() -> Self {
        Self {
            address: String::new(),
            buffer: Vec::new(),
            version: 4,
            client_id: String::new(),
            connected: false,
            keep_alive: 0,
            last_heard: Instant::now(),
            will: None,
            clean_goodbye: false,
            subscriptions: Vec::new(),
            next_id: 0,
            aliases: HashMap::new(),
        }
    }
}

pub struct Broker {
    options: BrokerOptions,
    sessions: BTreeMap<PeerId, Session>,
    retained: BTreeMap<String, Message>,
}

impl Broker {
    pub fn new(options: BrokerOptions) -> Self {
        Self {
            options,
            sessions: BTreeMap::new(),
            retained: BTreeMap::new(),
        }
    }

    fn send(&mut self, peer: PeerId, packet: Packet, io: &mut Io) {
        let version = self
            .sessions
            .get(&peer)
            .map_or(4, |session| session.version);
        io.went(peer, &describe(&packet, version));
        io.send(Target::Peer(peer), packet.encode(version));
    }

    /// Sends a message to every client whose subscriptions match it.
    fn route(&mut self, message: &Message, from: Option<PeerId>, io: &mut Io) {
        let mut deliveries = Vec::new();
        for (peer, session) in &self.sessions {
            if !session.connected {
                continue;
            }
            let best = session
                .subscriptions
                .iter()
                .filter(|subscription| !(subscription.no_local && Some(*peer) == from))
                .filter(|subscription| matches(plain_filter(&subscription.filter), &message.topic))
                .map(|subscription| subscription.qos)
                .max();
            if let Some(qos) = best {
                deliveries.push((*peer, qos.min(message.qos)));
            }
        }
        for (peer, qos) in deliveries {
            self.deliver(peer, message, qos, false, io);
        }
    }

    fn deliver(&mut self, peer: PeerId, message: &Message, qos: u8, retain: bool, io: &mut Io) {
        let Some(session) = self.sessions.get_mut(&peer) else {
            return;
        };
        let id = if qos > 0 {
            session.next_id = session.next_id.wrapping_add(1).max(1);
            session.next_id
        } else {
            0
        };
        let packet = Packet::Publish {
            message: Message {
                topic: message.topic.clone(),
                payload: message.payload.clone(),
                qos,
                retain,
                props: Vec::new(),
            },
            dup: false,
            id,
        };
        self.send(peer, packet, io);
    }

    /// Publishes a message from a client, `from`, or from the broker itself,
    /// and tells the view: `name` is who published it, empty for the broker.
    fn publish(&mut self, message: Message, from: Option<PeerId>, io: &mut Io) {
        let name = from
            .and_then(|peer| self.sessions.get(&peer))
            .map_or_else(String::new, |session| session.client_id.clone());
        self.publish_as(message, from, &name, io);
    }

    fn publish_as(&mut self, message: Message, from: Option<PeerId>, name: &str, io: &mut Io) {
        io.report(json!({
            "type": "message",
            "from": name,
            "topic": message.topic,
            "payload": hex(&message.payload),
            "qos": message.qos,
            "retain": message.retain,
        }));
        if message.retain {
            // An empty retained message clears the one before.
            let kept = !message.payload.is_empty();
            if kept {
                self.retained.insert(message.topic.clone(), message.clone());
            } else {
                self.retained.remove(&message.topic);
            }
            io.report(json!({
                "type": "retained",
                "topic": message.topic,
                "payload": kept.then(|| hex(&message.payload)),
                "qos": message.qos,
            }));
        }
        self.route(&message, from, io);
    }

    fn handle(&mut self, peer: PeerId, packet: Packet, io: &mut Io) {
        let connected = self
            .sessions
            .get(&peer)
            .is_some_and(|session| session.connected);
        if !connected && !matches!(packet, Packet::Connect(_)) {
            io.bad("A client must send CONNECT first: it is dropped.");
            io.drop_peer(peer);
            return;
        }
        match packet {
            Packet::Connect(connect) => self.connect(peer, connect, io),
            Packet::Publish {
                mut message, id, ..
            } => {
                if let Some(session) = self.sessions.get_mut(&peer) {
                    // MQTT 5 topic aliases: a topic and its number, or the number alone.
                    let alias =
                        message
                            .props
                            .iter()
                            .find_map(|(prop, value)| match (prop, value) {
                                (0x23, Value::Short(alias)) => Some(*alias),
                                _ => None,
                            });
                    if let Some(alias) = alias {
                        if message.topic.is_empty() {
                            match session.aliases.get(&alias) {
                                Some(topic) => message.topic = topic.clone(),
                                None => {
                                    io.bad(&format!("Topic alias {alias} was never set."));
                                    return;
                                }
                            }
                        } else {
                            session.aliases.insert(alias, message.topic.clone());
                        }
                    }
                }
                match message.qos {
                    1 => self.send(
                        peer,
                        Packet::Ack {
                            kind: PUBACK,
                            id,
                            code: 0,
                            props: Vec::new(),
                        },
                        io,
                    ),
                    2 => self.send(
                        peer,
                        Packet::Ack {
                            kind: PUBREC,
                            id,
                            code: 0,
                            props: Vec::new(),
                        },
                        io,
                    ),
                    _ => {}
                }
                message.props.clear();
                self.publish(message, Some(peer), io);
            }
            Packet::Ack { kind, id, .. } => match kind {
                PUBREL => self.send(
                    peer,
                    Packet::Ack {
                        kind: PUBCOMP,
                        id,
                        code: 0,
                        props: Vec::new(),
                    },
                    io,
                ),
                PUBREC => self.send(
                    peer,
                    Packet::Ack {
                        kind: PUBREL,
                        id,
                        code: 0,
                        props: Vec::new(),
                    },
                    io,
                ),
                _ => {}
            },
            Packet::Subscribe { id, filters, .. } => {
                let mut codes = Vec::new();
                let mut granted = Vec::new();
                if let Some(session) = self.sessions.get_mut(&peer) {
                    for (filter, options) in filters {
                        if filter_problem(plain_filter(&filter)).is_some() {
                            codes.push(if session.version >= 5 { 0x8F } else { 0x80 });
                            continue;
                        }
                        let qos = (options & 3).min(2);
                        session.subscriptions.retain(|known| known.filter != filter);
                        session.subscriptions.push(Subscription {
                            filter: filter.clone(),
                            qos,
                            no_local: session.version >= 5 && options & 0x04 != 0,
                        });
                        codes.push(qos);
                        granted.push((filter, qos));
                    }
                }
                self.send(
                    peer,
                    Packet::SubAck {
                        id,
                        codes,
                        props: Vec::new(),
                    },
                    io,
                );
                let filters: Vec<serde_json::Value> = granted
                    .iter()
                    .map(|(filter, qos)| json!({ "filter": filter, "qos": qos }))
                    .collect();
                io.report(json!({ "type": "subscribed", "peer": peer, "filters": filters }));
                // What is retained under the new filters goes at once.
                for (filter, qos) in granted {
                    let found: Vec<Message> = self
                        .retained
                        .values()
                        .filter(|message| matches(plain_filter(&filter), &message.topic))
                        .cloned()
                        .collect();
                    for message in found {
                        self.deliver(peer, &message, qos.min(message.qos), true, io);
                    }
                }
            }
            Packet::Unsubscribe { id, filters, .. } => {
                let mut codes = Vec::new();
                if let Some(session) = self.sessions.get_mut(&peer) {
                    for filter in &filters {
                        let before = session.subscriptions.len();
                        session
                            .subscriptions
                            .retain(|known| &known.filter != filter);
                        codes.push(if session.subscriptions.len() < before {
                            0x00
                        } else {
                            0x11
                        });
                    }
                }
                io.report(json!({ "type": "unsubscribed", "peer": peer, "filters": filters }));
                self.send(
                    peer,
                    Packet::UnsubAck {
                        id,
                        codes,
                        props: Vec::new(),
                    },
                    io,
                );
            }
            Packet::PingReq => self.send(peer, Packet::PingResp, io),
            Packet::Disconnect { code, .. } => {
                if let Some(session) = self.sessions.get_mut(&peer) {
                    // MQTT 5's "disconnect with will" still wants the will.
                    session.clean_goodbye = code != 0x04;
                }
                io.drop_peer(peer);
            }
            other => io.bad(&format!(
                "A client does not send {}: it is left unanswered.",
                describe(&other, 5)
                    .split_whitespace()
                    .next()
                    .unwrap_or("that")
            )),
        }
    }

    fn connect(&mut self, peer: PeerId, connect: Connect, io: &mut Io) {
        let version = connect.version;
        if !(3..=5).contains(&version) {
            if let Some(session) = self.sessions.get_mut(&peer) {
                session.version = 4;
            }
            self.send(
                peer,
                Packet::ConnAck {
                    session_present: false,
                    code: 1,
                    props: Vec::new(),
                },
                io,
            );
            io.drop_peer(peer);
            return;
        }
        let wanted_user = !self.options.username.is_empty() || !self.options.password.is_empty();
        let user_ok = !wanted_user
            || (connect.username.as_deref() == Some(self.options.username.as_str())
                && connect.password.as_deref() == Some(self.options.password.as_bytes()));
        let mut props = Vec::new();
        let client_id = if connect.client_id.is_empty() {
            let made = made_up_id();
            if version >= 5 {
                props.push((0x12, Value::Text(made.clone())));
            }
            made
        } else {
            connect.client_id.clone()
        };
        if let Some(session) = self.sessions.get_mut(&peer) {
            session.version = version;
        }
        if !user_ok {
            let code = if version >= 5 { 0x86 } else { 4 };
            self.send(
                peer,
                Packet::ConnAck {
                    session_present: false,
                    code,
                    props: Vec::new(),
                },
                io,
            );
            io.drop_peer(peer);
            return;
        }
        // The same client id again: the older connection goes.
        let older: Vec<PeerId> = self
            .sessions
            .iter()
            .filter(|(other, session)| {
                **other != peer && session.connected && session.client_id == client_id
            })
            .map(|(other, _)| *other)
            .collect();
        for other in older {
            io.note(&format!(
                "{client_id} connected again: its older connection is closed."
            ));
            if let Some(session) = self.sessions.get_mut(&other) {
                session.clean_goodbye = true;
            }
            io.drop_peer(other);
        }
        let will = connect.will.as_ref().map(|will| will.topic.clone());
        let mut address = String::new();
        if let Some(session) = self.sessions.get_mut(&peer) {
            session.client_id = client_id.clone();
            session.connected = true;
            session.keep_alive = connect.keep_alive;
            session.will = connect.will;
            address = session.address.clone();
        }
        self.send(
            peer,
            Packet::ConnAck {
                session_present: false,
                code: 0,
                props,
            },
            io,
        );
        io.report(json!({
            "type": "client",
            "peer": peer,
            "client_id": client_id,
            "address": address,
            "version": version_name(version),
            "keep_alive": connect.keep_alive,
            "will": will,
        }));
    }
}

const BROKER_HELP: &str =
    "pub [-q0|-q1|-q2] [-r] <topic> <payload>   publish to the clients subscribed
clients                                    the clients connected and what they subscribed to
retained                                   the retained messages
clear <topic>                              forget a retained message
kick <client number>                       close a client's connection";

impl Engine for Broker {
    fn help(&self) -> &'static str {
        BROKER_HELP
    }

    fn joined(&mut self, peer: &Peer, _io: &mut Io) {
        let session = Session {
            address: peer.address.clone(),
            ..Session::new()
        };
        self.sessions.insert(peer.id, session);
    }

    fn left(&mut self, peer: PeerId, io: &mut Io) {
        let Some(session) = self.sessions.remove(&peer) else {
            return;
        };
        if session.connected {
            io.report(json!({ "type": "gone", "peer": peer, "client_id": session.client_id }));
        }
        if session.connected
            && !session.clean_goodbye
            && let Some(will) = session.will
        {
            io.note(&format!(
                "{} went without a goodbye: its will is published.",
                session.client_id
            ));
            self.publish_as(will, Some(peer), &session.client_id, io);
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Some(session) = self.sessions.get_mut(&peer) else {
            return;
        };
        session.last_heard = Instant::now();
        session.buffer.extend_from_slice(bytes);
        loop {
            let Some(session) = self.sessions.get_mut(&peer) else {
                return;
            };
            let version = session.version;
            match take(&mut session.buffer, version) {
                Ok(Some(packet)) => {
                    let shown_version = match &packet {
                        Packet::Connect(connect) => connect.version,
                        _ => version,
                    };
                    io.came(peer, &describe(&packet, shown_version));
                    self.handle(peer, packet, io);
                }
                Ok(None) => return,
                Err(problem) => {
                    session.buffer.clear();
                    io.bad(&format!(
                        "What came cannot be read as MQTT: {problem}. The client is dropped."
                    ));
                    io.drop_peer(peer);
                    return;
                }
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let command = words.next().unwrap_or_default().to_lowercase();
        let done: Result<(), String> = match command.as_str() {
            "pub" | "publish" => (|| {
                let (qos, retain) = publish_flags(words, 0)?;
                let topic = words.need("the topic")?;
                let payload = words.rest();
                let message = Message {
                    topic,
                    payload,
                    qos,
                    retain,
                    props: Vec::new(),
                };
                io.note(&format!("This broker publishes {}.", message.topic));
                self.publish(message, None, io);
                Ok(())
            })(),
            "clients" => {
                if self.sessions.is_empty() {
                    io.note("No client is connected.");
                }
                let lines: Vec<String> = self
                    .sessions
                    .iter()
                    .map(|(peer, session)| {
                        let filters: Vec<String> = session
                            .subscriptions
                            .iter()
                            .map(|subscription| {
                                format!("{} (QoS {})", subscription.filter, subscription.qos)
                            })
                            .collect();
                        format!(
                            "{peer}: {} {}{}",
                            if session.client_id.is_empty() {
                                "(no CONNECT yet)"
                            } else {
                                &session.client_id
                            },
                            version_name(session.version),
                            if filters.is_empty() {
                                String::new()
                            } else {
                                format!(", subscribed to {}", filters.join(", "))
                            }
                        )
                    })
                    .collect();
                for line in lines {
                    io.note(&line);
                }
                Ok(())
            }
            "retained" => {
                if self.retained.is_empty() {
                    io.note("No message is retained.");
                }
                let lines: Vec<String> = self
                    .retained
                    .values()
                    .map(|message| {
                        format!(
                            "{} (QoS {}): {}",
                            message.topic,
                            message.qos,
                            payload_text(&message.payload)
                        )
                    })
                    .collect();
                for line in lines {
                    io.note(&line);
                }
                Ok(())
            }
            "clear" => (|| {
                let topic = words.need("the topic")?;
                match self.retained.remove(&topic) {
                    Some(_) => {
                        io.note(&format!("{topic} is retained no more."));
                        io.report(json!({ "type": "retained", "topic": topic, "payload": null }));
                    }
                    None => io.note(&format!("Nothing was retained for {topic}.")),
                }
                Ok(())
            })(),
            "kick" => (|| {
                let peer: PeerId = words.number("the client's number, as clients lists it")?;
                if self.sessions.contains_key(&peer) {
                    io.drop_peer(peer);
                    Ok(())
                } else {
                    Err(format!("No client {peer} is connected."))
                }
            })(),
            other => Err(format!(
                "{other} is not a command here. Type help for the list."
            )),
        };
        if let Err(problem) = done {
            io.bad(&problem);
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        // A client quiet for one and a half keep-alives is gone.
        let late: Vec<PeerId> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.connected
                    && session.keep_alive > 0
                    && now.duration_since(session.last_heard)
                        > Duration::from_millis(u64::from(session.keep_alive) * 1500)
            })
            .map(|(peer, _)| *peer)
            .collect();
        for peer in late {
            io.note(&format!(
                "Client {peer} was quiet past its keep-alive: it is dropped."
            ));
            io.drop_peer(peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::SocketKind;
    use crate::proto::SocketSetup;
    use crate::proto::tests::{client_to, listening, reported, server_on_loopback, shown, start};

    fn round_trip(packet: Packet, version: u8) {
        let mut bytes = packet.encode(version);
        assert_eq!(take(&mut bytes, version).unwrap(), Some(packet));
        assert!(bytes.is_empty());
    }

    #[test]
    fn packets_read_back_as_they_were_written_in_both_versions() {
        for version in [4, 5] {
            let props = if version == 5 {
                vec![
                    (0x11, Value::Long(300)),
                    (0x26, Value::Pair("a".into(), "b".into())),
                ]
            } else {
                Vec::new()
            };
            round_trip(
                Packet::Connect(Connect {
                    version,
                    client_id: "board-1".into(),
                    clean: true,
                    keep_alive: 30,
                    username: Some("user".into()),
                    password: Some(b"secret".to_vec()),
                    will: Some(Message {
                        topic: "board/status".into(),
                        payload: b"offline".to_vec(),
                        qos: 1,
                        retain: true,
                        props: Vec::new(),
                    }),
                    props: props.clone(),
                }),
                version,
            );
            round_trip(
                Packet::Publish {
                    message: Message {
                        topic: "a/b".into(),
                        payload: vec![0, 1, 2],
                        qos: 2,
                        retain: false,
                        props: props.clone(),
                    },
                    dup: true,
                    id: 7,
                },
                version,
            );
            round_trip(
                Packet::Subscribe {
                    id: 3,
                    filters: vec![("a/+".into(), 1), ("b/#".into(), 0)],
                    props: Vec::new(),
                },
                version,
            );
            round_trip(
                Packet::SubAck {
                    id: 3,
                    codes: vec![1, 0x80],
                    props: Vec::new(),
                },
                version,
            );
            round_trip(
                Packet::Ack {
                    kind: PUBREL,
                    id: 9,
                    code: 0,
                    props: Vec::new(),
                },
                version,
            );
            round_trip(Packet::PingReq, version);
        }
    }

    #[test]
    fn a_packet_split_in_pieces_waits_for_the_rest() {
        let bytes = Packet::Publish {
            message: Message {
                topic: "t".into(),
                payload: vec![7; 300],
                ..Message::default()
            },
            dup: false,
            id: 0,
        }
        .encode(4);
        let mut buffer = bytes[..3].to_vec();
        assert_eq!(take(&mut buffer, 4).unwrap(), None);
        buffer.extend_from_slice(&bytes[3..]);
        assert!(matches!(
            take(&mut buffer, 4).unwrap(),
            Some(Packet::Publish { .. })
        ));
    }

    #[test]
    fn filters_match_as_mqtt_says() {
        assert!(matches("a/+/c", "a/b/c"));
        assert!(!matches("a/+/c", "a/b/d"));
        assert!(matches("a/#", "a"));
        assert!(matches("a/#", "a/b/c"));
        assert!(matches("#", "x/y"));
        assert!(!matches("#", "$SYS/load"));
        assert!(matches("$SYS/#", "$SYS/load"));
        assert!(!matches("a/b", "a/b/c"));
        assert_eq!(plain_filter("$share/g/a/#"), "a/#");
        assert!(filter_problem("a/#/b").is_some());
        assert!(filter_problem("a+/b").is_some());
        assert!(filter_problem("a/+/b/#").is_none());
    }

    #[test]
    fn a_client_and_the_broker_publish_and_subscribe_with_every_qos() {
        for version in [4, 5] {
            let (_broker, broker_events) = start(
                Box::new(Broker::new(BrokerOptions::default())),
                SocketKind::Server,
                SocketSetup {
                    server: Some(server_on_loopback()),
                    ..SocketSetup::default()
                },
            );
            let port = listening(&broker_events);
            let options = ClientOptions {
                version,
                client_id: "board".into(),
                subscribe: "sensors/#".into(),
                qos: 2,
                will_topic: "board/state".into(),
                will_payload: "gone".into(),
                ..ClientOptions::default()
            };
            let (client, client_events) = start(
                Box::new(Client::new(options)),
                SocketKind::Client,
                SocketSetup {
                    client: Some(client_to(port)),
                    ..SocketSetup::default()
                },
            );
            shown(&client_events, "CONNACK");
            shown(&client_events, "SUBACK id 1: QoS 2");
            for qos in 0..=2 {
                client.command(&format!("pub -q{qos} sensors/temp {qos}1.5"));
                let text = shown(&client_events, &format!(": {qos}1.5"));
                assert!(
                    text.contains(&format!("PUBLISH sensors/temp (QoS {qos}")),
                    "{text}"
                );
            }
            shown(&client_events, "PUBCOMP");
            let text = shown(&broker_events, "PUBLISH sensors/temp (QoS 2");
            assert!(text.contains("CONNECT board"), "{text}");

            // The broker's own message, and one retained for a later subscriber.
            client.command("pub -q0 -r sensors/door open");
            shown(&client_events, "PUBLISH sensors/door (QoS 0): open");
            client.command("sub other/+");
            shown(&client_events, "SUBACK id");
            drop(client);
        }
    }

    #[test]
    fn retained_messages_and_wills_reach_later_subscribers() {
        let (_broker, broker_events) = start(
            Box::new(Broker::new(BrokerOptions::default())),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&broker_events);
        let setup = || SocketSetup {
            client: Some(client_to(port)),
            ..SocketSetup::default()
        };
        let (first, first_events) = start(
            Box::new(Client::new(ClientOptions {
                client_id: "first".into(),
                will_topic: "first/state".into(),
                will_payload: "lost".into(),
                ..ClientOptions::default()
            })),
            SocketKind::Client,
            setup(),
        );
        shown(&first_events, "CONNACK");
        first.command("pub -r config/rate 10");
        shown(&broker_events, "PUBLISH config/rate");

        let (_second, second_events) = start(
            Box::new(Client::new(ClientOptions {
                client_id: "second".into(),
                subscribe: "config/#, first/state".into(),
                ..ClientOptions::default()
            })),
            SocketKind::Client,
            setup(),
        );
        shown(&second_events, "PUBLISH config/rate (QoS 0, retained): 10");
        // Gone without DISCONNECT: the broker publishes its will.
        drop(first);
        shown(&second_events, "PUBLISH first/state (QoS 0): lost");
    }

    #[test]
    fn a_client_over_websocket_and_a_plain_one_share_a_broker() {
        use crate::proto::websocket::{Carriage, Carrier};
        let (_broker, broker_events) = start(
            Box::new(Carrier::server(
                Broker::new(BrokerOptions::default()),
                "mqtt",
            )),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&broker_events);
        let setup = || SocketSetup {
            client: Some(client_to(port)),
            ..SocketSetup::default()
        };
        let carriage = Carriage {
            websocket: true,
            host: "127.0.0.1".into(),
            port,
            ..Carriage::default()
        };
        let (web, web_events) = start(
            Box::new(Carrier::client(
                Client::new(ClientOptions {
                    client_id: "over-ws".into(),
                    subscribe: "plain/#".into(),
                    ..ClientOptions::default()
                }),
                carriage.upgrade("mqtt"),
            )),
            SocketKind::Client,
            setup(),
        );
        shown(&web_events, "101 Switching Protocols");
        shown(&web_events, "SUBACK");
        let (plain, plain_events) = start(
            Box::new(Client::new(ClientOptions {
                client_id: "plain".into(),
                subscribe: "web/#".into(),
                ..ClientOptions::default()
            })),
            SocketKind::Client,
            setup(),
        );
        shown(&plain_events, "SUBACK");
        plain.command("pub plain/temp 21.5");
        shown(&web_events, "PUBLISH plain/temp (QoS 0): 21.5");
        web.command("pub -q1 web/led on");
        shown(&web_events, "PUBACK");
        // The plain client subscribed with QoS 0, so it gets QoS 0.
        shown(&plain_events, "PUBLISH web/led (QoS 0): on");
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let (_broker, broker_events) = start(
            Box::new(Broker::new(BrokerOptions {
                username: "user".into(),
                password: "right".into(),
            })),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&broker_events);
        let (_client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                username: "user".into(),
                password: "wrong".into(),
                ..ClientOptions::default()
            })),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        shown(
            &client_events,
            "CONNACK refused: wrong user name or password",
        );
    }

    #[test]
    fn the_view_hears_what_the_client_and_the_broker_do() {
        let (broker, broker_events) = start(
            Box::new(Broker::new(BrokerOptions::default())),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&broker_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                client_id: "board".into(),
                ..ClientOptions::default()
            })),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        assert_eq!(reported(&client_events, "connack")["accepted"], true);
        let joined = reported(&broker_events, "client");
        assert_eq!(joined["client_id"], "board");
        assert!(
            joined["address"]
                .as_str()
                .unwrap()
                .starts_with("127.0.0.1:")
        );

        // Which filters a SUBACK is for, and the QoS each got.
        client.command("sub -q1 sensors/# board/+/cmd");
        let suback = reported(&client_events, "suback");
        assert_eq!(suback["filters"][0]["filter"], "sensors/#");
        assert_eq!(suback["filters"][0]["granted"], 1);
        assert_eq!(suback["filters"][1]["filter"], "board/+/cmd");
        let subscribed = reported(&broker_events, "subscribed");
        assert_eq!(subscribed["filters"][0]["filter"], "sensors/#");

        // A retained message with bytes no text has: the broker keeps it and
        // sends it back to its sender, which subscribed.
        client.command(r"pub -q1 -r sensors/temp \x01\xff");
        let heard = reported(&broker_events, "message");
        assert_eq!(heard["from"], "board");
        assert_eq!(heard["payload"], "01ff");
        let retained = reported(&broker_events, "retained");
        assert_eq!(
            (&retained["topic"], &retained["payload"]),
            (&json!("sensors/temp"), &json!("01ff"))
        );
        assert_eq!(reported(&client_events, "sent")["topic"], "sensors/temp");
        assert_eq!(
            reported(&client_events, "delivered")["topic"],
            "sensors/temp"
        );
        let came = reported(&client_events, "message");
        assert_eq!(
            (&came["topic"], &came["payload"], &came["qos"]),
            (&json!("sensors/temp"), &json!("01ff"), &json!(1))
        );

        broker.command("clear sensors/temp");
        assert_eq!(reported(&broker_events, "retained")["payload"], json!(null));
        client.command("unsub sensors/#");
        assert_eq!(
            reported(&client_events, "unsuback")["filters"],
            json!(["sensors/#"])
        );
        drop(client);
        assert_eq!(reported(&broker_events, "gone")["client_id"], "board");
    }
}
