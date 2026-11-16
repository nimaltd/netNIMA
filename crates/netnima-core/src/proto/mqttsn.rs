//! MQTT-SN 1.2 over UDP, for sensor networks such as Zephyr's MQTT-SN
//! client: a client that connects, registers topics, publishes with QoS -1
//! to 2, subscribes and keeps alive; and a gateway with a broker inside,
//! that its clients publish to each other through.
//!
//! Topics go as ids: a name is registered once (REGISTER), or is two letters
//! (a short topic). The gateway registers a topic with a subscriber before
//! it publishes one the subscriber has not seen.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::mqtt::matches;
use super::{Engine, Io, Words, hex_text, payload_text};
use crate::net::{Peer, PeerId, Target};

const ADVERTISE: u8 = 0x00;
const SEARCHGW: u8 = 0x01;
const GWINFO: u8 = 0x02;
const CONNECT: u8 = 0x04;
const CONNACK: u8 = 0x05;
const WILLTOPICREQ: u8 = 0x06;
const WILLTOPIC: u8 = 0x07;
const WILLMSGREQ: u8 = 0x08;
const WILLMSG: u8 = 0x09;
const REGISTER: u8 = 0x0a;
const REGACK: u8 = 0x0b;
const PUBLISH: u8 = 0x0c;
const PUBACK: u8 = 0x0d;
const PUBCOMP: u8 = 0x0e;
const PUBREC: u8 = 0x0f;
const PUBREL: u8 = 0x10;
const SUBSCRIBE: u8 = 0x12;
const SUBACK: u8 = 0x13;
const UNSUBSCRIBE: u8 = 0x14;
const UNSUBACK: u8 = 0x15;
const PINGREQ: u8 = 0x16;
const PINGRESP: u8 = 0x17;
const DISCONNECT: u8 = 0x18;

const DUP: u8 = 0x80;
const RETAIN: u8 = 0x10;
const WILL: u8 = 0x08;
const CLEAN: u8 = 0x04;
/// The topic id types: a registered id, a predefined one, or two letters.
const NORMAL: u8 = 0;
const PREDEFINED: u8 = 1;
const SHORT: u8 = 2;

const ACCEPTED: u8 = 0;
const INVALID_TOPIC: u8 = 2;
const NOT_SUPPORTED: u8 = 3;

/// MQTT-SN's QoS in its flags: 0, 1, 2, or 3 for -1.
fn qos_of(flags: u8) -> u8 {
    (flags >> 5) & 3
}

fn qos_flags(qos: u8) -> u8 {
    (qos & 3) << 5
}

fn qos_text(qos: u8) -> &'static str {
    match qos {
        0 => "0",
        1 => "1",
        2 => "2",
        _ => "-1",
    }
}

/// A packet's bytes: its length, its type, then its body.
pub fn encode(kind: u8, body: &[u8]) -> Vec<u8> {
    let length = body.len() + 2;
    let mut out = if length < 256 {
        vec![length as u8]
    } else {
        let mut long = vec![1];
        long.extend_from_slice(&((length + 2).min(0xffff) as u16).to_be_bytes());
        long
    };
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// A packet's type and body.
pub fn decode(bytes: &[u8]) -> Result<(u8, &[u8]), String> {
    let (length, start) = match bytes.first() {
        Some(1) => {
            let high = *bytes.get(1).ok_or("it ends early")?;
            let low = *bytes.get(2).ok_or("it ends early")?;
            (usize::from(u16::from_be_bytes([high, low])), 3)
        }
        Some(length) => (usize::from(*length), 1),
        None => return Err("it is empty".into()),
    };
    if length < start + 1 || length > bytes.len() {
        return Err(format!("it says {length} bytes, and {} came", bytes.len()));
    }
    Ok((bytes[start], &bytes[start + 1..length]))
}

fn u16_at(body: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([
        body.get(at).copied().unwrap_or(0),
        body.get(at + 1).copied().unwrap_or(0),
    ])
}

fn code_text(code: u8) -> &'static str {
    match code {
        ACCEPTED => "accepted",
        1 => "rejected: congestion",
        INVALID_TOPIC => "rejected: invalid topic id",
        NOT_SUPPORTED => "rejected: not supported",
        _ => "an unknown return code",
    }
}

/// A topic id as it goes: the two letters of a short topic, or its number.
fn topic_text(kind: u8, id: u16) -> String {
    if kind == SHORT {
        String::from_utf8_lossy(&id.to_be_bytes()).into_owned()
    } else if kind == PREDEFINED {
        format!("predefined {id}")
    } else {
        format!("topic {id}")
    }
}

/// A packet in a line; a PUBLISH's topic is named when `name` knows it.
pub fn describe(kind: u8, body: &[u8], name: impl Fn(u8, u16) -> Option<String>) -> String {
    let message = |at: usize| u16_at(body, at);
    match kind {
        ADVERTISE => format!(
            "ADVERTISE gateway {}, every {} s",
            body.first().copied().unwrap_or(0),
            message(1)
        ),
        SEARCHGW => "SEARCHGW".into(),
        GWINFO => format!("GWINFO gateway {}", body.first().copied().unwrap_or(0)),
        CONNECT => {
            let flags = body.first().copied().unwrap_or(0);
            format!(
                "CONNECT {}, keep-alive {} s{}{}",
                String::from_utf8_lossy(body.get(4..).unwrap_or(&[])),
                message(2),
                if flags & CLEAN != 0 { ", clean" } else { "" },
                if flags & WILL != 0 {
                    ", with a will"
                } else {
                    ""
                }
            )
        }
        CONNACK => format!("CONNACK {}", code_text(body.first().copied().unwrap_or(0))),
        WILLTOPICREQ => "WILLTOPICREQ".into(),
        WILLTOPIC => format!(
            "WILLTOPIC {}",
            String::from_utf8_lossy(body.get(1..).unwrap_or(&[]))
        ),
        WILLMSGREQ => "WILLMSGREQ".into(),
        WILLMSG => format!("WILLMSG {}", payload_text(body)),
        REGISTER => format!(
            "REGISTER topic {} = {} (message {})",
            message(0),
            String::from_utf8_lossy(body.get(4..).unwrap_or(&[])),
            message(2)
        ),
        REGACK => format!(
            "REGACK topic {} (message {}): {}",
            message(0),
            message(2),
            code_text(body.get(4).copied().unwrap_or(0))
        ),
        PUBLISH => {
            let flags = body.first().copied().unwrap_or(0);
            let kind = flags & 3;
            let id = message(1);
            let topic = name(kind, id).unwrap_or_else(|| topic_text(kind, id));
            let qos = qos_of(flags);
            let mut line = format!("PUBLISH {topic} (QoS {}", qos_text(qos));
            if flags & RETAIN != 0 {
                line.push_str(", retained");
            }
            if flags & DUP != 0 {
                line.push_str(", again");
            }
            if qos == 1 || qos == 2 {
                line.push_str(&format!(", message {}", message(3)));
            }
            line.push_str(&format!(
                "): {}",
                payload_text(body.get(5..).unwrap_or(&[]))
            ));
            line
        }
        PUBACK => format!(
            "PUBACK topic {} (message {}): {}",
            message(0),
            message(2),
            code_text(body.get(4).copied().unwrap_or(0))
        ),
        PUBREC | PUBREL | PUBCOMP => format!(
            "{} message {}",
            match kind {
                PUBREC => "PUBREC",
                PUBREL => "PUBREL",
                _ => "PUBCOMP",
            },
            message(0)
        ),
        SUBSCRIBE | UNSUBSCRIBE => {
            let flags = body.first().copied().unwrap_or(0);
            let topic = if flags & 3 == NORMAL {
                String::from_utf8_lossy(body.get(3..).unwrap_or(&[])).into_owned()
            } else {
                topic_text(flags & 3, message(3))
            };
            format!(
                "{} {topic} (QoS {}, message {})",
                if kind == SUBSCRIBE {
                    "SUBSCRIBE"
                } else {
                    "UNSUBSCRIBE"
                },
                qos_text(qos_of(flags)),
                message(1)
            )
        }
        SUBACK => format!(
            "SUBACK topic {} (QoS {}, message {}): {}",
            message(1),
            qos_text(qos_of(body.first().copied().unwrap_or(0))),
            message(3),
            code_text(body.get(5).copied().unwrap_or(0))
        ),
        UNSUBACK => format!("UNSUBACK message {}", message(0)),
        PINGREQ => "PINGREQ".into(),
        PINGRESP => "PINGRESP".into(),
        DISCONNECT if body.len() >= 2 => format!("DISCONNECT, asleep for {} s", message(0)),
        DISCONNECT => "DISCONNECT".into(),
        other => format!("type {other:#04x}: {}", hex_text(body)),
    }
}

/// QoS and retain from flags such as -q1 -r; -q-1 publishes without connecting.
fn publish_flags(words: &mut Words, mut qos: u8) -> Result<(u8, bool), String> {
    let mut retain = false;
    for (letter, value) in words.flags() {
        match letter {
            'q' => {
                qos = match value.as_str() {
                    "0" => 0,
                    "1" => 1,
                    "2" => 2,
                    "-1" | "3" => 3,
                    _ => return Err("QoS is -1, 0, 1 or 2, as in -q1.".into()),
                };
            }
            'r' => retain = true,
            other => {
                return Err(format!(
                    "-{other} is not a flag here: -q-1, -q0, -q1, -q2 or -r."
                ));
            }
        }
    }
    Ok((qos, retain))
}

/// A topic's id and its type: two letters go as themselves.
fn short_topic(name: &str) -> Option<u16> {
    let bytes = name.as_bytes();
    (bytes.len() == 2 && !name.contains(['+', '#']))
        .then(|| u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// A PUBLISH's body.
fn publish_body(flags: u8, topic: u16, message: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![flags];
    body.extend_from_slice(&topic.to_be_bytes());
    body.extend_from_slice(&message.to_be_bytes());
    body.extend_from_slice(payload);
    body
}

// ----- The client -----

/// An MQTT-SN client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    pub client_id: String,
    /// Seconds.
    pub keep_alive: u16,
    /// Topics subscribed to on connecting, with commas between.
    pub subscribe: String,
    /// The QoS for what is not told one.
    pub qos: u8,
    pub clean: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            client_id: "netnima-sn".into(),
            keep_alive: 60,
            subscribe: "sensors/#".into(),
            qos: 0,
            clean: true,
        }
    }
}

/// A publish that waits for its topic's REGACK.
struct Waiting {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    retain: bool,
}

pub struct Client {
    options: ClientOptions,
    connected: bool,
    next_try: Option<Instant>,
    last_sent: Instant,
    next_message: u16,
    /// Topic ids and names, both ways.
    names: BTreeMap<u16, String>,
    ids: HashMap<String, u16>,
    /// Publishes waiting for a REGACK, by the REGISTER's message id.
    waiting: HashMap<u16, Waiting>,
    /// Subscriptions waiting for a SUBACK, by message id.
    subscribing: HashMap<u16, String>,
    /// QoS 2 messages that came, waiting for their PUBREL.
    receiving: HashSet<u16>,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        Self {
            options,
            connected: false,
            next_try: Some(Instant::now()),
            last_sent: Instant::now(),
            next_message: 0,
            names: BTreeMap::new(),
            ids: HashMap::new(),
            waiting: HashMap::new(),
            subscribing: HashMap::new(),
            receiving: HashSet::new(),
        }
    }

    fn message_id(&mut self) -> u16 {
        self.next_message = self.next_message.wrapping_add(1).max(1);
        self.next_message
    }

    fn send(&mut self, kind: u8, body: &[u8], io: &mut Io) {
        io.went(0, &describe(kind, body, |kind, id| self.name(kind, id)));
        io.send(Target::Default, encode(kind, body));
        self.last_sent = Instant::now();
    }

    fn name(&self, kind: u8, id: u16) -> Option<String> {
        match kind {
            NORMAL => self.names.get(&id).cloned(),
            SHORT => Some(topic_text(SHORT, id)),
            _ => None,
        }
    }

    fn connect(&mut self, io: &mut Io) {
        let mut body = vec![if self.options.clean { CLEAN } else { 0 }, 0x01];
        body.extend_from_slice(&self.options.keep_alive.to_be_bytes());
        body.extend_from_slice(self.options.client_id.as_bytes());
        self.send(CONNECT, &body, io);
        self.next_try = Some(Instant::now() + Duration::from_secs(5));
    }

    fn subscribe(&mut self, topic: &str, qos: u8, io: &mut Io) {
        let message = self.message_id();
        let mut body = vec![qos_flags(qos)];
        body.extend_from_slice(&message.to_be_bytes());
        match short_topic(topic) {
            Some(id) => {
                body[0] |= SHORT;
                body.extend_from_slice(&id.to_be_bytes());
            }
            None => body.extend_from_slice(topic.as_bytes()),
        }
        self.subscribing.insert(message, topic.to_string());
        self.send(SUBSCRIBE, &body, io);
    }

    fn publish(
        &mut self,
        topic: &str,
        payload: Vec<u8>,
        qos: u8,
        retain: bool,
        io: &mut Io,
    ) -> Result<(), String> {
        let (kind, id) = match (short_topic(topic), self.ids.get(topic)) {
            (Some(id), _) => (SHORT, id),
            (None, Some(id)) => (NORMAL, *id),
            (None, None) if qos == 3 => {
                return Err("QoS -1 publishes without connecting: give a short topic of two letters, such as t1.".into());
            }
            (None, None) => {
                // The name is registered first; the publish goes on its REGACK.
                let message = self.message_id();
                let mut body = vec![0, 0];
                body.extend_from_slice(&message.to_be_bytes());
                body.extend_from_slice(topic.as_bytes());
                self.waiting.insert(
                    message,
                    Waiting {
                        topic: topic.to_string(),
                        payload,
                        qos,
                        retain,
                    },
                );
                self.send(REGISTER, &body, io);
                return Ok(());
            }
        };
        if !self.connected && qos != 3 {
            return Err("Not connected: nothing was sent. Type connect, or publish with -q-1 to a short topic.".into());
        }
        let message = if qos == 1 || qos == 2 {
            self.message_id()
        } else {
            0
        };
        let flags = qos_flags(qos) | if retain { RETAIN } else { 0 } | kind;
        self.send(PUBLISH, &publish_body(flags, id, message, &payload), io);
        Ok(())
    }
}

const CLIENT_HELP: &str = "pub [-q-1|-q0|-q1|-q2] [-r] <topic> <payload>   publish; -q-1 -q0 -q1 -q2 for QoS, -r to retain; \\r \\n \\xHH in the payload
sub [-q0|-q1|-q2] <topic>                       subscribe, with + and # in names
unsub <topic>                                   unsubscribe
topics                                          the topic ids it knows
ping                                            send PINGREQ
connect                                         connect again
disconnect                                      say goodbye
A topic of two letters goes as itself; others are registered first. Set the gateway as the remote host above.";

impl Engine for Client {
    fn help(&self) -> &'static str {
        CLIENT_HELP
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let (kind, body) = match decode(bytes) {
            Ok(packet) => packet,
            Err(problem) => {
                io.bad(&format!("Not MQTT-SN: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        io.came(peer, &describe(kind, body, |kind, id| self.name(kind, id)));
        match kind {
            CONNACK => {
                if body.first() == Some(&ACCEPTED) {
                    self.connected = true;
                    self.next_try = None;
                    io.note("Connected.");
                    let topics: Vec<String> = self
                        .options
                        .subscribe
                        .split(',')
                        .map(str::trim)
                        .filter(|topic| !topic.is_empty())
                        .map(str::to_string)
                        .collect();
                    let qos = self.options.qos.min(2);
                    for topic in topics {
                        self.subscribe(&topic, qos, io);
                    }
                }
            }
            REGISTER => {
                let id = u16_at(body, 0);
                let message = u16_at(body, 2);
                let name = String::from_utf8_lossy(body.get(4..).unwrap_or(&[])).into_owned();
                self.names.insert(id, name.clone());
                self.ids.insert(name, id);
                let mut answer = id.to_be_bytes().to_vec();
                answer.extend_from_slice(&message.to_be_bytes());
                answer.push(ACCEPTED);
                self.send(REGACK, &answer, io);
            }
            REGACK => {
                let id = u16_at(body, 0);
                let message = u16_at(body, 2);
                let Some(waiting) = self.waiting.remove(&message) else {
                    return;
                };
                if body.get(4) != Some(&ACCEPTED) {
                    io.bad(&format!("{} was not registered.", waiting.topic));
                    return;
                }
                self.names.insert(id, waiting.topic.clone());
                self.ids.insert(waiting.topic.clone(), id);
                if let Err(problem) = self.publish(
                    &waiting.topic,
                    waiting.payload,
                    waiting.qos,
                    waiting.retain,
                    io,
                ) {
                    io.bad(&problem);
                }
            }
            PUBLISH => {
                let flags = body.first().copied().unwrap_or(0);
                let id = u16_at(body, 1);
                let message = u16_at(body, 3);
                let mut answer = id.to_be_bytes().to_vec();
                answer.extend_from_slice(&message.to_be_bytes());
                match qos_of(flags) {
                    1 => {
                        let code = if flags & 3 == NORMAL && !self.names.contains_key(&id) {
                            INVALID_TOPIC
                        } else {
                            ACCEPTED
                        };
                        answer.push(code);
                        self.send(PUBACK, &answer, io);
                    }
                    2 => {
                        self.receiving.insert(message);
                        self.send(PUBREC, &message.to_be_bytes(), io);
                    }
                    _ => {}
                }
            }
            PUBREL => {
                let message = u16_at(body, 0);
                self.receiving.remove(&message);
                self.send(PUBCOMP, &message.to_be_bytes(), io);
            }
            PUBREC => {
                let message = u16_at(body, 0);
                self.send(PUBREL, &message.to_be_bytes(), io);
            }
            SUBACK => {
                let id = u16_at(body, 1);
                let message = u16_at(body, 3);
                if let Some(topic) = self.subscribing.remove(&message)
                    && body.get(5) == Some(&ACCEPTED)
                    && id != 0
                    && short_topic(&topic).is_none()
                {
                    self.names.insert(id, topic.clone());
                    self.ids.insert(topic, id);
                }
            }
            DISCONNECT => {
                self.connected = false;
                self.next_try = None;
                io.note("Disconnected. Type connect to connect again.");
            }
            _ => {}
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.next().unwrap_or_default().to_lowercase().as_str() {
                "pub" | "publish" => {
                    let (qos, retain) = publish_flags(words, self.options.qos.min(2))?;
                    let topic = words.need("the topic")?;
                    let payload = words.rest();
                    self.publish(&topic, payload, qos, retain, io)?;
                }
                "sub" | "subscribe" => {
                    let (qos, _) = publish_flags(words, self.options.qos.min(2))?;
                    let topic = words.need("the topic")?;
                    self.subscribe(&topic, qos.min(2), io);
                }
                "unsub" | "unsubscribe" => {
                    let topic = words.need("the topic")?;
                    let message = self.message_id();
                    let mut body = vec![NORMAL];
                    body.extend_from_slice(&message.to_be_bytes());
                    match short_topic(&topic) {
                        Some(id) => {
                            body[0] = SHORT;
                            body.extend_from_slice(&id.to_be_bytes());
                        }
                        None => body.extend_from_slice(topic.as_bytes()),
                    }
                    self.send(UNSUBSCRIBE, &body, io);
                }
                "topics" => {
                    let lines: Vec<String> = self
                        .names
                        .iter()
                        .map(|(id, name)| format!("{id} = {name}"))
                        .collect();
                    io.note(&if lines.is_empty() {
                        "No topic is registered yet.".to_string()
                    } else {
                        lines.join("\n")
                    });
                }
                "ping" => self.send(PINGREQ, self.options.client_id.clone().as_bytes(), io),
                "connect" => self.connect(io),
                "disconnect" => {
                    self.send(DISCONNECT, &[], io);
                    self.connected = false;
                    self.next_try = None;
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

    fn tick(&mut self, now: Instant, io: &mut Io) {
        if !self.connected && self.next_try.is_some_and(|at| now >= at) {
            self.connect(io);
        }
        let keep_alive = u64::from(self.options.keep_alive);
        if self.connected
            && keep_alive > 0
            && now.duration_since(self.last_sent) >= Duration::from_millis(keep_alive * 800)
        {
            self.send(PINGREQ, &[], io);
        }
    }
}

// ----- The gateway -----

/// An MQTT-SN gateway tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct GatewayOptions {
    /// Its id, in GWINFO.
    pub gateway_id: u8,
}

impl Default for GatewayOptions {
    fn default() -> Self {
        Self { gateway_id: 1 }
    }
}

/// A will: its topic, message, QoS and whether it is retained.
type Will = (String, Vec<u8>, u8, bool);

/// One client of the gateway.
struct Session {
    client_id: String,
    keep_alive: Duration,
    last_heard: Instant,
    connected: bool,
    /// The topic ids it has been told of.
    known: HashSet<u16>,
    subscriptions: Vec<(String, u8)>,
    /// A will asked for, its topic and flags while its message is awaited.
    will_topic: Option<(String, u8)>,
    will: Option<Will>,
    /// QoS 2 messages that came, waiting for their PUBREL.
    receiving: HashMap<u16, (String, Vec<u8>, bool)>,
}

/// A gateway with a broker inside: its clients publish to each other.
pub struct Gateway {
    gateway_id: u8,
    sessions: BTreeMap<PeerId, Session>,
    /// One id for each topic name, the same for every client.
    ids: HashMap<String, u16>,
    names: BTreeMap<u16, String>,
    retained: BTreeMap<String, Vec<u8>>,
    next_message: u16,
}

impl Gateway {
    pub fn new(options: GatewayOptions) -> Self {
        Self {
            gateway_id: options.gateway_id,
            sessions: BTreeMap::new(),
            ids: HashMap::new(),
            names: BTreeMap::new(),
            retained: BTreeMap::new(),
            next_message: 0,
        }
    }

    fn id_of(&mut self, topic: &str) -> u16 {
        if let Some(id) = self.ids.get(topic) {
            return *id;
        }
        let id = self.names.keys().next_back().map_or(1, |last| last + 1);
        self.ids.insert(topic.to_string(), id);
        self.names.insert(id, topic.to_string());
        id
    }

    fn name(&self, kind: u8, id: u16) -> Option<String> {
        match kind {
            NORMAL => self.names.get(&id).cloned(),
            SHORT => Some(topic_text(SHORT, id)),
            _ => None,
        }
    }

    fn send(&self, peer: PeerId, kind: u8, body: &[u8], io: &mut Io) {
        io.went(peer, &describe(kind, body, |kind, id| self.name(kind, id)));
        io.send(Target::Peer(peer), encode(kind, body));
    }

    fn message_id(&mut self) -> u16 {
        self.next_message = self.next_message.wrapping_add(1).max(1);
        self.next_message
    }

    /// Sends a message to every client subscribed to its topic, registering
    /// the topic first with those that have not seen it.
    fn route(&mut self, topic: &str, payload: &[u8], qos: u8, retain: bool, io: &mut Io) {
        if retain {
            if payload.is_empty() {
                self.retained.remove(topic);
            } else {
                self.retained.insert(topic.to_string(), payload.to_vec());
            }
        }
        let receivers: Vec<(PeerId, u8)> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.connected)
            .filter_map(|(peer, session)| {
                session
                    .subscriptions
                    .iter()
                    .filter(|(filter, _)| matches(filter, topic))
                    .map(|(_, granted)| *granted)
                    .max()
                    .map(|granted| (*peer, granted.min(qos.min(2))))
            })
            .collect();
        for (peer, qos) in receivers {
            self.deliver(peer, topic, payload, qos, false, io);
        }
    }

    fn deliver(
        &mut self,
        peer: PeerId,
        topic: &str,
        payload: &[u8],
        qos: u8,
        retained: bool,
        io: &mut Io,
    ) {
        let (kind, id) = match short_topic(topic) {
            Some(id) => (SHORT, id),
            None => {
                let id = self.id_of(topic);
                let told = self
                    .sessions
                    .get(&peer)
                    .is_some_and(|session| session.known.contains(&id));
                if !told {
                    let message = self.message_id();
                    let mut body = id.to_be_bytes().to_vec();
                    body.extend_from_slice(&message.to_be_bytes());
                    body.extend_from_slice(topic.as_bytes());
                    self.send(peer, REGISTER, &body, io);
                    if let Some(session) = self.sessions.get_mut(&peer) {
                        session.known.insert(id);
                    }
                }
                (NORMAL, id)
            }
        };
        let message = if qos == 0 { 0 } else { self.message_id() };
        let flags = qos_flags(qos) | if retained { RETAIN } else { 0 } | kind;
        self.send(
            peer,
            PUBLISH,
            &publish_body(flags, id, message, payload),
            io,
        );
    }

    /// A client gone without DISCONNECT: its will is published.
    fn lost(&mut self, peer: PeerId, io: &mut Io) {
        let Some(session) = self.sessions.remove(&peer) else {
            return;
        };
        io.note(&format!("{} is gone.", session.client_id));
        if let Some((topic, payload, qos, retain)) = session.will {
            io.note(&format!("Its will goes to {topic}."));
            self.route(&topic, &payload, qos, retain, io);
        }
    }
}

const GATEWAY_HELP: &str =
    "pub [-q0|-q1|-q2] [-r] <topic> <payload>   publish to the clients subscribed
clients                                    the clients connected
topics                                     the topic ids given out
It takes CONNECT, REGISTER, PUBLISH, SUBSCRIBE, wills and PINGREQ, and answers SEARCHGW.";

impl Engine for Gateway {
    fn help(&self) -> &'static str {
        GATEWAY_HELP
    }

    fn left(&mut self, peer: PeerId, io: &mut Io) {
        self.lost(peer, io);
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let (kind, body) = match decode(bytes) {
            Ok(packet) => packet,
            Err(problem) => {
                io.bad(&format!("Not MQTT-SN: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        io.came(peer, &describe(kind, body, |kind, id| self.name(kind, id)));
        if let Some(session) = self.sessions.get_mut(&peer) {
            session.last_heard = Instant::now();
        }
        match kind {
            SEARCHGW => self.send(peer, GWINFO, &[self.gateway_id], io),
            CONNECT => {
                let flags = body.first().copied().unwrap_or(0);
                let client_id = String::from_utf8_lossy(body.get(4..).unwrap_or(&[])).into_owned();
                let keep_alive = Duration::from_secs(u64::from(u16_at(body, 2)));
                let old = self.sessions.remove(&peer);
                let mut session = Session {
                    client_id,
                    keep_alive,
                    last_heard: Instant::now(),
                    connected: flags & WILL == 0,
                    known: HashSet::new(),
                    subscriptions: Vec::new(),
                    will_topic: None,
                    will: None,
                    receiving: HashMap::new(),
                };
                // Without a clean session, it keeps what it had.
                if flags & CLEAN == 0
                    && let Some(old) = old
                {
                    session.known = old.known;
                    session.subscriptions = old.subscriptions;
                }
                self.sessions.insert(peer, session);
                if flags & WILL != 0 {
                    self.send(peer, WILLTOPICREQ, &[], io);
                } else {
                    self.send(peer, CONNACK, &[ACCEPTED], io);
                }
            }
            WILLTOPIC => {
                let flags = body.first().copied().unwrap_or(0);
                let topic = String::from_utf8_lossy(body.get(1..).unwrap_or(&[])).into_owned();
                if let Some(session) = self.sessions.get_mut(&peer) {
                    session.will_topic = Some((topic, flags));
                }
                self.send(peer, WILLMSGREQ, &[], io);
            }
            WILLMSG => {
                if let Some(session) = self.sessions.get_mut(&peer) {
                    if let Some((topic, flags)) = session.will_topic.take() {
                        session.will = Some((
                            topic,
                            body.to_vec(),
                            qos_of(flags).min(2),
                            flags & RETAIN != 0,
                        ));
                    }
                    session.connected = true;
                }
                self.send(peer, CONNACK, &[ACCEPTED], io);
            }
            REGISTER => {
                let message = u16_at(body, 2);
                let topic = String::from_utf8_lossy(body.get(4..).unwrap_or(&[])).into_owned();
                let id = self.id_of(&topic);
                if let Some(session) = self.sessions.get_mut(&peer) {
                    session.known.insert(id);
                }
                let mut answer = id.to_be_bytes().to_vec();
                answer.extend_from_slice(&message.to_be_bytes());
                answer.push(ACCEPTED);
                self.send(peer, REGACK, &answer, io);
            }
            PUBLISH => {
                let flags = body.first().copied().unwrap_or(0);
                let id = u16_at(body, 1);
                let message = u16_at(body, 3);
                let payload = body.get(5..).unwrap_or(&[]).to_vec();
                let qos = qos_of(flags);
                let topic = self.name(flags & 3, id);
                let mut answer = id.to_be_bytes().to_vec();
                answer.extend_from_slice(&message.to_be_bytes());
                let Some(topic) = topic else {
                    if qos == 1 || qos == 2 {
                        answer.push(INVALID_TOPIC);
                        self.send(peer, PUBACK, &answer, io);
                    }
                    return;
                };
                let retain = flags & RETAIN != 0;
                match qos {
                    1 => {
                        answer.push(ACCEPTED);
                        self.send(peer, PUBACK, &answer, io);
                        self.route(&topic, &payload, 1, retain, io);
                    }
                    2 => {
                        if let Some(session) = self.sessions.get_mut(&peer) {
                            session.receiving.insert(message, (topic, payload, retain));
                        }
                        self.send(peer, PUBREC, &message.to_be_bytes(), io);
                    }
                    // QoS 0, and -1 from clients not connected.
                    _ => self.route(&topic, &payload, 0, retain, io),
                }
            }
            PUBREL => {
                let message = u16_at(body, 0);
                let held = self
                    .sessions
                    .get_mut(&peer)
                    .and_then(|session| session.receiving.remove(&message));
                self.send(peer, PUBCOMP, &message.to_be_bytes(), io);
                if let Some((topic, payload, retain)) = held {
                    self.route(&topic, &payload, 2, retain, io);
                }
            }
            PUBREC => {
                let message = u16_at(body, 0);
                self.send(peer, PUBREL, &message.to_be_bytes(), io);
            }
            SUBSCRIBE => {
                let flags = body.first().copied().unwrap_or(0);
                let message = u16_at(body, 1);
                let qos = qos_of(flags).min(2);
                let topic = match flags & 3 {
                    NORMAL => String::from_utf8_lossy(body.get(3..).unwrap_or(&[])).into_owned(),
                    SHORT => topic_text(SHORT, u16_at(body, 3)),
                    _ => String::new(),
                };
                let mut answer = vec![qos_flags(qos)];
                if topic.is_empty() {
                    answer.extend_from_slice(&[0, 0]);
                    answer.extend_from_slice(&message.to_be_bytes());
                    answer.push(INVALID_TOPIC);
                    self.send(peer, SUBACK, &answer, io);
                    return;
                }
                // A name without wildcards gets its id; a filter gets 0.
                let id = if topic.contains(['+', '#']) || short_topic(&topic).is_some() {
                    0
                } else {
                    self.id_of(&topic)
                };
                if let Some(session) = self.sessions.get_mut(&peer) {
                    session.subscriptions.retain(|(filter, _)| *filter != topic);
                    session.subscriptions.push((topic.clone(), qos));
                    if id != 0 {
                        session.known.insert(id);
                    }
                }
                answer.extend_from_slice(&id.to_be_bytes());
                answer.extend_from_slice(&message.to_be_bytes());
                answer.push(ACCEPTED);
                self.send(peer, SUBACK, &answer, io);
                // The retained messages under it go at once.
                let retained: Vec<(String, Vec<u8>)> = self
                    .retained
                    .iter()
                    .filter(|(name, _)| matches(&topic, name))
                    .map(|(name, payload)| (name.clone(), payload.clone()))
                    .collect();
                for (name, payload) in retained {
                    self.deliver(peer, &name, &payload, qos, true, io);
                }
            }
            UNSUBSCRIBE => {
                let flags = body.first().copied().unwrap_or(0);
                let message = u16_at(body, 1);
                let topic = if flags & 3 == SHORT {
                    topic_text(SHORT, u16_at(body, 3))
                } else {
                    String::from_utf8_lossy(body.get(3..).unwrap_or(&[])).into_owned()
                };
                if let Some(session) = self.sessions.get_mut(&peer) {
                    session.subscriptions.retain(|(filter, _)| *filter != topic);
                }
                self.send(peer, UNSUBACK, &message.to_be_bytes(), io);
            }
            PINGREQ => self.send(peer, PINGRESP, &[], io),
            DISCONNECT => {
                self.send(peer, DISCONNECT, &[], io);
                if let Some(session) = self.sessions.remove(&peer) {
                    io.note(&format!("{} disconnected.", session.client_id));
                }
            }
            _ => {}
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.next().unwrap_or_default().to_lowercase().as_str() {
                "pub" | "publish" => {
                    let (qos, retain) = publish_flags(words, 0)?;
                    let topic = words.need("the topic")?;
                    let payload = words.rest();
                    io.note(&format!("PUBLISH {topic}: {}", payload_text(&payload)));
                    self.route(&topic, &payload, qos.min(2), retain, io);
                }
                "clients" => {
                    let lines: Vec<String> = self
                        .sessions
                        .values()
                        .map(|session| {
                            let filters: Vec<&str> = session
                                .subscriptions
                                .iter()
                                .map(|(filter, _)| filter.as_str())
                                .collect();
                            format!(
                                "{}, keep-alive {} s, subscribed to {}",
                                session.client_id,
                                session.keep_alive.as_secs(),
                                if filters.is_empty() {
                                    "nothing".to_string()
                                } else {
                                    filters.join(", ")
                                }
                            )
                        })
                        .collect();
                    io.note(&if lines.is_empty() {
                        "No client is connected.".to_string()
                    } else {
                        lines.join("\n")
                    });
                }
                "topics" => {
                    let lines: Vec<String> = self
                        .names
                        .iter()
                        .map(|(id, name)| format!("{id} = {name}"))
                        .collect();
                    io.note(&if lines.is_empty() {
                        "No topic is registered yet.".to_string()
                    } else {
                        lines.join("\n")
                    });
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

    fn tick(&mut self, now: Instant, io: &mut Io) {
        // A client not heard from for one and a half keep-alives is gone.
        let late: Vec<PeerId> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                !session.keep_alive.is_zero()
                    && now.duration_since(session.last_heard) > session.keep_alive * 3 / 2
            })
            .map(|(peer, _)| *peer)
            .collect();
        for peer in late {
            self.lost(peer, io);
        }
    }

    fn joined(&mut self, _peer: &Peer, _io: &mut Io) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{listening, shown, start, udp_on_loopback};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn packets_read_back_with_short_and_long_lengths() {
        let short = encode(PINGREQ, &[]);
        assert_eq!(short, [2, PINGREQ]);
        assert_eq!(decode(&short).unwrap(), (PINGREQ, &[][..]));
        let body = vec![7u8; 300];
        let long = encode(PUBLISH, &body);
        assert_eq!(long[..3], [1, 0x01, 0x30]);
        assert_eq!(decode(&long).unwrap().1.len(), 300);
        assert!(decode(&[9, PUBLISH, 0]).is_err());
        assert_eq!(describe(CONNACK, &[0], |_, _| None), "CONNACK accepted");
    }

    #[test]
    fn clients_publish_to_each_other_through_the_gateway() {
        let (gateway, gateway_events) = start(
            Box::new(Gateway::new(GatewayOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&gateway_events);
        let udp = || SocketSetup {
            udp: Some(udp_on_loopback(port)),
            ..SocketSetup::default()
        };
        let (_listener, listener_events) = start(
            Box::new(Client::new(ClientOptions {
                client_id: "listener".into(),
                subscribe: "sensors/#, cmd".into(),
                qos: 1,
                ..ClientOptions::default()
            })),
            SocketKind::Udp,
            udp(),
        );
        shown(&listener_events, "SUBACK topic 0 (QoS 1");
        let (sensor, sensor_events) = start(
            Box::new(Client::new(ClientOptions {
                client_id: "sensor".into(),
                subscribe: String::new(),
                ..ClientOptions::default()
            })),
            SocketKind::Udp,
            udp(),
        );
        shown(&sensor_events, "Connected.");
        sensor.command("pub -q1 sensors/temp 21.5");
        shown(&sensor_events, "REGACK topic");
        shown(&sensor_events, "PUBACK topic");
        // The gateway registers the name with the listener, then publishes.
        let text = shown(&listener_events, "PUBLISH sensors/temp (QoS 1");
        assert!(text.contains("REGISTER topic"), "{text}");
        assert!(text.contains("21.5"), "{text}");
        sensor.command("pub -q2 cmd on");
        shown(&sensor_events, "PUBCOMP");
        shown(&listener_events, "PUBLISH cmd (QoS 1");
        // A short topic goes as itself, with QoS -1 too.
        sensor.command("pub -q-1 t1 hello");
        gateway.command("clients");
        shown(
            &gateway_events,
            "listener, keep-alive 60 s, subscribed to sensors/#, cmd",
        );
        // Retained messages reach later subscribers.
        gateway.command("pub -r sensors/rate 10");
        sensor.command("sub sensors/rate");
        shown(&sensor_events, "PUBLISH sensors/rate (QoS 0, retained): 10");
    }
}
