//! SNMP v1 and v2c (RFC 1157, RFC 3416): a manager that gets, walks, bulks
//! and sets, and shows the traps that come, and an agent with the system
//! group and a few values of a board's own, that sends traps.
//!
//! Both run on a UDP socket: the manager sends to an agent's port 161, and
//! the agent answers whoever asks. Values are shown as Net-SNMP shows them,
//! such as `sysName.0 = STRING: "board"`, and set with its type letters.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{Engine, Io, Words, hex_text};
use crate::net::{Peer, PeerId, Target};

// ----- BER, as SNMP uses it -----

const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;
const IP_ADDRESS: u8 = 0x40;
const COUNTER32: u8 = 0x41;
const GAUGE32: u8 = 0x42;
const TIMETICKS: u8 = 0x43;
const OPAQUE: u8 = 0x44;
const COUNTER64: u8 = 0x46;
const NO_SUCH_OBJECT: u8 = 0x80;
const NO_SUCH_INSTANCE: u8 = 0x81;
const END_OF_MIB_VIEW: u8 = 0x82;

const GET: u8 = 0xa0;
const GET_NEXT: u8 = 0xa1;
const RESPONSE: u8 = 0xa2;
const SET: u8 = 0xa3;
const TRAP_V1: u8 = 0xa4;
const GET_BULK: u8 = 0xa5;
const INFORM: u8 = 0xa6;
const TRAP_V2: u8 = 0xa7;
const REPORT: u8 = 0xa8;

/// The most values a walk shows before it stops.
const LONGEST_WALK: usize = 2000;

fn put_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let skip = bytes.iter().take_while(|byte| **byte == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    put_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// A signed number in the fewest bytes, two's complement.
fn signed_bytes(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (here, next) = (bytes[start], bytes[start + 1]);
        if (here == 0 && next & 0x80 == 0) || (here == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    bytes[start..].to_vec()
}

/// An unsigned number in the fewest bytes, a 0 in front when its top bit is set.
fn unsigned_bytes(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|byte| **byte == 0).count().min(7);
    let mut out = Vec::new();
    if bytes[skip] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&bytes[skip..]);
    out
}

fn oid_bytes(oid: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    let (first, second) = (
        oid.first().copied().unwrap_or(0),
        oid.get(1).copied().unwrap_or(0),
    );
    let mut arcs = vec![first * 40 + second];
    arcs.extend(oid.iter().skip(2));
    for arc in arcs {
        let mut groups = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            groups.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        groups.reverse();
        out.extend(groups);
    }
    out
}

fn read_oid(bytes: &[u8]) -> Result<Vec<u32>, String> {
    let mut arcs = Vec::new();
    let mut value: u32 = 0;
    for byte in bytes {
        value = value.checked_mul(128).ok_or("an OID arc is too big")? | u32::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    let Some(first) = arcs.first().copied() else {
        return Ok(Vec::new());
    };
    let (a, b) = if first < 80 {
        (first / 40, first % 40)
    } else {
        (2, first - 80)
    };
    let mut oid = vec![a, b];
    oid.extend_from_slice(&arcs[1..]);
    Ok(oid)
}

fn read_signed(bytes: &[u8]) -> i64 {
    let mut value: i64 = if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        -1
    } else {
        0
    };
    for byte in bytes.iter().take(8) {
        value = (value << 8) | i64::from(*byte);
    }
    value
}

fn read_unsigned(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .take(9)
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

/// One TLV off the front of `bytes` at `at`: its tag and its value.
fn read_tlv<'a>(bytes: &'a [u8], at: &mut usize) -> Result<(u8, &'a [u8]), String> {
    let tag = *bytes.get(*at).ok_or("it ends early")?;
    let first = *bytes.get(*at + 1).ok_or("it ends early")?;
    *at += 2;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err("a length is not one SNMP uses".into());
        }
        let bytes_of = bytes.get(*at..*at + count).ok_or("it ends early")?;
        *at += count;
        bytes_of
            .iter()
            .fold(0usize, |length, byte| (length << 8) | usize::from(*byte))
    };
    let value = bytes.get(*at..*at + length).ok_or("it ends early")?;
    *at += length;
    Ok((tag, value))
}

fn expect(bytes: &[u8], at: &mut usize, want: u8, what: &str) -> Result<Vec<u8>, String> {
    let (tag, value) = read_tlv(bytes, at)?;
    if tag != want {
        return Err(format!("{what} is not where it should be"));
    }
    Ok(value.to_vec())
}

// ----- Values and OIDs -----

/// One value of a variable binding.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    Oid(Vec<u32>),
    IpAddress([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl Value {
    fn encode(&self) -> Vec<u8> {
        match self {
            Value::Integer(value) => tlv(INTEGER, &signed_bytes(*value)),
            Value::OctetString(bytes) => tlv(OCTET_STRING, bytes),
            Value::Null => tlv(NULL, &[]),
            Value::Oid(oid) => tlv(OID, &oid_bytes(oid)),
            Value::IpAddress(octets) => tlv(IP_ADDRESS, octets),
            Value::Counter32(value) => tlv(COUNTER32, &unsigned_bytes(u64::from(*value))),
            Value::Gauge32(value) => tlv(GAUGE32, &unsigned_bytes(u64::from(*value))),
            Value::TimeTicks(value) => tlv(TIMETICKS, &unsigned_bytes(u64::from(*value))),
            Value::Opaque(bytes) => tlv(OPAQUE, bytes),
            Value::Counter64(value) => tlv(COUNTER64, &unsigned_bytes(*value)),
            Value::NoSuchObject => tlv(NO_SUCH_OBJECT, &[]),
            Value::NoSuchInstance => tlv(NO_SUCH_INSTANCE, &[]),
            Value::EndOfMibView => tlv(END_OF_MIB_VIEW, &[]),
        }
    }

    fn decode(tag: u8, bytes: &[u8]) -> Result<Value, String> {
        Ok(match tag {
            INTEGER => Value::Integer(read_signed(bytes)),
            OCTET_STRING => Value::OctetString(bytes.to_vec()),
            NULL => Value::Null,
            OID => Value::Oid(read_oid(bytes)?),
            IP_ADDRESS => Value::IpAddress(
                bytes
                    .try_into()
                    .map_err(|_| "an IpAddress is not 4 bytes")?,
            ),
            COUNTER32 => Value::Counter32(read_unsigned(bytes) as u32),
            GAUGE32 => Value::Gauge32(read_unsigned(bytes) as u32),
            TIMETICKS => Value::TimeTicks(read_unsigned(bytes) as u32),
            OPAQUE => Value::Opaque(bytes.to_vec()),
            COUNTER64 => Value::Counter64(read_unsigned(bytes)),
            NO_SUCH_OBJECT => Value::NoSuchObject,
            NO_SUCH_INSTANCE => Value::NoSuchInstance,
            END_OF_MIB_VIEW => Value::EndOfMibView,
            other => return Err(format!("type {other:#04x} is not one SNMP has")),
        })
    }

    /// As Net-SNMP shows it: `STRING: "board"`, `Timeticks: (12345) 0:02:03.45`.
    pub fn describe(&self) -> String {
        match self {
            Value::Integer(value) => format!("INTEGER: {value}"),
            Value::OctetString(bytes) => match std::str::from_utf8(bytes) {
                Ok(text)
                    if text
                        .chars()
                        .all(|c| !c.is_control() || c == '\n' || c == '\t') =>
                {
                    format!("STRING: \"{text}\"")
                }
                _ => format!("Hex-STRING: {}", hex_text(bytes)),
            },
            Value::Null => "NULL".into(),
            Value::Oid(oid) => format!("OID: {}", oid_name(oid)),
            Value::IpAddress(octets) => format!(
                "IpAddress: {}.{}.{}.{}",
                octets[0], octets[1], octets[2], octets[3]
            ),
            Value::Counter32(value) => format!("Counter32: {value}"),
            Value::Gauge32(value) => format!("Gauge32: {value}"),
            Value::TimeTicks(ticks) => {
                let hundredths = ticks % 100;
                let seconds = ticks / 100;
                format!(
                    "Timeticks: ({ticks}) {}:{:02}:{:02}.{hundredths:02}",
                    seconds / 3600,
                    seconds / 60 % 60,
                    seconds % 60
                )
            }
            Value::Opaque(bytes) => format!("Opaque: {}", hex_text(bytes)),
            Value::Counter64(value) => format!("Counter64: {value}"),
            Value::NoSuchObject => "No Such Object available on this agent at this OID".into(),
            Value::NoSuchInstance => "No Such Instance currently exists at this OID".into(),
            Value::EndOfMibView => "No more variables left in this MIB View".into(),
        }
    }

    /// A value typed as `snmpset` takes it: a type letter, then the value.
    fn typed(kind: &str, text: &str) -> Result<Value, String> {
        let text = text.trim();
        let number = |what: &str| -> Result<u64, String> {
            text.parse::<u64>()
                .map_err(|_| format!("{text} is not {what}."))
        };
        Ok(match kind {
            "i" => Value::Integer(
                text.parse()
                    .map_err(|_| format!("{text} is not a whole number."))?,
            ),
            "u" => Value::Gauge32(
                u32::try_from(number("a number from 0 up")?)
                    .map_err(|_| "it is too big".to_string())?,
            ),
            "c" => Value::Counter32(
                u32::try_from(number("a number from 0 up")?)
                    .map_err(|_| "it is too big".to_string())?,
            ),
            "t" => Value::TimeTicks(
                u32::try_from(number("a number of hundredths of a second")?)
                    .map_err(|_| "it is too big".to_string())?,
            ),
            "s" => Value::OctetString(text.trim_matches('"').as_bytes().to_vec()),
            "x" => {
                let digits: String = text.chars().filter(char::is_ascii_hexdigit).collect();
                if !digits.len().is_multiple_of(2) {
                    return Err(format!("{text} is not hex bytes, such as 01 02 ff."));
                }
                Value::OctetString(
                    (0..digits.len())
                        .step_by(2)
                        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap_or(0))
                        .collect(),
                )
            }
            "a" => {
                let ip: std::net::Ipv4Addr = text
                    .parse()
                    .map_err(|_| format!("{text} is not an IPv4 address."))?;
                Value::IpAddress(ip.octets())
            }
            "o" => Value::Oid(parse_oid(text)?),
            "n" => Value::Null,
            other => {
                return Err(format!(
                    "{other} is not a type: i integer, u gauge, c counter, t timeticks, s string, x hex, a address, o OID, n null."
                ));
            }
        })
    }

    /// The same kind of value, for a set that must keep a variable's type.
    fn same_kind(&self, other: &Value) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

/// The names of the OIDs people know, for typing and showing.
const NAMES: [(&str, &[u32]); 14] = [
    ("sysDescr", &[1, 3, 6, 1, 2, 1, 1, 1]),
    ("sysObjectID", &[1, 3, 6, 1, 2, 1, 1, 2]),
    ("sysUpTime", &[1, 3, 6, 1, 2, 1, 1, 3]),
    ("sysContact", &[1, 3, 6, 1, 2, 1, 1, 4]),
    ("sysName", &[1, 3, 6, 1, 2, 1, 1, 5]),
    ("sysLocation", &[1, 3, 6, 1, 2, 1, 1, 6]),
    ("sysServices", &[1, 3, 6, 1, 2, 1, 1, 7]),
    ("system", &[1, 3, 6, 1, 2, 1, 1]),
    ("ifNumber", &[1, 3, 6, 1, 2, 1, 2, 1]),
    ("interfaces", &[1, 3, 6, 1, 2, 1, 2]),
    ("mib-2", &[1, 3, 6, 1, 2, 1]),
    ("snmpTrapOID", &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1]),
    ("coldStart", &[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
    ("enterprises", &[1, 3, 6, 1, 4, 1]),
];

/// An OID typed: numbers with dots, or a name such as sysName.0.
pub fn parse_oid(text: &str) -> Result<Vec<u32>, String> {
    let text = text.trim().trim_start_matches('.');
    let (head, tail) = match text.split_once('.') {
        Some((head, tail)) if !head.chars().all(|c| c.is_ascii_digit()) => (head, tail),
        _ if !text.chars().all(|c| c.is_ascii_digit() || c == '.') => (text, ""),
        _ => ("", text),
    };
    let mut oid = Vec::new();
    if !head.is_empty() {
        let (_, known) = NAMES
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(head))
            .ok_or(format!(
                "{head} is not a name netNIMA knows: give the OID's numbers, such as 1.3.6.1.2.1.1.5.0."
            ))?;
        oid.extend_from_slice(known);
    }
    for part in tail.split('.').filter(|part| !part.is_empty()) {
        oid.push(
            part.parse()
                .map_err(|_| format!("{text} is not an OID, such as 1.3.6.1.2.1.1.5.0."))?,
        );
    }
    if oid.len() < 2 {
        return Err(format!("{text} is not an OID, such as 1.3.6.1.2.1.1.5.0."));
    }
    Ok(oid)
}

/// An OID as people read it: by its name when it has one, such as sysName.0.
pub fn oid_name(oid: &[u32]) -> String {
    let numbers = |arcs: &[u32]| {
        arcs.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    };
    for (name, known) in NAMES {
        if oid.len() >= known.len() && oid[..known.len()] == *known && name != "mib-2" {
            let rest = &oid[known.len()..];
            return if rest.is_empty() {
                name.to_string()
            } else {
                format!("{name}.{}", numbers(rest))
            };
        }
    }
    numbers(oid)
}

// ----- Messages -----

/// A v1 trap's own fields: enterprise, agent address, generic and specific
/// trap, and time stamp.
pub type TrapFields = (Vec<u32>, [u8; 4], i64, i64, u32);

/// One SNMP message: its version (0 for v1, 1 for v2c), community and PDU.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub version: i64,
    pub community: Vec<u8>,
    pub kind: u8,
    pub request_id: i64,
    /// For GetBulk: non-repeaters.
    pub error_status: i64,
    /// For GetBulk: max-repetitions.
    pub error_index: i64,
    pub bindings: Vec<(Vec<u32>, Value)>,
    pub trap: Option<TrapFields>,
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let bindings: Vec<u8> = self
            .bindings
            .iter()
            .flat_map(|(oid, value)| {
                tlv(
                    SEQUENCE,
                    &[tlv(OID, &oid_bytes(oid)), value.encode()].concat(),
                )
            })
            .collect();
        let bindings = tlv(SEQUENCE, &bindings);
        let pdu = match &self.trap {
            Some((enterprise, address, generic, specific, stamp)) => [
                tlv(OID, &oid_bytes(enterprise)),
                tlv(IP_ADDRESS, address),
                tlv(INTEGER, &signed_bytes(*generic)),
                tlv(INTEGER, &signed_bytes(*specific)),
                tlv(TIMETICKS, &unsigned_bytes(u64::from(*stamp))),
                bindings,
            ]
            .concat(),
            None => [
                tlv(INTEGER, &signed_bytes(self.request_id)),
                tlv(INTEGER, &signed_bytes(self.error_status)),
                tlv(INTEGER, &signed_bytes(self.error_index)),
                bindings,
            ]
            .concat(),
        };
        tlv(
            SEQUENCE,
            &[
                tlv(INTEGER, &signed_bytes(self.version)),
                tlv(OCTET_STRING, &self.community),
                tlv(self.kind, &pdu),
            ]
            .concat(),
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Message, String> {
        let mut at = 0;
        let outer = expect(bytes, &mut at, SEQUENCE, "the message")?;
        let mut at = 0;
        let version = read_signed(&expect(&outer, &mut at, INTEGER, "the version")?);
        if version == 3 {
            return Err("it is SNMPv3, which netNIMA does not speak yet".into());
        }
        let community = expect(&outer, &mut at, OCTET_STRING, "the community")?;
        let (kind, pdu) = read_tlv(&outer, &mut at)?;
        let mut at = 0;
        let mut message = Message {
            version,
            community,
            kind,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            bindings: Vec::new(),
            trap: None,
        };
        if kind == TRAP_V1 {
            let enterprise = read_oid(&expect(pdu, &mut at, OID, "the enterprise")?)?;
            let address = expect(pdu, &mut at, IP_ADDRESS, "the agent's address")?;
            let generic = read_signed(&expect(pdu, &mut at, INTEGER, "the generic trap")?);
            let specific = read_signed(&expect(pdu, &mut at, INTEGER, "the specific trap")?);
            let stamp = read_unsigned(&expect(pdu, &mut at, TIMETICKS, "the time stamp")?) as u32;
            message.trap = Some((
                enterprise,
                address.try_into().unwrap_or([0; 4]),
                generic,
                specific,
                stamp,
            ));
        } else {
            message.request_id = read_signed(&expect(pdu, &mut at, INTEGER, "the request id")?);
            message.error_status = read_signed(&expect(pdu, &mut at, INTEGER, "the error status")?);
            message.error_index = read_signed(&expect(pdu, &mut at, INTEGER, "the error index")?);
        }
        let list = expect(pdu, &mut at, SEQUENCE, "the variable bindings")?;
        let mut at = 0;
        while at < list.len() {
            let binding = expect(&list, &mut at, SEQUENCE, "a variable binding")?;
            let mut inner = 0;
            let oid = read_oid(&expect(&binding, &mut inner, OID, "a binding's OID")?)?;
            let (tag, value) = read_tlv(&binding, &mut inner)?;
            message.bindings.push((oid, Value::decode(tag, value)?));
        }
        Ok(message)
    }
}

fn pdu_name(kind: u8) -> &'static str {
    match kind {
        GET => "GetRequest",
        GET_NEXT => "GetNextRequest",
        RESPONSE => "Response",
        SET => "SetRequest",
        TRAP_V1 => "Trap",
        GET_BULK => "GetBulkRequest",
        INFORM => "InformRequest",
        TRAP_V2 => "SNMPv2-Trap",
        REPORT => "Report",
        _ => "PDU",
    }
}

fn error_name(status: i64) -> &'static str {
    match status {
        0 => "noError",
        1 => "tooBig",
        2 => "noSuchName",
        3 => "badValue",
        4 => "readOnly",
        5 => "genErr",
        6 => "noAccess",
        7 => "wrongType",
        8 => "wrongLength",
        9 => "wrongEncoding",
        10 => "wrongValue",
        11 => "noCreation",
        12 => "inconsistentValue",
        13 => "resourceUnavailable",
        14 => "commitFailed",
        15 => "undoFailed",
        16 => "authorizationError",
        17 => "notWritable",
        18 => "inconsistentName",
        _ => "an error",
    }
}

/// A message in lines: its PDU, then a binding a line.
pub fn describe(message: &Message) -> String {
    let version = if message.version == 0 { "v1" } else { "v2c" };
    let mut head = format!(
        "SNMP{version} {} \"{}\"",
        pdu_name(message.kind),
        String::from_utf8_lossy(&message.community)
    );
    match &message.trap {
        Some((enterprise, address, generic, specific, _)) => head.push_str(&format!(
            ", enterprise {}, from {}.{}.{}.{}, generic {generic}, specific {specific}",
            oid_name(enterprise),
            address[0],
            address[1],
            address[2],
            address[3]
        )),
        None if message.kind == GET_BULK => head.push_str(&format!(
            " id {}, non-repeaters {}, max-repetitions {}",
            message.request_id, message.error_status, message.error_index
        )),
        None => {
            head.push_str(&format!(" id {}", message.request_id));
            if message.error_status != 0 {
                head.push_str(&format!(
                    ", error {} at {}",
                    error_name(message.error_status),
                    message.error_index
                ));
            }
        }
    }
    let lines: Vec<String> = message
        .bindings
        .iter()
        .map(|(oid, value)| {
            if *value == Value::Null && message.kind != RESPONSE {
                oid_name(oid)
            } else {
                format!("{} = {}", oid_name(oid), value.describe())
            }
        })
        .collect();
    if lines.is_empty() {
        head
    } else {
        format!("{head}\n{}", lines.join("\n"))
    }
}

/// What lies under `root`: `oid` starts with it.
fn under(oid: &[u32], root: &[u32]) -> bool {
    oid.len() > root.len() && oid[..root.len()] == *root
}

// ----- The manager -----

/// An SNMP manager tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ManagerOptions {
    pub community: String,
    /// "1" or "2c".
    pub version: String,
}

impl Default for ManagerOptions {
    fn default() -> Self {
        Self {
            community: "public".into(),
            version: "2c".into(),
        }
    }
}

/// A walk going on: what it is under, and how many values it has shown.
struct Walk {
    root: Vec<u32>,
    count: usize,
}

/// Asks an agent: get, next, walk, bulk and set; and shows the traps that come.
pub struct Manager {
    community: String,
    version: i64,
    next_id: i64,
    walks: HashMap<i64, Walk>,
    /// When each request went, to say how long the answer took.
    sent: HashMap<i64, Instant>,
}

impl Manager {
    pub fn new(options: ManagerOptions) -> Self {
        Self {
            community: options.community,
            version: i64::from(options.version.trim() != "1"),
            next_id: i64::from(std::process::id() % 10_000 * 100 + 1),
            walks: HashMap::new(),
            sent: HashMap::new(),
        }
    }

    fn request(
        &mut self,
        kind: u8,
        bindings: Vec<(Vec<u32>, Value)>,
        extra: (i64, i64),
        io: &mut Io,
    ) -> i64 {
        self.next_id += 1;
        let message = Message {
            version: self.version,
            community: self.community.as_bytes().to_vec(),
            kind,
            request_id: self.next_id,
            error_status: extra.0,
            error_index: extra.1,
            bindings,
            trap: None,
        };
        io.went(0, &describe(&message));
        io.send(Target::Default, message.encode());
        self.sent.insert(self.next_id, Instant::now());
        self.next_id
    }

    /// The bindings of a list of OIDs, each with a NULL value.
    fn asked(words: &mut Words) -> Result<Vec<(Vec<u32>, Value)>, String> {
        let mut bindings = Vec::new();
        while let Some(word) = words.next() {
            bindings.push((parse_oid(&word)?, Value::Null));
        }
        if bindings.is_empty() {
            return Err("Give an OID, such as sysDescr.0 or 1.3.6.1.2.1.1.1.0.".into());
        }
        Ok(bindings)
    }
}

const MANAGER_HELP: &str = "get <oid> [oid...]         get values, such as get sysDescr.0 sysUpTime.0
next <oid>                 the value after an OID
walk [oid]                 every value under an OID: mib-2 unless told
bulk <oid> [count]         up to count values after it, in one answer (v2c)
set <oid> <type> <value>   set a value; type i integer, u gauge, c counter, t timeticks, s string, x hex, a address, o OID
community <name>           the community it asks with
version 1|2c               the version it speaks
Set the agent's address as the remote host above. Traps and informs that come are shown.";

impl Engine for Manager {
    fn help(&self) -> &'static str {
        MANAGER_HELP
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let message = match Message::decode(bytes) {
            Ok(message) => message,
            Err(problem) => {
                io.bad(&format!("Not SNMP: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        let took = self
            .sent
            .remove(&message.request_id)
            .map(|sent| format!(" ({} ms)", sent.elapsed().as_millis()))
            .unwrap_or_default();
        let mut text = describe(&message);
        if let Some(first) = text.lines().next().map(str::len) {
            text.insert_str(first, &took);
        }
        io.came(peer, &text);
        match message.kind {
            // An inform is answered, as its sender waits for it.
            INFORM => {
                let answer = Message {
                    kind: RESPONSE,
                    ..message.clone()
                };
                io.went(peer, &describe(&answer));
                io.send(Target::Peer(peer), answer.encode());
            }
            RESPONSE => {
                let Some(mut walk) = self.walks.remove(&message.request_id) else {
                    return;
                };
                let last = message.bindings.last().cloned();
                let more = match &last {
                    Some((oid, value)) => {
                        message.error_status == 0
                            && under(oid, &walk.root)
                            && !matches!(
                                value,
                                Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance
                            )
                    }
                    None => false,
                };
                if !more {
                    io.note(&format!("End of the walk: {} values.", walk.count));
                    return;
                }
                walk.count += 1;
                if walk.count >= LONGEST_WALK {
                    io.note(&format!("The walk stopped after {LONGEST_WALK} values."));
                    return;
                }
                if let Some((oid, _)) = last {
                    let id = self.request(GET_NEXT, vec![(oid, Value::Null)], (0, 0), io);
                    self.walks.insert(id, walk);
                }
            }
            _ => {}
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.next().unwrap_or_default().to_lowercase().as_str() {
                "get" => {
                    let bindings = Self::asked(words)?;
                    self.request(GET, bindings, (0, 0), io);
                }
                "next" | "getnext" => {
                    let bindings = Self::asked(words)?;
                    self.request(GET_NEXT, bindings, (0, 0), io);
                }
                "walk" => {
                    let root = match words.next() {
                        Some(word) => parse_oid(&word)?,
                        None => vec![1, 3, 6, 1, 2, 1],
                    };
                    let id = self.request(GET_NEXT, vec![(root.clone(), Value::Null)], (0, 0), io);
                    self.walks.insert(id, Walk { root, count: 0 });
                }
                "bulk" | "getbulk" => {
                    if self.version == 0 {
                        return Err("GetBulk is SNMPv2c's: set the version to 2c.".into());
                    }
                    let oid = parse_oid(&words.need("the OID to start after")?)?;
                    let count: i64 = words.number_or("how many values", 10)?;
                    self.request(GET_BULK, vec![(oid, Value::Null)], (0, count), io);
                }
                "set" => {
                    let oid = parse_oid(&words.need("the OID")?)?;
                    let kind = words.need("the type: i, u, c, t, s, x, a, o or n")?;
                    let value = Value::typed(&kind, &words.rest_text())?;
                    self.request(SET, vec![(oid, value)], (0, 0), io);
                }
                "community" => {
                    self.community = words.rest_text().trim().to_string();
                    io.note(&format!("It asks as \"{}\" now.", self.community));
                }
                "version" => {
                    let version = words.need("1 or 2c")?;
                    self.version = match version.as_str() {
                        "1" => 0,
                        "2" | "2c" => 1,
                        other => return Err(format!("{other} is not a version here: 1 or 2c.")),
                    };
                    io.note(&format!("It speaks SNMP {version} now."));
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

    fn tick(&mut self, now: Instant, _io: &mut Io) {
        // Answers that never came are forgotten.
        self.sent
            .retain(|_, sent| now.duration_since(*sent) < Duration::from_secs(60));
    }
}

// ----- The agent -----

/// An SNMP agent tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct AgentOptions {
    /// The community that reads.
    pub community: String,
    /// The community that writes too.
    pub write_community: String,
    pub name: String,
    pub location: String,
}

impl Default for AgentOptions {
    fn default() -> Self {
        Self {
            community: "public".into(),
            write_community: "private".into(),
            name: "netnima".into(),
            location: "bench".into(),
        }
    }
}

/// The enterprise number for documentation (RFC 5612), under which the
/// agent's own values are.
const EXAMPLE: [u32; 7] = [1, 3, 6, 1, 4, 1, 32473];

/// Answers managers from its own values: the system group, and a board's
/// temperature, LED and message under the example enterprise.
pub struct Agent {
    community: String,
    write_community: String,
    /// Each value, and whether a set may change it.
    mib: BTreeMap<Vec<u32>, (Value, bool)>,
    started: Instant,
    next_reading: Instant,
    next_id: i64,
}

impl Agent {
    pub fn new(options: AgentOptions) -> Self {
        let mut mib = BTreeMap::new();
        let system = |last: u32| vec![1, 3, 6, 1, 2, 1, 1, last, 0];
        let own = |last: u32| [&EXAMPLE[..], &[1, last, 0]].concat();
        let describe = format!(
            "netNIMA SNMP agent {} on {}",
            crate::VERSION,
            std::env::consts::OS
        );
        mib.insert(
            system(1),
            (Value::OctetString(describe.into_bytes()), false),
        );
        mib.insert(
            system(2),
            (Value::Oid([&EXAMPLE[..], &[1]].concat()), false),
        );
        mib.insert(system(3), (Value::TimeTicks(0), false));
        mib.insert(system(4), (Value::OctetString(Vec::new()), true));
        mib.insert(
            system(5),
            (Value::OctetString(options.name.into_bytes()), true),
        );
        mib.insert(
            system(6),
            (Value::OctetString(options.location.into_bytes()), true),
        );
        mib.insert(system(7), (Value::Integer(72), false));
        // Tenths of a degree, the LED, and a message.
        mib.insert(own(1), (Value::Gauge32(215), false));
        mib.insert(own(2), (Value::Integer(0), true));
        mib.insert(own(3), (Value::OctetString(b"hello".to_vec()), true));
        Self {
            community: options.community,
            write_community: options.write_community,
            mib,
            started: Instant::now(),
            next_reading: Instant::now() + Duration::from_secs(5),
            next_id: 1,
        }
    }

    fn uptime(&self) -> u32 {
        (self.started.elapsed().as_millis() / 10).min(u128::from(u32::MAX)) as u32
    }

    /// A value now: sysUpTime counts.
    fn value(&self, oid: &[u32]) -> Option<Value> {
        let (value, _) = self.mib.get(oid)?;
        Some(if *oid == [1, 3, 6, 1, 2, 1, 1, 3, 0] {
            Value::TimeTicks(self.uptime())
        } else {
            value.clone()
        })
    }

    /// The first variable after `oid`.
    fn after(&self, oid: &[u32]) -> Option<(Vec<u32>, Value)> {
        let (next, _) = self
            .mib
            .range::<[u32], _>((Bound::Excluded(oid), Bound::Unbounded))
            .next()?;
        Some((next.clone(), self.value(next)?))
    }

    /// The answer to a request, or none when its community is turned down.
    fn answer(&mut self, request: &Message, io: &mut Io) -> Option<Message> {
        let v1 = request.version == 0;
        let community = String::from_utf8_lossy(&request.community).into_owned();
        let writes = request.kind == SET;
        let allowed = community == self.write_community || (!writes && community == self.community);
        if !allowed {
            io.note(&format!(
                "The community \"{community}\" was turned down: no answer goes, as SNMP does."
            ));
            return None;
        }
        let mut answer = Message {
            kind: RESPONSE,
            error_status: 0,
            error_index: 0,
            bindings: Vec::new(),
            trap: None,
            ..request.clone()
        };
        let fail = |answer: &mut Message, status: i64, index: usize| {
            answer.error_status = status;
            answer.error_index = index as i64 + 1;
            answer.bindings = request.bindings.clone();
        };
        match request.kind {
            GET => {
                for (index, (oid, _)) in request.bindings.iter().enumerate() {
                    match self.value(oid) {
                        Some(value) => answer.bindings.push((oid.clone(), value)),
                        None if v1 => {
                            fail(&mut answer, 2, index);
                            break;
                        }
                        None => {
                            let object = self
                                .mib
                                .keys()
                                .any(|known| under(known, &oid[..oid.len().saturating_sub(1)]));
                            let missing = if object {
                                Value::NoSuchInstance
                            } else {
                                Value::NoSuchObject
                            };
                            answer.bindings.push((oid.clone(), missing));
                        }
                    }
                }
            }
            GET_NEXT => {
                for (index, (oid, _)) in request.bindings.iter().enumerate() {
                    match self.after(oid) {
                        Some(found) => answer.bindings.push(found),
                        None if v1 => {
                            fail(&mut answer, 2, index);
                            break;
                        }
                        None => answer.bindings.push((oid.clone(), Value::EndOfMibView)),
                    }
                }
            }
            GET_BULK if !v1 => {
                let non_repeaters = usize::try_from(request.error_status.max(0)).unwrap_or(0);
                let repetitions = usize::try_from(request.error_index.max(0))
                    .unwrap_or(0)
                    .min(50);
                let (single, repeated) = request
                    .bindings
                    .split_at(non_repeaters.min(request.bindings.len()));
                for (oid, _) in single {
                    let found = self
                        .after(oid)
                        .unwrap_or((oid.clone(), Value::EndOfMibView));
                    answer.bindings.push(found);
                }
                let mut cursors: Vec<Vec<u32>> =
                    repeated.iter().map(|(oid, _)| oid.clone()).collect();
                'rows: for _ in 0..repetitions {
                    let mut all_ended = true;
                    for cursor in &mut cursors {
                        match self.after(cursor) {
                            Some((oid, value)) => {
                                *cursor = oid.clone();
                                answer.bindings.push((oid, value));
                                all_ended = false;
                            }
                            None => answer.bindings.push((cursor.clone(), Value::EndOfMibView)),
                        }
                    }
                    if all_ended || answer.bindings.len() >= 60 {
                        break 'rows;
                    }
                }
            }
            SET => {
                // All are checked before any is set, as a set is all or none.
                for (index, (oid, value)) in request.bindings.iter().enumerate() {
                    let problem = match self.mib.get(oid) {
                        None => Some(if v1 { 2 } else { 17 }),
                        Some((_, false)) => Some(if v1 { 2 } else { 17 }),
                        Some((present, true)) if !present.same_kind(value) => {
                            Some(if v1 { 3 } else { 7 })
                        }
                        Some(_) => None,
                    };
                    if let Some(status) = problem {
                        fail(&mut answer, status, index);
                        return Some(answer);
                    }
                }
                for (oid, value) in &request.bindings {
                    if let Some(entry) = self.mib.get_mut(oid) {
                        entry.0 = value.clone();
                    }
                    io.note(&format!("{} = {}", oid_name(oid), value.describe()));
                }
                answer.bindings = request.bindings.clone();
            }
            _ => {
                // GetBulk in v1, or a PDU an agent does not take.
                fail(&mut answer, 5, 0);
            }
        }
        Some(answer)
    }

    /// Sends an SNMPv2-Trap: sysUpTime, snmpTrapOID, then the bindings given.
    fn trap(&mut self, trap: Vec<u32>, extra: Vec<(Vec<u32>, Value)>, io: &mut Io) {
        let mut bindings = vec![
            (
                vec![1, 3, 6, 1, 2, 1, 1, 3, 0],
                Value::TimeTicks(self.uptime()),
            ),
            (vec![1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0], Value::Oid(trap)),
        ];
        bindings.extend(extra);
        self.next_id += 1;
        let message = Message {
            version: 1,
            community: self.community.as_bytes().to_vec(),
            kind: TRAP_V2,
            request_id: self.next_id,
            error_status: 0,
            error_index: 0,
            bindings,
            trap: None,
        };
        io.went(0, &describe(&message));
        io.send(Target::Default, message.encode());
    }
}

const AGENT_HELP: &str = "mib                          its values
set <oid> <type> <value>     change one here, as a manager's set would: such as set 1.3.6.1.4.1.32473.1.1.0 u 300
trap [<oid> <type> <value>]  send an SNMPv2-Trap: coldStart, or with the value given
Its own values: 1.3.6.1.4.1.32473.1.1.0 the temperature in tenths of a degree, .2.0 a LED (0 or 1), .3.0 a message.
Traps go to the remote host above, or else to the manager heard from last.";

impl Engine for Agent {
    fn help(&self) -> &'static str {
        AGENT_HELP
    }

    fn joined(&mut self, _peer: &Peer, _io: &mut Io) {}

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let request = match Message::decode(bytes) {
            Ok(message) => message,
            Err(problem) => {
                io.bad(&format!("Not SNMP: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        io.came(peer, &describe(&request));
        if !matches!(request.kind, GET | GET_NEXT | GET_BULK | SET) {
            return;
        }
        if let Some(answer) = self.answer(&request, io) {
            io.went(peer, &describe(&answer));
            io.send(Target::Peer(peer), answer.encode());
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.next().unwrap_or_default().to_lowercase().as_str() {
                "mib" | "values" => {
                    let lines: Vec<String> = self
                        .mib
                        .keys()
                        .filter_map(|oid| {
                            let (_, writable) = self.mib.get(oid)?;
                            let value = self.value(oid)?;
                            Some(format!(
                                "{} = {}{}",
                                oid_name(oid),
                                value.describe(),
                                if *writable { "  (can be set)" } else { "" }
                            ))
                        })
                        .collect();
                    io.note(&lines.join("\n"));
                }
                "set" => {
                    let oid = parse_oid(&words.need("the OID")?)?;
                    let kind = words.need("the type: i, u, c, t, s, x, a, o or n")?;
                    let value = Value::typed(&kind, &words.rest_text())?;
                    let entry = self
                        .mib
                        .get_mut(&oid)
                        .ok_or(format!("It has no {}.", oid_name(&oid)))?;
                    entry.0 = value.clone();
                    io.note(&format!("{} = {}", oid_name(&oid), value.describe()));
                }
                "trap" => match words.next() {
                    None => self.trap(vec![1, 3, 6, 1, 6, 3, 1, 1, 5, 1], Vec::new(), io),
                    Some(word) => {
                        let oid = parse_oid(&word)?;
                        let kind = words.need("the type: i, u, c, t, s, x, a, o or n")?;
                        let value = Value::typed(&kind, &words.rest_text())?;
                        self.trap([&EXAMPLE[..], &[2]].concat(), vec![(oid, value)], io);
                    }
                },
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

    fn tick(&mut self, now: Instant, _io: &mut Io) {
        if now < self.next_reading {
            return;
        }
        self.next_reading = now + Duration::from_secs(5);
        // The temperature walks slowly between 18 and 28 degrees.
        let key = [&EXAMPLE[..], &[1, 1, 0]].concat();
        if let Some((Value::Gauge32(tenths), _)) = self.mib.get_mut(&key) {
            let step = (now.duration_since(self.started).as_millis() / 5000 % 7) as u32;
            *tenths = (*tenths + step).saturating_sub(3).clamp(180, 280);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{listening, shown, start, udp_on_loopback};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn ber_reads_back_as_it_was_written() {
        for value in [
            0,
            1,
            127,
            128,
            255,
            256,
            -1,
            -128,
            -129,
            i64::from(i32::MAX),
            i64::MIN,
        ] {
            assert_eq!(read_signed(&signed_bytes(value)), value, "{value}");
        }
        assert_eq!(unsigned_bytes(0x80), [0, 0x80]);
        assert_eq!(
            read_unsigned(&unsigned_bytes(u64::from(u32::MAX))),
            u64::from(u32::MAX)
        );
        let oid = vec![1, 3, 6, 1, 4, 1, 32473, 1, 300_000];
        assert_eq!(read_oid(&oid_bytes(&oid)).unwrap(), oid);
        // A v2c GetRequest for sysDescr.0 as public, its bytes worked out by
        // hand from BER's rules.
        let message = Message {
            version: 1,
            community: b"public".to_vec(),
            kind: GET,
            request_id: 0x1234,
            error_status: 0,
            error_index: 0,
            bindings: vec![(parse_oid("sysDescr.0").unwrap(), Value::Null)],
            trap: None,
        };
        let bytes = message.encode();
        assert_eq!(
            bytes,
            [
                0x30, 0x27, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
                0x1a, 0x02, 0x02, 0x12, 0x34, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
                0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
            ]
        );
        assert_eq!(Message::decode(&bytes).unwrap(), message);
        assert_eq!(
            oid_name(&parse_oid("1.3.6.1.2.1.1.5.0").unwrap()),
            "sysName.0"
        );
        assert_eq!(
            Value::TimeTicks(1_234_567).describe(),
            "Timeticks: (1234567) 3:25:45.67"
        );
    }

    #[test]
    fn a_manager_gets_walks_bulks_and_sets_on_the_agent() {
        let (agent, agent_events) = start(
            Box::new(Agent::new(AgentOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&agent_events);
        let (manager, manager_events) = start(
            Box::new(Manager::new(ManagerOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&manager_events);
        manager.command("get sysDescr.0 sysName.0");
        let text = shown(&manager_events, "sysName.0 = STRING: \"netnima\"");
        assert!(
            text.contains("sysDescr.0 = STRING: \"netNIMA SNMP agent"),
            "{text}"
        );
        manager.command("walk system");
        let text = shown(&manager_events, "End of the walk: 7 values.");
        assert!(text.contains("sysServices.0 = INTEGER: 72"), "{text}");
        manager.command("bulk 1.3.6.1.4.1.32473 5");
        shown(
            &manager_events,
            "enterprises.32473.1.3.0 = STRING: \"hello\"",
        );
        // public reads; only private sets.
        manager.command("set sysLocation.0 s lab 2");
        shown(&agent_events, "The community \"public\" was turned down");
        manager.command("community private");
        manager.command("set sysLocation.0 s lab 2");
        shown(&manager_events, "Response \"private\"");
        agent.command("mib");
        shown(
            &agent_events,
            "sysLocation.0 = STRING: \"lab 2\"  (can be set)",
        );
        manager.command("set sysDescr.0 s no");
        shown(&manager_events, "error notWritable at 1");
        manager.command("set 1.3.6.1.4.1.32473.1.2.0 s on");
        shown(&manager_events, "error wrongType at 1");
        manager.command("get 1.3.6.1.4.1.32473.1.9.0");
        shown(&manager_events, "No Such Object available");
        // v1: noSuchName, and a community that is turned down gets no answer.
        manager.command("version 1");
        manager.command("get 1.3.6.1.4.1.32473.1.9.0");
        shown(&manager_events, "error noSuchName at 1");
        manager.command("community nobody");
        manager.command("get sysName.0");
        shown(&agent_events, "The community \"nobody\" was turned down");
        // A trap goes to the manager heard from last.
        agent.command("trap 1.3.6.1.4.1.32473.1.2.0 i 1");
        shown(&manager_events, "SNMPv2-Trap");
    }
}
