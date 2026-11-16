//! STUN (RFC 8489) over UDP: a client that asks a server how it sees this
//! end, the address and port its NAT gives it, and a server that answers,
//! for a device that finds its outside address before it talks to peers.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::{Engine, Io, Words, hex_text};
use crate::net::{Peer, PeerId, Target};

const MAGIC: u32 = 0x2112_a442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const BINDING_INDICATION: u16 = 0x0011;

const MAPPED_ADDRESS: u16 = 0x0001;
const USERNAME: u16 = 0x0006;
const MESSAGE_INTEGRITY: u16 = 0x0008;
const ERROR_CODE: u16 = 0x0009;
const UNKNOWN_ATTRIBUTES: u16 = 0x000a;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const SOFTWARE: u16 = 0x8022;
const FINGERPRINT: u16 = 0x8028;
const RESPONSE_ORIGIN: u16 = 0x802b;
const OTHER_ADDRESS: u16 = 0x802c;

/// One STUN message: its type, transaction id and attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: u16,
    pub transaction: [u8; 12],
    pub attributes: Vec<(u16, Vec<u8>)>,
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for (kind, value) in &self.attributes {
            body.extend_from_slice(&kind.to_be_bytes());
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(value);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut out = self.kind.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.extend_from_slice(&self.transaction);
        out.extend(body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Message, String> {
        if bytes.len() < 20 {
            return Err("it is shorter than STUN's 20-byte header".into());
        }
        if bytes[0] & 0xc0 != 0 {
            return Err("its first two bits are not 0, as STUN's are".into());
        }
        if u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != MAGIC {
            return Err(
                "it has no magic cookie: it is not STUN, or it is RFC 3489's old form".into(),
            );
        }
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if bytes.len() < 20 + length {
            return Err(format!(
                "it says {length} bytes of attributes, and fewer came"
            ));
        }
        let mut transaction = [0u8; 12];
        transaction.copy_from_slice(&bytes[8..20]);
        let mut attributes = Vec::new();
        let mut at = 20;
        while at + 4 <= 20 + length {
            let kind = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
            let size = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
            let value = bytes
                .get(at + 4..at + 4 + size)
                .ok_or("an attribute is cut short")?;
            attributes.push((kind, value.to_vec()));
            at += 4 + size.div_ceil(4) * 4;
        }
        Ok(Message {
            kind: u16::from_be_bytes([bytes[0], bytes[1]]),
            transaction,
            attributes,
        })
    }

    fn attribute(&self, kind: u16) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|(found, _)| *found == kind)
            .map(|(_, value)| value.as_slice())
    }
}

/// An address as MAPPED-ADDRESS carries it; XORed with the cookie and the
/// transaction id as XOR-MAPPED-ADDRESS does, when `transaction` is given.
fn address_value(address: SocketAddr, transaction: Option<&[u8; 12]>) -> Vec<u8> {
    let mask: Vec<u8> = match transaction {
        Some(transaction) => [&MAGIC.to_be_bytes()[..], transaction].concat(),
        None => vec![0; 16],
    };
    let port = address.port() ^ u16::from_be_bytes([mask[0], mask[1]]);
    let mut out = vec![0];
    let octets: Vec<u8> = match address.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            ip.octets().to_vec()
        }
        IpAddr::V6(ip) => {
            out.push(2);
            ip.octets().to_vec()
        }
    };
    out.extend_from_slice(&port.to_be_bytes());
    out.extend(
        octets
            .iter()
            .zip(mask.iter())
            .map(|(byte, mask)| byte ^ mask),
    );
    out
}

fn read_address(value: &[u8], transaction: Option<&[u8; 12]>) -> Option<SocketAddr> {
    let mask: Vec<u8> = match transaction {
        Some(transaction) => [&MAGIC.to_be_bytes()[..], transaction].concat(),
        None => vec![0; 16],
    };
    let port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?])
        ^ u16::from_be_bytes([mask[0], mask[1]]);
    let bytes: Vec<u8> = value
        .get(4..)?
        .iter()
        .zip(mask.iter())
        .map(|(byte, mask)| byte ^ mask)
        .collect();
    let ip = match (value.get(1)?, bytes.len()) {
        (1, 4) => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        (2, 16) => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn kind_name(kind: u16) -> String {
    match kind {
        BINDING_REQUEST => "Binding Request".into(),
        BINDING_SUCCESS => "Binding Success".into(),
        BINDING_ERROR => "Binding Error".into(),
        BINDING_INDICATION => "Binding Indication".into(),
        other => format!("type {other:#06x}"),
    }
}

/// A message in lines: its type and transaction, then its attributes.
pub fn describe(message: &Message) -> String {
    let mut lines = vec![format!(
        "{} (transaction {})",
        kind_name(message.kind),
        hex_text(&message.transaction).replace(' ', "")
    )];
    for (kind, value) in &message.attributes {
        lines.push(match *kind {
            XOR_MAPPED_ADDRESS => format!(
                "XOR-MAPPED-ADDRESS {}",
                read_address(value, Some(&message.transaction))
                    .map_or_else(|| hex_text(value), |at| at.to_string())
            ),
            MAPPED_ADDRESS | RESPONSE_ORIGIN | OTHER_ADDRESS => format!(
                "{} {}",
                match *kind {
                    MAPPED_ADDRESS => "MAPPED-ADDRESS",
                    RESPONSE_ORIGIN => "RESPONSE-ORIGIN",
                    _ => "OTHER-ADDRESS",
                },
                read_address(value, None).map_or_else(|| hex_text(value), |at| at.to_string())
            ),
            SOFTWARE => format!("SOFTWARE {}", String::from_utf8_lossy(value)),
            USERNAME => format!("USERNAME {}", String::from_utf8_lossy(value)),
            ERROR_CODE if value.len() >= 4 => format!(
                "ERROR-CODE {}{:02}: {}",
                value[2] & 0x07,
                value[3],
                String::from_utf8_lossy(&value[4..])
            ),
            MESSAGE_INTEGRITY => "MESSAGE-INTEGRITY".into(),
            FINGERPRINT => "FINGERPRINT".into(),
            UNKNOWN_ATTRIBUTES => format!("UNKNOWN-ATTRIBUTES {}", hex_text(value)),
            other => format!("attribute {other:#06x}: {}", hex_text(value)),
        });
    }
    lines.join("\n")
}

fn transaction_id(counter: &mut u64) -> [u8; 12] {
    *counter = counter.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos() as u64);
    let mut id = [0u8; 12];
    id[..8].copy_from_slice(&(*counter ^ time).to_be_bytes());
    id[8..].copy_from_slice(&std::process::id().to_be_bytes());
    id
}

// ----- The client -----

/// Asks a STUN server how it sees this end.
pub struct Client {
    counter: u64,
    /// Requests out, by transaction id, with when each went.
    asked: HashMap<[u8; 12], Instant>,
    /// The address the last answer gave, to say when it changes.
    seen: Option<SocketAddr>,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            counter: u64::from(std::process::id()),
            asked: HashMap::new(),
            seen: None,
        }
    }
}

impl Client {
    fn ask(&mut self, io: &mut Io) {
        let transaction = transaction_id(&mut self.counter);
        let message = Message {
            kind: BINDING_REQUEST,
            transaction,
            attributes: vec![(SOFTWARE, format!("netNIMA {}", crate::VERSION).into_bytes())],
        };
        io.went(0, &describe(&message));
        io.send(Target::Default, message.encode());
        self.asked.insert(transaction, Instant::now());
    }
}

impl Engine for Client {
    fn help(&self) -> &'static str {
        "bind    ask the server how it sees this end: the address and port its NAT gives it
Set the STUN server as the remote host above: port 3478, or 19302 for some public ones."
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let message = match Message::decode(bytes) {
            Ok(message) => message,
            Err(problem) => {
                io.bad(&format!("Not STUN: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        io.came(peer, &describe(&message));
        let Some(sent) = self.asked.remove(&message.transaction) else {
            return;
        };
        let time = format!("{:.2} ms", sent.elapsed().as_secs_f64() * 1000.0);
        let seen = message
            .attribute(XOR_MAPPED_ADDRESS)
            .and_then(|value| read_address(value, Some(&message.transaction)))
            .or_else(|| {
                message
                    .attribute(MAPPED_ADDRESS)
                    .and_then(|value| read_address(value, None))
            });
        match (message.kind, seen) {
            (BINDING_SUCCESS, Some(at)) => {
                let changed = match self.seen {
                    Some(before) if before != at => {
                        format!(" It was {before} before: the NAT moved it.")
                    }
                    _ => String::new(),
                };
                io.note(&format!(
                    "The server sees this end at {at}, after {time}.{changed}"
                ));
                self.seen = Some(at);
            }
            (BINDING_SUCCESS, None) => io.bad("The answer has no address in it."),
            _ => io.bad(&format!(
                "The server turned the request down, after {time}."
            )),
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "bind" | "" => self.ask(io),
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        let before = self.asked.len();
        self.asked
            .retain(|_, sent| now.duration_since(*sent) < Duration::from_secs(3));
        if self.asked.len() < before {
            io.bad("No answer came within 3 s: is a STUN server at the remote address?");
        }
    }
}

// ----- The server -----

/// Answers Binding Requests with the address each came from.
#[derive(Default)]
pub struct Server {
    /// Each peer's address, to answer with.
    addresses: BTreeMap<PeerId, SocketAddr>,
    answered: u64,
}

impl Engine for Server {
    fn help(&self) -> &'static str {
        "It answers each Binding Request with the address and port it came from.
stats    how many it has answered"
    }

    fn joined(&mut self, peer: &Peer, _io: &mut Io) {
        if let Ok(address) = peer.address.parse() {
            self.addresses.insert(peer.id, address);
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let request = match Message::decode(bytes) {
            Ok(message) => message,
            Err(problem) => {
                io.bad(&format!("Not STUN: {problem}: {}", hex_text(bytes)));
                return;
            }
        };
        io.came(peer, &describe(&request));
        if request.kind != BINDING_REQUEST {
            return;
        }
        let Some(address) = self.addresses.get(&peer).copied() else {
            return;
        };
        let answer = Message {
            kind: BINDING_SUCCESS,
            transaction: request.transaction,
            attributes: vec![
                (
                    XOR_MAPPED_ADDRESS,
                    address_value(address, Some(&request.transaction)),
                ),
                (MAPPED_ADDRESS, address_value(address, None)),
                (SOFTWARE, format!("netNIMA {}", crate::VERSION).into_bytes()),
            ],
        };
        io.went(peer, &describe(&answer));
        io.send(Target::Peer(peer), answer.encode());
        self.answered += 1;
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "stats" => io.note(&format!(
                "It has answered {} Binding Requests.",
                self.answered
            )),
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{listening, shown, start, udp_on_loopback};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn addresses_read_back_xored_or_not() {
        let transaction = [7u8; 12];
        for address in ["192.0.2.1:32853", "[2001:db8::1]:40000"] {
            let address: SocketAddr = address.parse().unwrap();
            for xored in [None, Some(&transaction)] {
                assert_eq!(
                    read_address(&address_value(address, xored), xored),
                    Some(address)
                );
            }
        }
        // RFC 5769's sample response: XOR-MAPPED-ADDRESS 192.0.2.1:32853.
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        assert_eq!(
            read_address(&value, Some(&[0; 12])),
            Some("192.0.2.1:32853".parse().unwrap())
        );
        let message = Message {
            kind: BINDING_REQUEST,
            transaction,
            attributes: vec![(SOFTWARE, b"abc".to_vec())],
        };
        let bytes = message.encode();
        assert_eq!(bytes.len(), 20 + 8, "padded to 4 bytes");
        assert_eq!(Message::decode(&bytes).unwrap(), message);
    }

    #[test]
    fn a_client_learns_how_the_server_sees_it() {
        let (server, server_events) = start(
            Box::new(Server::default()),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::default()),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        let local = listening(&client_events);
        client.command("bind");
        shown(
            &client_events,
            &format!("The server sees this end at 127.0.0.1:{local}"),
        );
        server.command("stats");
        shown(&server_events, "It has answered 1 Binding Requests.");
    }
}
