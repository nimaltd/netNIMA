//! DHCP: a server that gives addresses from a pool, for a board wired
//! straight to the PC, and a client that asks a server for one, to test it.
//! The client only shows what it was offered: it never sets the PC's address.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{Engine, Io, Words, hex_text};
use crate::net::{PeerId, Target};

const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const DECLINE: u8 = 4;
const ACK: u8 = 5;
const NAK: u8 = 6;
const RELEASE: u8 = 7;
const INFORM: u8 = 8;

const COOKIE: [u8; 4] = [99, 130, 83, 99];

fn kind_name(kind: u8) -> &'static str {
    match kind {
        DISCOVER => "DISCOVER",
        OFFER => "OFFER",
        REQUEST => "REQUEST",
        DECLINE => "DECLINE",
        ACK => "ACK",
        NAK => "NAK",
        RELEASE => "RELEASE",
        INFORM => "INFORM",
        _ => "DHCP message",
    }
}

/// One DHCP (BOOTP) message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// 1 from a client, 2 from a server.
    pub op: u8,
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub mac: [u8; 6],
    /// Options by number, in order.
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            op: 0,
            xid: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            mac: [0; 6],
            options: Vec::new(),
        }
    }
}

impl Message {
    pub fn option(&self, number: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(found, _)| *found == number)
            .map(|(_, value)| value.as_slice())
    }

    pub fn kind(&self) -> u8 {
        self.option(53)
            .and_then(|value| value.first().copied())
            .unwrap_or(0)
    }

    fn address_option(&self, number: u8) -> Option<Ipv4Addr> {
        self.option(number)
            .filter(|value| value.len() >= 4)
            .map(|value| Ipv4Addr::new(value[0], value[1], value[2], value[3]))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.op, 1, 6, 0];
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.flags.to_be_bytes());
        for address in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            out.extend_from_slice(&address.octets());
        }
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(&[0; 64 + 128]);
        out.extend_from_slice(&COOKIE);
        for (number, value) in &self.options {
            out.push(*number);
            out.push(value.len().min(255) as u8);
            out.extend_from_slice(&value[..value.len().min(255)]);
        }
        out.push(255);
        // BOOTP's least size, which some clients still want.
        while out.len() < 300 {
            out.push(0);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 240 {
            return Err(format!("{} bytes is too short for DHCP", bytes.len()));
        }
        if bytes[236..240] != COOKIE {
            return Err("it has no DHCP magic cookie".into());
        }
        let address =
            |at: usize| Ipv4Addr::new(bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]);
        let mut message = Message {
            op: bytes[0],
            xid: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            flags: u16::from_be_bytes([bytes[10], bytes[11]]),
            ciaddr: address(12),
            yiaddr: address(16),
            siaddr: address(20),
            giaddr: address(24),
            mac: bytes[28..34].try_into().unwrap_or_default(),
            options: Vec::new(),
        };
        let mut at = 240;
        while at < bytes.len() {
            match bytes[at] {
                0 => at += 1,
                255 => break,
                number => {
                    let length = usize::from(*bytes.get(at + 1).ok_or("an option is cut short")?);
                    let value = bytes
                        .get(at + 2..at + 2 + length)
                        .ok_or("an option is cut short")?;
                    message.options.push((number, value.to_vec()));
                    at += 2 + length;
                }
            }
        }
        Ok(message)
    }
}

fn mac_text(mac: &[u8]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn addresses_text(value: &[u8]) -> String {
    value
        .chunks(4)
        .filter(|chunk| chunk.len() == 4)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A message in one line, with the options people look for under it.
pub fn describe(message: &Message) -> String {
    let mut line = format!(
        "{} (xid {:#010x}) {} {}",
        kind_name(message.kind()),
        message.xid,
        if message.op == 1 { "from" } else { "for" },
        mac_text(&message.mac)
    );
    if !message.yiaddr.is_unspecified() {
        line.push_str(&format!(", address {}", message.yiaddr));
    }
    if !message.ciaddr.is_unspecified() {
        line.push_str(&format!(", client {}", message.ciaddr));
    }
    let mut details = Vec::new();
    for (number, value) in &message.options {
        let text = match number {
            53 | 55 | 61 => continue,
            1 => format!("mask {}", addresses_text(value)),
            3 => format!("router {}", addresses_text(value)),
            6 => format!("DNS {}", addresses_text(value)),
            12 => format!("host {}", String::from_utf8_lossy(value)),
            15 => format!("domain {}", String::from_utf8_lossy(value)),
            50 => format!("asks for {}", addresses_text(value)),
            51 if value.len() == 4 => format!(
                "lease {} s",
                u32::from_be_bytes([value[0], value[1], value[2], value[3]])
            ),
            54 => format!("server {}", addresses_text(value)),
            56 => format!("says {:?}", String::from_utf8_lossy(value)),
            60 => format!("vendor {}", String::from_utf8_lossy(value)),
            other => format!("option {other}: {}", hex_text(value)),
        };
        details.push(text);
    }
    if !details.is_empty() {
        line.push('\n');
        line.push_str(&details.join(", "));
    }
    line
}

// ----- The server -----

/// A DHCP server tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ServerOptions {
    /// The server's own address, which clients answer to; it should be the
    /// PC's address on the board's network.
    pub server: String,
    /// The first address it gives.
    pub first: String,
    /// How many addresses it gives.
    pub count: u32,
    pub mask: String,
    /// The router clients use; empty for none.
    pub router: String,
    /// The DNS server clients use; empty for none.
    pub dns: String,
    /// How long a lease lasts, in seconds.
    pub lease: u32,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            server: "192.168.137.1".into(),
            first: "192.168.137.100".into(),
            count: 50,
            mask: "255.255.255.0".into(),
            router: String::new(),
            dns: String::new(),
            lease: 3600,
        }
    }
}

struct Lease {
    address: Ipv4Addr,
    host: String,
    until: Option<Instant>,
}

/// Gives addresses from a pool.
pub struct Server {
    server: Ipv4Addr,
    first: Ipv4Addr,
    count: u32,
    mask: Ipv4Addr,
    router: Option<Ipv4Addr>,
    dns: Option<Ipv4Addr>,
    lease: u32,
    leases: BTreeMap<[u8; 6], Lease>,
    problem: Option<String>,
}

impl Server {
    pub fn new(options: ServerOptions) -> Self {
        let parse = |text: &str| text.trim().parse::<Ipv4Addr>().ok();
        let mut problem = None;
        let mut need = |text: &str, what: &str| {
            parse(text).unwrap_or_else(|| {
                problem.get_or_insert(format!("{text} is not an IPv4 address for {what}."));
                Ipv4Addr::UNSPECIFIED
            })
        };
        let server = need(&options.server, "the server");
        let first = need(&options.first, "the first address");
        let mask = need(&options.mask, "the mask");
        Self {
            server,
            first,
            count: options.count.clamp(1, 1000),
            mask,
            router: parse(&options.router),
            dns: parse(&options.dns),
            lease: options.lease.max(60),
            leases: BTreeMap::new(),
            problem,
        }
    }

    fn pool(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        let first = u32::from(self.first);
        (0..self.count).map(move |index| Ipv4Addr::from(first.wrapping_add(index)))
    }

    fn in_pool(&self, address: Ipv4Addr) -> bool {
        let at = u32::from(address).wrapping_sub(u32::from(self.first));
        at < self.count
    }

    fn taken(&self, address: Ipv4Addr, by: &[u8; 6]) -> bool {
        self.leases
            .iter()
            .any(|(mac, lease)| mac != by && lease.address == address)
    }

    /// The address for a client: its lease, what it asks for if free, or the first free.
    fn address_for(&self, mac: &[u8; 6], asked: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(lease) = self.leases.get(mac) {
            return Some(lease.address);
        }
        if let Some(asked) = asked.filter(|asked| self.in_pool(*asked) && !self.taken(*asked, mac))
        {
            return Some(asked);
        }
        self.pool()
            .find(|address| !self.taken(*address, mac) && *address != self.server)
    }

    fn reply(&self, request: &Message, kind: u8, address: Ipv4Addr) -> Message {
        let mut options = vec![(53, vec![kind]), (54, self.server.octets().to_vec())];
        if kind != NAK {
            if kind != ACK || !address.is_unspecified() {
                options.push((51, self.lease.to_be_bytes().to_vec()));
            }
            options.push((1, self.mask.octets().to_vec()));
            if let Some(router) = self.router {
                options.push((3, router.octets().to_vec()));
            }
            if let Some(dns) = self.dns {
                options.push((6, dns.octets().to_vec()));
            }
        }
        Message {
            op: 2,
            xid: request.xid,
            flags: request.flags,
            ciaddr: request.ciaddr,
            yiaddr: address,
            siaddr: self.server,
            giaddr: request.giaddr,
            mac: request.mac,
            options,
        }
    }
}

impl Engine for Server {
    fn help(&self) -> &'static str {
        "It gives addresses from its pool to the clients that ask.
leases            the addresses given
forget <MAC>      drop a client's lease"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let request = match Message::decode(bytes) {
            Ok(request) if request.op == 1 => request,
            Ok(_) => return,
            Err(problem) => {
                io.bad(&format!("Not DHCP: {problem}."));
                return;
            }
        };
        io.came(peer, &describe(&request));
        if let Some(problem) = &self.problem {
            io.bad(problem);
            return;
        }
        let asked = request
            .address_option(50)
            .or((!request.ciaddr.is_unspecified()).then_some(request.ciaddr));
        let host = request
            .option(12)
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .unwrap_or_default();
        let reply = match request.kind() {
            DISCOVER => match self.address_for(&request.mac, asked) {
                Some(address) => self.reply(&request, OFFER, address),
                None => {
                    io.bad("The pool has no address left.");
                    return;
                }
            },
            REQUEST => {
                // To another server: not for this one.
                if request
                    .address_option(54)
                    .is_some_and(|server| server != self.server)
                {
                    self.leases.remove(&request.mac);
                    return;
                }
                match asked {
                    Some(address)
                        if self.in_pool(address) && !self.taken(address, &request.mac) =>
                    {
                        self.leases.insert(
                            request.mac,
                            Lease {
                                address,
                                host,
                                until: Some(
                                    Instant::now() + Duration::from_secs(u64::from(self.lease)),
                                ),
                            },
                        );
                        self.reply(&request, ACK, address)
                    }
                    _ => self.reply(&request, NAK, Ipv4Addr::UNSPECIFIED),
                }
            }
            INFORM => self.reply(&request, ACK, Ipv4Addr::UNSPECIFIED),
            RELEASE | DECLINE => {
                self.leases.remove(&request.mac);
                return;
            }
            _ => return,
        };
        io.went(0, &describe(&reply));
        io.send(Target::Default, reply.encode());
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "leases" => {
                if self.leases.is_empty() {
                    io.note("No address is given yet.");
                }
                let lines: Vec<String> = self
                    .leases
                    .iter()
                    .map(|(mac, lease)| {
                        let left = lease
                            .until
                            .map(|until| until.saturating_duration_since(Instant::now()).as_secs())
                            .unwrap_or(0);
                        format!(
                            "{} {} {} ({left} s left)",
                            lease.address,
                            mac_text(mac),
                            lease.host
                        )
                    })
                    .collect();
                for line in lines {
                    io.note(&line);
                }
            }
            "forget" => {
                let word = words.next().unwrap_or_default();
                let before = self.leases.len();
                self.leases
                    .retain(|mac, _| !mac_text(mac).eq_ignore_ascii_case(&word.replace('-', ":")));
                if self.leases.len() < before {
                    io.note(&format!("{word} has no lease now."));
                } else {
                    io.bad(&format!("No lease for {word}."));
                }
            }
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }

    fn tick(&mut self, now: Instant, _io: &mut Io) {
        self.leases
            .retain(|_, lease| lease.until.is_none_or(|until| until > now));
    }
}

// ----- The client -----

/// A DHCP client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// The MAC address it asks for: empty for one made up.
    pub mac: String,
    pub host: String,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            mac: String::new(),
            host: "netnima".into(),
        }
    }
}

/// Asks DHCP servers for an address, and shows the answers.
pub struct Client {
    mac: [u8; 6],
    host: String,
    xid: u32,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        let digits: String = options
            .mac
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(7, |since| since.subsec_nanos());
        let mac = if digits.len() == 12 {
            let mut mac = [0u8; 6];
            for (index, byte) in mac.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).unwrap_or(0);
            }
            mac
        } else {
            // A locally administered address, so it is no real card's.
            let bytes = nanos.to_be_bytes();
            [0x02, 0x6e, bytes[0], bytes[1], bytes[2], bytes[3]]
        };
        Self {
            mac,
            host: options.host,
            xid: nanos,
        }
    }

    fn message(&self, kind: u8, extra: Vec<(u8, Vec<u8>)>) -> Message {
        let mut options = vec![
            (53, vec![kind]),
            (61, [vec![1], self.mac.to_vec()].concat()),
        ];
        if !self.host.is_empty() {
            options.push((12, self.host.as_bytes().to_vec()));
        }
        options.extend(extra);
        options.push((55, vec![1, 3, 6, 15, 51, 54]));
        Message {
            op: 1,
            xid: self.xid,
            // Asks for broadcast answers: it has no address yet.
            flags: 0x8000,
            mac: self.mac,
            options,
            ..Message::default()
        }
    }

    fn send(&self, message: Message, io: &mut Io) {
        io.went(0, &describe(&message));
        io.send(Target::Default, message.encode());
    }
}

impl Engine for Client {
    fn help(&self) -> &'static str {
        "discover      ask the servers for an address: it takes the first offer and asks for it
release       give the address back
It only shows what it is given: the PC's own address does not change."
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let message = match Message::decode(bytes) {
            Ok(message) if message.op == 2 && message.mac == self.mac => message,
            Ok(_) => return,
            Err(problem) => {
                io.bad(&format!("Not DHCP: {problem}."));
                return;
            }
        };
        io.came(peer, &describe(&message));
        match message.kind() {
            OFFER => {
                let mut extra = vec![(50, message.yiaddr.octets().to_vec())];
                if let Some(server) = message.option(54) {
                    extra.push((54, server.to_vec()));
                }
                let request = self.message(REQUEST, extra);
                self.send(request, io);
            }
            ACK => io.note(&format!("{} is this client's for now.", message.yiaddr)),
            NAK => io.bad("The server said no: discover again."),
            _ => {}
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "discover" => {
                self.xid = self.xid.wrapping_add(1);
                let message = self.message(DISCOVER, Vec::new());
                self.send(message, io);
            }
            "release" => {
                let message = self.message(RELEASE, Vec::new());
                self.send(message, io);
            }
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
    fn messages_read_back_as_they_were_written() {
        let message = Message {
            op: 1,
            xid: 0x1234_5678,
            flags: 0x8000,
            mac: [2, 0, 0, 0, 0, 1],
            options: vec![(53, vec![DISCOVER]), (12, b"board".to_vec())],
            ..Message::default()
        };
        let bytes = message.encode();
        assert_eq!(bytes.len(), 300);
        assert_eq!(Message::decode(&bytes).unwrap(), message);
        assert!(describe(&message).starts_with("DISCOVER (xid 0x12345678) from 02:00:00:00:00:01"));
    }

    #[test]
    fn a_client_gets_an_address_from_the_server() {
        let (server, server_events) = start(
            Box::new(Server::new(ServerOptions {
                router: "192.168.137.1".into(),
                ..ServerOptions::default()
            })),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions {
                mac: "02:00:00:00:00:07".into(),
                host: "board".into(),
            })),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&client_events);
        client.command("discover");
        let text = shown(&client_events, "192.168.137.100 is this client's for now.");
        assert!(text.contains("OFFER"), "{text}");
        assert!(text.contains("router 192.168.137.1"), "{text}");
        server.command("leases");
        shown(&server_events, "192.168.137.100 02:00:00:00:00:07 board");
    }
}
