//! Finding devices: mDNS / DNS-SD, to browse the services on the network
//! and advertise one of our own, and SSDP, UPnP's search and its answer.
//!
//! Both run on UDP multicast: mDNS on 224.0.0.251 port 5353, SSDP on
//! 239.255.255.250 port 1900, with the port shared with the OS's own
//! responder.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::services::{describe_dns, put_name, rdata_text, read_name, type_name};
use super::{Engine, Io, Words, hex_text};
use crate::net::{PeerId, Target};

const PTR: u16 = 12;
const TXT: u16 = 16;
const SRV: u16 = 33;
const A: u16 = 1;
const ANY: u16 = 255;
/// The class of a record whose owner is the only one with that name, "cache flush".
const UNIQUE: u16 = 0x8001;

/// One record of a DNS message.
struct Record {
    name: String,
    kind: u16,
    /// Its data, and where it starts in the message, for names inside it.
    data: Vec<u8>,
    start: usize,
}

/// A DNS message's flags, questions (name and type), and records of every section.
struct Parsed {
    flags: u16,
    questions: Vec<(String, u16, bool)>,
    records: Vec<Record>,
}

fn parse(message: &[u8]) -> Result<Parsed, String> {
    if message.len() < 12 {
        return Err("it is shorter than DNS's 12-byte header".into());
    }
    let count = |index: usize| {
        usize::from(u16::from_be_bytes([
            message[4 + index * 2],
            message[5 + index * 2],
        ]))
    };
    let mut at = 12;
    let mut questions = Vec::new();
    for _ in 0..count(0) {
        let (name, after) = read_name(message, at)?;
        let fields = message
            .get(after..after + 4)
            .ok_or("a question is cut short")?;
        let kind = u16::from_be_bytes([fields[0], fields[1]]);
        // The top bit of the class asks for an answer sent straight back (QU).
        let unicast = fields[2] & 0x80 != 0;
        questions.push((name, kind, unicast));
        at = after + 4;
    }
    let mut records = Vec::new();
    for _ in 0..count(1) + count(2) + count(3) {
        let (name, after) = read_name(message, at)?;
        let header = message
            .get(after..after + 10)
            .ok_or("a record is cut short")?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let start = after + 10;
        let data = message
            .get(start..start + length)
            .ok_or("a record's data is cut short")?
            .to_vec();
        records.push(Record {
            name,
            kind,
            data,
            start,
        });
        at = start + length;
    }
    Ok(Parsed {
        flags: u16::from_be_bytes([message[2], message[3]]),
        questions,
        records,
    })
}

/// "_http._tcp" as mDNS names it: "_http._tcp.local".
fn local_name(name: &str) -> String {
    let name = name.trim().trim_end_matches('.');
    if name.ends_with(".local") {
        name.to_string()
    } else {
        format!("{name}.local")
    }
}

/// The PC's own IPv4 addresses, not the loopback, for A records.
fn own_addresses() -> Vec<Ipv4Addr> {
    let mut found: Vec<Ipv4Addr> = crate::net::interfaces()
        .iter()
        .filter(|interface| interface.up)
        .flat_map(|interface| interface.ipv4.iter())
        .filter_map(|address| address.parse::<Ipv4Addr>().ok())
        .filter(|ip| !ip.is_loopback() && !ip.is_link_local())
        .collect();
    found.sort();
    found.dedup();
    if found.is_empty() {
        found.push(Ipv4Addr::LOCALHOST);
    }
    found
}

fn put_record(out: &mut Vec<u8>, name: &str, kind: u16, class: u16, ttl: u32, data: &[u8]) {
    put_name(out, name);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// A query for `name`, of type `kind`, as mDNS sends it: id 0.
fn query(name: &str, kind: u16) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    put_name(&mut out, name);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out
}

// ----- mDNS browse -----

/// What was found of one service instance.
#[derive(Default)]
struct Found {
    host: String,
    port: u16,
    txt: String,
}

/// Browses the services on the network.
#[derive(Default)]
pub struct MdnsBrowser {
    found: BTreeMap<String, Found>,
    /// Hosts and their addresses.
    hosts: BTreeMap<String, Vec<String>>,
    queries_heard: u64,
}

impl Engine for MdnsBrowser {
    fn help(&self) -> &'static str {
        "browse [type]       the services of a type, such as browse _http._tcp; with none, the types there are
resolve <instance>  an instance's host, port and text, such as resolve Kitchen._http._tcp
a <host>            a host's address, such as a esp32.local
found               what was found so far"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Ok(parsed) = parse(bytes) else {
            io.bad(&format!("Not an mDNS message: {}", hex_text(bytes)));
            return;
        };
        // Others' questions are many: only answers are shown.
        if parsed.flags & 0x8000 == 0 {
            self.queries_heard += 1;
            return;
        }
        for record in &parsed.records {
            match record.kind {
                SRV if record.data.len() > 6 => {
                    let port = u16::from_be_bytes([record.data[4], record.data[5]]);
                    let host = read_name(bytes, record.start + 6)
                        .map(|(name, _)| name)
                        .unwrap_or_default();
                    let entry = self.found.entry(record.name.clone()).or_default();
                    entry.host = host;
                    entry.port = port;
                }
                TXT => {
                    self.found.entry(record.name.clone()).or_default().txt =
                        rdata_text(bytes, TXT, record.start, &record.data);
                }
                PTR => {
                    if let Ok((target, _)) = read_name(bytes, record.start)
                        && !record.name.starts_with("_services.")
                    {
                        self.found.entry(target).or_default();
                    }
                }
                A | 28 => {
                    let address = rdata_text(bytes, record.kind, record.start, &record.data);
                    let addresses = self.hosts.entry(record.name.clone()).or_default();
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                _ => {}
            }
        }
        match describe_dns(bytes) {
            Ok(text) => io.came(peer, &text),
            Err(problem) => io.bad(&format!("An mDNS answer cannot be read: {problem}")),
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let command = words.next().unwrap_or_default().to_lowercase();
        let (name, kind) = match command.as_str() {
            "browse" => {
                let service = words
                    .next()
                    .unwrap_or_else(|| "_services._dns-sd._udp".into());
                (local_name(&service), PTR)
            }
            "resolve" => match words.next() {
                Some(instance) => (local_name(&instance), ANY),
                None => {
                    io.bad("Missing: the instance, such as Kitchen._http._tcp.");
                    return;
                }
            },
            "a" => match words.next() {
                Some(host) => (local_name(&host), A),
                None => {
                    io.bad("Missing: the host, such as esp32.local.");
                    return;
                }
            },
            "found" => {
                if self.found.is_empty() {
                    io.note(&format!(
                        "Nothing found yet. Questions heard from others: {}.",
                        self.queries_heard
                    ));
                }
                let lines: Vec<String> = self
                    .found
                    .iter()
                    .map(|(name, found)| {
                        let addresses = self
                            .hosts
                            .get(&found.host)
                            .map(|list| list.join(", "))
                            .unwrap_or_default();
                        format!(
                            "{name}: {}:{}{}{}",
                            if found.host.is_empty() {
                                "?"
                            } else {
                                &found.host
                            },
                            found.port,
                            if addresses.is_empty() {
                                String::new()
                            } else {
                                format!(" ({addresses})")
                            },
                            if found.txt.is_empty() {
                                String::new()
                            } else {
                                format!(" {}", found.txt)
                            }
                        )
                    })
                    .collect();
                for line in lines {
                    io.note(&line);
                }
                return;
            }
            other => {
                io.bad(&format!(
                    "{other} is not a command here. Type help for the list."
                ));
                return;
            }
        };
        io.went(0, &format!("query {} {name}", type_name(kind)));
        io.send(Target::Default, query(&name, kind));
    }
}

// ----- mDNS advertise -----

/// An mDNS advertise tab's settings: the service it says it has.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct AdvertiseOptions {
    pub instance: String,
    /// Such as "_http._tcp" or "_coap._udp".
    pub service: String,
    pub port: u16,
    /// Text, as "key=value" with semicolons between.
    pub txt: String,
    /// The host's name, without .local.
    pub host: String,
}

impl Default for AdvertiseOptions {
    fn default() -> Self {
        Self {
            instance: "netNIMA".into(),
            service: "_netnima._udp".into(),
            port: 5683,
            txt: "version=1".into(),
            host: "netnima".into(),
        }
    }
}

/// Answers mDNS questions about one service of our own.
pub struct MdnsAdvertiser {
    service: String,
    instance: String,
    host: String,
    port: u16,
    txt: Vec<String>,
    announced: u32,
    next_announce: Instant,
}

impl MdnsAdvertiser {
    pub fn new(options: AdvertiseOptions) -> Self {
        let service = local_name(&options.service);
        Self {
            instance: format!("{}.{service}", options.instance.trim()),
            host: local_name(&options.host),
            service,
            port: options.port,
            txt: options
                .txt
                .split(';')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect(),
            announced: 0,
            next_announce: Instant::now(),
        }
    }

    /// The answer to a question, with what goes with it: our records that match.
    fn answer(&self, name: &str, kind: u16) -> Option<Vec<u8>> {
        let name = name.to_lowercase();
        let ptr = (name == self.service.to_lowercase() && (kind == PTR || kind == ANY))
            || (name == "_services._dns-sd._udp.local" && kind == PTR);
        let instance = name == self.instance.to_lowercase() && matches!(kind, SRV | TXT | ANY);
        let host = name == self.host.to_lowercase() && matches!(kind, A | ANY);
        if !(ptr || instance || host) {
            return None;
        }
        if name == "_services._dns-sd._udp.local" {
            let mut data = Vec::new();
            put_name(&mut data, &self.service);
            return Some(self.message(&[(name.clone(), PTR, 1, 4500, data)]));
        }
        Some(self.message(&self.all_records()))
    }

    /// PTR, SRV, TXT and A: everything about the service.
    fn all_records(&self) -> Vec<(String, u16, u16, u32, Vec<u8>)> {
        let mut records = Vec::new();
        let mut ptr = Vec::new();
        put_name(&mut ptr, &self.instance);
        records.push((self.service.clone(), PTR, 1, 4500, ptr));
        let mut srv = vec![0, 0, 0, 0];
        srv.extend_from_slice(&self.port.to_be_bytes());
        put_name(&mut srv, &self.host);
        records.push((self.instance.clone(), SRV, UNIQUE, 120, srv));
        let mut txt = Vec::new();
        for item in &self.txt {
            let bytes = &item.as_bytes()[..item.len().min(255)];
            txt.push(bytes.len() as u8);
            txt.extend_from_slice(bytes);
        }
        if txt.is_empty() {
            txt.push(0);
        }
        records.push((self.instance.clone(), TXT, UNIQUE, 4500, txt));
        for address in own_addresses() {
            records.push((self.host.clone(), A, UNIQUE, 120, address.octets().to_vec()));
        }
        records
    }

    fn message(&self, records: &[(String, u16, u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0, 0, 0x84, 0, 0, 0];
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        for (name, kind, class, ttl, data) in records {
            put_record(&mut out, name, *kind, *class, *ttl, data);
        }
        out
    }

    fn announce(&mut self, io: &mut Io) {
        let message = self.message(&self.all_records());
        io.went(0, &describe_dns(&message).unwrap_or_default());
        io.send(Target::Default, message);
    }
}

impl Engine for MdnsAdvertiser {
    fn help(&self) -> &'static str {
        "It answers the questions about its service, and says it is there when it starts.
announce     say it again"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Ok(parsed) = parse(bytes) else {
            return;
        };
        if parsed.flags & 0x8000 != 0 {
            return;
        }
        for (name, kind, unicast) in parsed.questions {
            if let Some(answer) = self.answer(&name, kind) {
                io.came(
                    peer,
                    &format!(
                        "query {} {name}{}",
                        type_name(kind),
                        if unicast {
                            " (answer straight back)"
                        } else {
                            ""
                        }
                    ),
                );
                io.went(peer, &describe_dns(&answer).unwrap_or_default());
                io.send(
                    if unicast {
                        Target::Peer(peer)
                    } else {
                        Target::Default
                    },
                    answer,
                );
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "announce" => self.announce(io),
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        // Twice at the start, a second apart, as mDNS says.
        if self.announced < 2 && now >= self.next_announce {
            self.announced += 1;
            self.next_announce = now + Duration::from_secs(1);
            self.announce(io);
        }
    }
}

// ----- SSDP -----

/// An SSDP message: its first line and its headers.
fn ssdp_parse(bytes: &[u8]) -> Option<(String, BTreeMap<String, String>)> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n");
    let start = lines.next()?.trim().to_string();
    if start.is_empty() {
        return None;
    }
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_uppercase(), value.trim().to_string()))
        .collect();
    Some((start, headers))
}

fn ssdp_describe(start: &str, headers: &BTreeMap<String, String>) -> String {
    let get = |name: &str| headers.get(name).cloned().unwrap_or_default();
    if start.starts_with("M-SEARCH") {
        format!("M-SEARCH for {} (MX {})", get("ST"), get("MX"))
    } else if start.starts_with("NOTIFY") {
        format!(
            "NOTIFY {} {} at {} ({})",
            get("NTS"),
            get("NT"),
            get("LOCATION"),
            get("SERVER")
        )
    } else {
        format!(
            "{start}: {} at {}\nSERVER: {}\nUSN: {}",
            get("ST"),
            get("LOCATION"),
            get("SERVER"),
            get("USN")
        )
    }
}

/// Searches for UPnP devices and services.
#[derive(Default)]
pub struct SsdpSearch {
    found: BTreeMap<String, String>,
}

impl Engine for SsdpSearch {
    fn help(&self) -> &'static str {
        "search [ST] [MX]   search, ssdp:all unless told, such as search upnp:rootdevice
found              what answered so far"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        match ssdp_parse(bytes) {
            Some((start, headers)) => {
                if let (Some(usn), Some(location)) = (headers.get("USN"), headers.get("LOCATION")) {
                    self.found.insert(usn.clone(), location.clone());
                }
                if !start.starts_with("M-SEARCH") {
                    io.came(peer, &ssdp_describe(&start, &headers));
                }
            }
            None => io.bad(&format!("Not SSDP: {}", hex_text(bytes))),
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "search" => {
                let target = words.next().unwrap_or_else(|| "ssdp:all".into());
                let wait: u8 = words.number_or("MX", 2).unwrap_or(2).clamp(1, 5);
                let message = format!(
                    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: {wait}\r\nST: {target}\r\nUSER-AGENT: netNIMA/{} UPnP/1.1\r\n\r\n",
                    crate::VERSION
                );
                io.went(0, &format!("M-SEARCH for {target} (MX {wait})"));
                io.send(Target::Default, message.into_bytes());
            }
            "found" => {
                if self.found.is_empty() {
                    io.note("Nothing answered yet.");
                }
                let lines: Vec<String> = self
                    .found
                    .iter()
                    .map(|(usn, location)| format!("{usn} at {location}"))
                    .collect();
                for line in lines {
                    io.note(&line);
                }
            }
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }
}

/// An SSDP answer tab's settings: the device it says it is.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct SsdpOptions {
    /// The search target it answers, such as "upnp:rootdevice".
    pub target: String,
    /// Where its description is; empty for one on this PC.
    pub location: String,
}

impl Default for SsdpOptions {
    fn default() -> Self {
        Self {
            target: "upnp:rootdevice".into(),
            location: String::new(),
        }
    }
}

/// Answers SSDP searches for one device.
pub struct SsdpAnswer {
    target: String,
    location: String,
    usn: String,
}

impl SsdpAnswer {
    pub fn new(options: SsdpOptions) -> Self {
        let address = own_addresses()[0];
        let location = if options.location.trim().is_empty() {
            format!("http://{address}:8080/description.xml")
        } else {
            options.location.trim().to_string()
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        Self {
            usn: format!(
                "uuid:6e65744e-494d-4100-8000-{:012x}::{}",
                nanos & 0xffff_ffff_ffff,
                options.target.trim()
            ),
            target: options.target.trim().to_string(),
            location,
        }
    }

    fn headers(&self) -> String {
        format!(
            "CACHE-CONTROL: max-age=1800\r\nLOCATION: {}\r\nSERVER: netNIMA/{} UPnP/1.1\r\nUSN: {}\r\n",
            self.location,
            crate::VERSION,
            self.usn
        )
    }

    fn notify(&self, kind: &str, io: &mut Io) {
        let message = format!(
            "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: {}\r\nNTS: {kind}\r\n{}\r\n",
            self.target,
            self.headers()
        );
        io.went(
            0,
            &format!("NOTIFY {kind} {} at {}", self.target, self.location),
        );
        io.send(Target::Default, message.into_bytes());
    }
}

impl Engine for SsdpAnswer {
    fn help(&self) -> &'static str {
        "It answers searches for its target, or for ssdp:all.
notify     say it is there (ssdp:alive)
byebye     say it is going (ssdp:byebye)"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Some((start, headers)) = ssdp_parse(bytes) else {
            return;
        };
        if !start.starts_with("M-SEARCH") {
            return;
        }
        let wanted = headers.get("ST").cloned().unwrap_or_default();
        if wanted != "ssdp:all" && !wanted.eq_ignore_ascii_case(&self.target) {
            return;
        }
        io.came(peer, &ssdp_describe(&start, &headers));
        let answer = format!(
            "HTTP/1.1 200 OK\r\nEXT:\r\nST: {}\r\n{}\r\n",
            self.target,
            self.headers()
        );
        io.went(
            peer,
            &format!("HTTP/1.1 200 OK: {} at {}", self.target, self.location),
        );
        io.send(Target::Peer(peer), answer.into_bytes());
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "notify" | "alive" => self.notify("ssdp:alive", io),
            "byebye" => self.notify("ssdp:byebye", io),
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
    fn an_advertiser_answers_a_browser() {
        let (_advertiser, advertiser_events) = start(
            Box::new(MdnsAdvertiser::new(AdvertiseOptions {
                instance: "Board 7".into(),
                service: "_coap._udp".into(),
                port: 5683,
                txt: "fw=1.2; model=nrf".into(),
                host: "board7".into(),
            })),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&advertiser_events);
        let (browser, browser_events) = start(
            Box::new(MdnsBrowser::default()),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&browser_events);
        browser.command("browse _coap._udp");
        let text = shown(&browser_events, "board7.local A");
        assert!(
            text.contains("_coap._udp.local PTR Board 7._coap._udp.local"),
            "{text}"
        );
        assert!(text.contains("port 5683 board7.local"), "{text}");
        browser.command("found");
        shown(
            &browser_events,
            "Board 7._coap._udp.local: board7.local:5683",
        );
    }

    #[test]
    fn a_search_finds_the_answer() {
        let (_answer, answer_events) = start(
            Box::new(SsdpAnswer::new(SsdpOptions::default())),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&answer_events);
        let (search, search_events) = start(
            Box::new(SsdpSearch::default()),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&search_events);
        search.command("search upnp:rootdevice");
        let text = shown(&search_events, "description.xml");
        assert!(text.contains("HTTP/1.1 200 OK: upnp:rootdevice"), "{text}");
        search.command("search urn:other");
        search.command("found");
        shown(&search_events, "::upnp:rootdevice at http://");
    }
}
