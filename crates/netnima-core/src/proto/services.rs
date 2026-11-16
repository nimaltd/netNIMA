//! Small services boards use, each with both ends, over UDP: Syslog, NTP,
//! Wake-on-LAN, DNS and TFTP. Syslog and DNS run over TCP and TLS too.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use super::{Engine, Io, Words, hex_text, payload_text};
use crate::net::{Peer, PeerId, Target};

// ----- Syslog -----

const FACILITIES: [&str; 24] = [
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "security",
    "console",
    "solaris-cron",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
];
const SEVERITIES: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// What a syslog message says: its priority's words, and the message
/// without its header, in either RFC 3164's form or RFC 5424's.
pub fn describe_syslog(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_end_matches(['\r', '\n', '\0']);
    let Some(rest) = text.strip_prefix('<') else {
        return format!("(no priority) {text}");
    };
    let Some((priority, body)) = rest.split_once('>') else {
        return format!("(no priority) {text}");
    };
    let Ok(priority) = priority.parse::<usize>() else {
        return format!("(no priority) {text}");
    };
    let facility = FACILITIES.get(priority / 8).copied().unwrap_or("?");
    let severity = SEVERITIES[priority % 8];
    // RFC 5424: "1 2026-01-31T12:00:00Z host app procid msgid [sd] message".
    if let Some(after) = body.strip_prefix("1 ") {
        let parts: Vec<&str> = after.splitn(6, ' ').collect();
        if parts.len() == 6 {
            let (sd, message) = split_structured(parts[5]);
            let mut line = format!("{facility}.{severity} {} {}", parts[1], parts[2]);
            if parts[3] != "-" {
                line.push_str(&format!("[{}]", parts[3]));
            }
            if parts[4] != "-" {
                line.push_str(&format!(" {}", parts[4]));
            }
            line.push_str(&format!(": {message}"));
            if sd != "-" && !sd.is_empty() {
                line.push_str(&format!(" {sd}"));
            }
            return line;
        }
    }
    format!("{facility}.{severity} {body}")
}

/// RFC 5424's structured data, and the message after it.
fn split_structured(text: &str) -> (&str, &str) {
    if let Some(rest) = text.strip_prefix("- ") {
        return ("-", rest.trim_start_matches('\u{feff}'));
    }
    if text.starts_with('[') {
        let mut depth = 0;
        for (index, c) in text.char_indices() {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                ' ' if depth == 0 => {
                    return (
                        &text[..index],
                        text[index + 1..].trim_start_matches('\u{feff}'),
                    );
                }
                _ => {}
            }
        }
        return (text, "");
    }
    ("-", text)
}

/// Takes the first whole syslog message off a TCP stream: one with its
/// length in front, as "12 <13>message" (RFC 6587's octet counting, which
/// RFC 5425 has over TLS), or one line (its non-transparent framing).
fn take_syslog(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let digits = buffer
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if (1..=6).contains(&digits) {
        let space = *buffer.get(digits)?;
        if space == b' ' {
            let length: usize = std::str::from_utf8(&buffer[..digits]).ok()?.parse().ok()?;
            let start = digits + 1;
            if buffer.len() < start + length {
                return None;
            }
            let message = buffer[start..start + length].to_vec();
            buffer.drain(..start + length);
            return Some(message);
        }
    }
    let end = buffer
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\0'))?;
    let message = buffer[..end].to_vec();
    buffer.drain(..=end);
    Some(message)
}

/// A syslog sender tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct SyslogOptions {
    /// 5424 for RFC 5424's form, 3164 for the older BSD form.
    pub format: u16,
    pub hostname: String,
    pub app: String,
    pub facility: String,
    /// Over TCP: a line end after each message, rather than its length in front.
    pub lines: bool,
}

impl Default for SyslogOptions {
    fn default() -> Self {
        Self {
            format: 5424,
            hostname: "netnima".into(),
            app: "netnima".into(),
            facility: "user".into(),
            lines: false,
        }
    }
}

pub struct SyslogSender {
    options: SyslogOptions,
    /// Over TCP or TLS, where messages need framing.
    stream: bool,
}

impl SyslogSender {
    pub fn new(options: SyslogOptions) -> Self {
        Self {
            options,
            stream: false,
        }
    }

    /// Over TCP or TLS: each message with its length in front, or a line end
    /// after it when the settings say so.
    pub fn over_stream(options: SyslogOptions) -> Self {
        Self {
            options,
            stream: true,
        }
    }
}

impl Engine for SyslogSender {
    fn help(&self) -> &'static str {
        "[-e|-a|-c|-r|-w|-n|-i|-d] <message>   send it at the info level, or at the one given: -e emerg, -a alert, -c crit, -r err, -w warning, -n notice, -i info, -d debug"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        io.came(peer, &payload_text(bytes));
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let mut severity = 6;
        for (letter, _) in words.flags() {
            severity = match letter {
                'e' => 0,
                'a' => 1,
                'c' => 2,
                'r' => 3,
                'w' => 4,
                'n' => 5,
                'i' => 6,
                'd' => 7,
                other => {
                    io.bad(&format!(
                        "-{other} is not a level: -e -a -c -r -w -n -i -d."
                    ));
                    return;
                }
            };
        }
        // Escapes such as \t in it are the bytes they name, as in other payloads.
        let message = String::from_utf8_lossy(&words.rest()).into_owned();
        let facility = FACILITIES
            .iter()
            .position(|name| name.eq_ignore_ascii_case(self.options.facility.trim()))
            .unwrap_or(1);
        let priority = facility * 8 + severity;
        let now = chrono::Utc::now();
        let line = if self.options.format == 3164 {
            format!(
                "<{priority}>{} {} {}: {message}",
                now.format("%b %e %H:%M:%S"),
                self.options.hostname,
                self.options.app
            )
        } else {
            format!(
                "<{priority}>1 {} {} {} {} - - {message}",
                now.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                self.options.hostname,
                self.options.app,
                std::process::id()
            )
        };
        io.went(0, &describe_syslog(line.as_bytes()));
        let bytes = match (self.stream, self.options.lines) {
            (false, _) => line.into_bytes(),
            (true, false) => format!("{} {line}", line.len()).into_bytes(),
            (true, true) => format!("{line}\n").into_bytes(),
        };
        io.send(Target::Default, bytes);
    }
}

/// What a filter looks at in a syslog message: its severity, and its
/// module: Zephyr's, from "<inf> net_dhcpv4: ..." in the text, or else the
/// app name.
fn syslog_source(bytes: &[u8]) -> (Option<usize>, String) {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_end_matches(['\r', '\n', '\0']);
    let Some((priority, body)) = text.strip_prefix('<').and_then(|rest| rest.split_once('>'))
    else {
        return (None, zephyr_module(text).unwrap_or_default());
    };
    let severity = priority.parse::<usize>().ok().map(|priority| priority % 8);
    let (app, message) = match body.strip_prefix("1 ") {
        // RFC 5424: timestamp, host, app, procid, msgid, then the rest.
        Some(after) => {
            let parts: Vec<&str> = after.splitn(6, ' ').collect();
            let rest = parts.get(5).copied().unwrap_or("");
            (
                parts.get(2).copied().unwrap_or("-"),
                split_structured(rest).1,
            )
        }
        // RFC 3164: "Jan 31 12:00:00 host app[42]: text"; the month, day,
        // time and host go before the app.
        None => {
            let mut rest = body.trim_start();
            for _ in 0..4 {
                rest = rest
                    .split_once(char::is_whitespace)
                    .map_or("", |(_, after)| after)
                    .trim_start();
            }
            let (app, message) = rest.split_once(": ").unwrap_or(("", rest));
            (app.split('[').next().unwrap_or(app), message)
        }
    };
    let module = zephyr_module(message).unwrap_or_else(|| app.to_string());
    (severity, module)
}

/// The module of a Zephyr log line, as "[00:00:01.000,000] <inf> main: hello" names it.
fn zephyr_module(message: &str) -> Option<String> {
    let mut rest = message.trim_start();
    if rest.starts_with('[') {
        rest = rest.split_once(']')?.1.trim_start();
    }
    let rest = ["<err>", "<wrn>", "<inf>", "<dbg>"]
        .iter()
        .find_map(|level| rest.strip_prefix(level))?;
    let (module, _) = rest.trim_start().split_once(':')?;
    (!module.is_empty() && !module.contains(' ')).then(|| module.to_string())
}

/// A severity typed: a number, or a name such as warning, err or info.
fn severity_number(word: &str) -> Option<usize> {
    let word = word.trim().to_lowercase();
    if let Ok(number) = word.parse::<usize>() {
        return (number < 8).then_some(number);
    }
    let named = match word.as_str() {
        "emergency" | "panic" => "emerg",
        "critical" => "crit",
        "error" => "err",
        "warn" | "wrn" => "warning",
        "inf" => "info",
        "dbg" => "debug",
        other => other,
    };
    SEVERITIES.iter().position(|name| *name == named)
}

/// Shows the syslog messages that come, those the filter lets through.
#[derive(Default)]
pub struct SyslogReceiver {
    /// Over TCP or TLS: what came from each sender, until a message is whole.
    streams: Option<BTreeMap<PeerId, Vec<u8>>>,
    /// The least urgent severity shown: 7 (debug) shows all.
    level: Option<usize>,
    /// The modules shown; empty for all.
    modules: Vec<String>,
    /// How many the filter has hidden.
    hidden: u64,
}

impl SyslogReceiver {
    /// Over TCP or TLS: messages with their length in front, or one a line.
    pub fn over_stream() -> Self {
        Self {
            streams: Some(BTreeMap::new()),
            ..Self::default()
        }
    }

    /// Shows a message, if the filter lets it through.
    fn show(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let (severity, module) = syslog_source(bytes);
        let too_low =
            matches!((self.level, severity), (Some(level), Some(severity)) if severity > level);
        let other_module = !self.modules.is_empty()
            && !self
                .modules
                .iter()
                .any(|wanted| wanted.eq_ignore_ascii_case(&module));
        if too_low || other_module {
            self.hidden += 1;
            return;
        }
        io.came(peer, &describe_syslog(bytes));
    }

    fn filter_text(&self) -> String {
        let level = match self.level {
            Some(level) => format!("{} and more urgent", SEVERITIES[level]),
            None => "every level".into(),
        };
        let modules = if self.modules.is_empty() {
            "every module".to_string()
        } else {
            format!("the modules {}", self.modules.join(", "))
        };
        format!(
            "It shows {level}, from {modules}; {} hidden so far.",
            self.hidden
        )
    }
}

/// The most a syslog line waits for its end before what came is dropped.
const LONGEST_LINE: usize = 1 << 20;

impl Engine for SyslogReceiver {
    fn help(&self) -> &'static str {
        "It shows the syslog messages that come, in either form.
level <level>            only that level and more urgent: emerg alert crit err warning notice info debug, or 0 to 7
level all                every level again
module <name> [name...]  only these modules: Zephyr's, as in <inf> net_dhcpv4: ..., or the app name
module all               every module again
filter                   what it shows, and how many it has hidden"
    }

    fn left(&mut self, peer: PeerId, _io: &mut Io) {
        if let Some(streams) = &mut self.streams {
            streams.remove(&peer);
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Some(streams) = &mut self.streams else {
            self.show(peer, bytes, io);
            return;
        };
        let buffer = streams.entry(peer).or_default();
        buffer.extend_from_slice(bytes);
        let mut messages = Vec::new();
        while let Some(message) = take_syslog(buffer) {
            if message.iter().any(|byte| !byte.is_ascii_whitespace()) {
                messages.push(message);
            }
        }
        if buffer.len() > LONGEST_LINE {
            io.bad("A message has come with no end for 1 MB: what came of it is dropped.");
            buffer.clear();
        }
        for message in messages {
            self.show(peer, &message, io);
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.next().unwrap_or_default().to_lowercase().as_str() {
                "level" => {
                    let word = words.need("the level, such as warning, or all")?;
                    self.level = if word.eq_ignore_ascii_case("all") {
                        None
                    } else {
                        Some(severity_number(&word).ok_or(format!(
                            "{word} is not a level: emerg, alert, crit, err, warning, notice, info, debug, or 0 to 7."
                        ))?)
                    };
                }
                "module" | "modules" => {
                    let names: Vec<String> = words
                        .rest_text()
                        .split([' ', ','])
                        .filter(|name| !name.is_empty())
                        .map(str::to_string)
                        .collect();
                    self.modules = if names.iter().any(|name| name.eq_ignore_ascii_case("all")) {
                        Vec::new()
                    } else {
                        names
                    };
                }
                "filter" => {}
                other => {
                    return Err(format!(
                        "{other} is not a command here. Type help for the list."
                    ));
                }
            }
            io.note(&self.filter_text());
            Ok(())
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }
}

// ----- NTP -----

/// Seconds from 1900, NTP's start, to 1970.
const NTP_EPOCH: f64 = 2_208_988_800.0;

fn ntp_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |since| since.as_secs_f64())
        + NTP_EPOCH
}

fn put_timestamp(out: &mut [u8], seconds: f64) {
    let whole = seconds.floor();
    let fraction = ((seconds - whole) * 4_294_967_296.0) as u32;
    out[..4].copy_from_slice(&(whole as u64 as u32).to_be_bytes());
    out[4..8].copy_from_slice(&fraction.to_be_bytes());
}

fn get_timestamp(bytes: &[u8]) -> f64 {
    let whole = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let fraction = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(whole) + f64::from(fraction) / 4_294_967_296.0
}

/// An NTP time as "2026-01-31 12:00:00.123 UTC".
fn ntp_text(seconds: f64) -> String {
    let unix = seconds - NTP_EPOCH;
    chrono::DateTime::from_timestamp(unix.floor() as i64, ((unix.fract()) * 1e9) as u32)
        .map(|at| at.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string())
        .unwrap_or_else(|| "a time out of range".into())
}

fn reference_text(stratum: u8, id: &[u8]) -> String {
    if stratum <= 1 {
        String::from_utf8_lossy(id)
            .trim_end_matches('\0')
            .to_string()
    } else {
        Ipv4Addr::new(id[0], id[1], id[2], id[3]).to_string()
    }
}

/// Asks NTP servers for the time.
#[derive(Default)]
pub struct NtpClient {
    asked: Option<(f64, [u8; 8])>,
    every: Option<(Duration, Instant)>,
}

impl NtpClient {
    fn ask(&mut self, io: &mut Io) {
        let mut request = [0u8; 48];
        request[0] = 0x23; // version 4, client
        let now = ntp_now();
        put_timestamp(&mut request[40..48], now);
        let mut sent = [0u8; 8];
        sent.copy_from_slice(&request[40..48]);
        self.asked = Some((now, sent));
        io.went(
            0,
            &format!("NTP request, version 4, sent at {}", ntp_text(now)),
        );
        io.send(Target::Default, request.to_vec());
    }
}

impl Engine for NtpClient {
    fn help(&self) -> &'static str {
        "ask              ask for the time once
every <seconds>  ask again and again; every 0 stops"
    }

    fn joined(&mut self, _peer: &Peer, _io: &mut Io) {}

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let arrived = ntp_now();
        if bytes.len() < 48 {
            io.bad(&format!(
                "{} bytes is too short for NTP: {}",
                bytes.len(),
                hex_text(bytes)
            ));
            return;
        }
        let mode = bytes[0] & 7;
        let stratum = bytes[1];
        let received = get_timestamp(&bytes[32..40]);
        let transmitted = get_timestamp(&bytes[40..48]);
        let mut line = format!(
            "NTP answer, version {}, stratum {stratum}{}, reference {}: {}",
            (bytes[0] >> 3) & 7,
            if mode == 4 {
                ""
            } else {
                " (not a server's mode)"
            },
            reference_text(stratum, &bytes[12..16]),
            ntp_text(transmitted)
        );
        if let Some((sent, sent_bytes)) = self.asked.take() {
            if bytes[24..32] != sent_bytes {
                line.push_str("\nIts origin time is not the one sent: it answers another request.");
            }
            let offset = ((received - sent) + (transmitted - arrived)) / 2.0;
            let delay = (arrived - sent) - (transmitted - received);
            line.push_str(&format!(
                "\nThis PC is {:.3} ms {} it; the round trip took {:.3} ms.",
                offset.abs() * 1000.0,
                if offset >= 0.0 { "behind" } else { "ahead of" },
                delay * 1000.0
            ));
        }
        if stratum == 0 {
            line.push_str(&format!(
                "\nKiss-o'-Death: {}",
                String::from_utf8_lossy(&bytes[12..16])
            ));
        }
        io.came(peer, &line);
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "ask" | "time" => self.ask(io),
            "every" => match words.number::<u64>("seconds") {
                Ok(0) => {
                    self.every = None;
                    io.note("It asks no more.");
                }
                Ok(seconds) => {
                    self.every = Some((Duration::from_secs(seconds), Instant::now()));
                    self.ask(io);
                }
                Err(problem) => io.bad(&problem),
            },
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        if let Some((every, last)) = self.every
            && now.duration_since(last) >= every
        {
            self.every = Some((every, now));
            self.ask(io);
        }
    }
}

/// Answers NTP requests with this PC's clock.
#[derive(Default)]
pub struct NtpServer;

impl Engine for NtpServer {
    fn help(&self) -> &'static str {
        "It answers NTP and SNTP requests with this PC's clock, as stratum 1 with reference LOCL. It takes no commands."
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let arrived = ntp_now();
        if bytes.len() < 48 || bytes[0] & 7 != 3 {
            io.bad(&format!("Not an NTP client's request: {}", hex_text(bytes)));
            return;
        }
        let version = (bytes[0] >> 3) & 7;
        io.came(peer, &format!("NTP request, version {version}"));
        let mut answer = [0u8; 48];
        answer[0] = version << 3 | 4;
        answer[1] = 1; // stratum 1: this PC's clock is the reference
        answer[2] = bytes[2].max(4);
        answer[3] = (-20i8) as u8;
        answer[12..16].copy_from_slice(b"LOCL");
        put_timestamp(&mut answer[16..24], arrived);
        answer[24..32].copy_from_slice(&bytes[40..48]);
        put_timestamp(&mut answer[32..40], arrived);
        let now = ntp_now();
        put_timestamp(&mut answer[40..48], now);
        io.went(peer, &format!("NTP answer, stratum 1: {}", ntp_text(now)));
        io.send(Target::Peer(peer), answer.to_vec());
    }

    fn command(&mut self, _words: &mut Words, io: &mut Io) {
        io.bad("An NTP server only answers.");
    }
}

// ----- Wake-on-LAN -----

fn parse_mac(text: &str) -> Result<[u8; 6], String> {
    let digits: String = text.chars().filter(char::is_ascii_hexdigit).collect();
    if digits.len() != 12 {
        return Err(format!(
            "{text} is not a MAC address, such as 00:11:22:33:44:55."
        ));
    }
    let mut mac = [0u8; 6];
    for (index, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{text} is not a MAC address."))?;
    }
    Ok(mac)
}

fn mac_text(mac: &[u8]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The MAC address a magic packet wakes, and its SecureOn password, if it is one.
pub fn magic_packet(bytes: &[u8]) -> Option<(String, Option<String>)> {
    let start = bytes.windows(6).position(|window| window == [0xff; 6])?;
    let body = &bytes[start + 6..];
    if body.len() < 96 {
        return None;
    }
    let mac = &body[..6];
    if !(0..16).all(|index| &body[index * 6..index * 6 + 6] == mac) {
        return None;
    }
    let password = body.get(96..102).map(mac_text);
    Some((mac_text(mac), password))
}

/// Sends magic packets.
#[derive(Default)]
pub struct WakeSender;

impl Engine for WakeSender {
    fn help(&self) -> &'static str {
        "wake <MAC> [password]   send a magic packet to wake that PC or board; a SecureOn password if it has one"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        io.came(peer, &payload_text(bytes));
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            let first = words.need("wake and a MAC address")?;
            let mac_word = if first.eq_ignore_ascii_case("wake") {
                words.need("the MAC address")?
            } else {
                first
            };
            let mac = parse_mac(&mac_word)?;
            let mut packet = vec![0xff; 6];
            for _ in 0..16 {
                packet.extend_from_slice(&mac);
            }
            if let Some(password) = words.next() {
                packet.extend_from_slice(&parse_mac(&password)?);
            }
            io.went(
                0,
                &format!(
                    "magic packet for {}, {} bytes",
                    mac_text(&mac),
                    packet.len()
                ),
            );
            io.send(Target::Default, packet);
            Ok(())
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }
}

/// Shows the magic packets that come.
#[derive(Default)]
pub struct WakeListener;

impl Engine for WakeListener {
    fn help(&self) -> &'static str {
        "It shows the magic packets that come, and for which MAC address. It takes no commands."
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        match magic_packet(bytes) {
            Some((mac, None)) => io.came(peer, &format!("magic packet for {mac}")),
            Some((mac, Some(password))) => io.came(
                peer,
                &format!("magic packet for {mac}, SecureOn password {password}"),
            ),
            None => io.came(peer, &format!("not a magic packet: {}", hex_text(bytes))),
        }
    }

    fn command(&mut self, _words: &mut Words, io: &mut Io) {
        io.bad("It only listens: use a Wake-on-LAN Send tab to send.");
    }
}

// ----- DNS -----

const TYPES: [(u16, &str); 12] = [
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (6, "SOA"),
    (12, "PTR"),
    (15, "MX"),
    (16, "TXT"),
    (28, "AAAA"),
    (33, "SRV"),
    (65, "HTTPS"),
    (255, "ANY"),
    (64, "SVCB"),
];

pub(crate) fn type_name(number: u16) -> String {
    TYPES
        .iter()
        .find(|(found, _)| *found == number)
        .map_or_else(|| format!("TYPE{number}"), |(_, name)| (*name).to_string())
}

pub(crate) fn type_number(name: &str) -> Option<u16> {
    TYPES
        .iter()
        .find(|(_, found)| found.eq_ignore_ascii_case(name))
        .map(|(number, _)| *number)
}

fn rcode_name(code: u8) -> &'static str {
    match code {
        0 => "no error",
        1 => "format error",
        2 => "server failure",
        3 => "no such name",
        4 => "not implemented",
        5 => "refused",
        _ => "an error DNS does not name",
    }
}

pub(crate) fn put_name(out: &mut Vec<u8>, name: &str) {
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
    {
        let label = &label.as_bytes()[..label.len().min(63)];
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
}

/// Reads a name at `at`, following compression; gives the name and where it ends.
pub(crate) fn read_name(message: &[u8], mut at: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let length = *message.get(at).ok_or("a name runs past the end")?;
        if length & 0xc0 == 0xc0 {
            let pointer = usize::from(u16::from_be_bytes([
                length & 0x3f,
                *message.get(at + 1).ok_or("a name runs past the end")?,
            ]));
            end.get_or_insert(at + 2);
            at = pointer;
            jumps += 1;
            if jumps > 32 {
                return Err("a name points in a circle".into());
            }
            continue;
        }
        if length == 0 {
            let name = if labels.is_empty() {
                ".".to_string()
            } else {
                labels.join(".")
            };
            return Ok((name, end.unwrap_or(at + 1)));
        }
        let label = message
            .get(at + 1..at + 1 + usize::from(length))
            .ok_or("a name runs past the end")?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        at += 1 + usize::from(length);
    }
}

/// A record's data in words.
pub(crate) fn rdata_text(message: &[u8], kind: u16, start: usize, data: &[u8]) -> String {
    match kind {
        1 if data.len() == 4 => Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        28 if data.len() == 16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(data);
            Ipv6Addr::from(bytes).to_string()
        }
        2 | 5 | 12 => read_name(message, start).map_or_else(|problem| problem, |(name, _)| name),
        15 if data.len() > 2 => format!(
            "{} {}",
            u16::from_be_bytes([data[0], data[1]]),
            read_name(message, start + 2).map_or_else(|problem| problem, |(name, _)| name)
        ),
        16 => {
            let mut parts = Vec::new();
            let mut at = 0;
            while at < data.len() {
                let length = usize::from(data[at]);
                parts.push(format!(
                    "{:?}",
                    String::from_utf8_lossy(data.get(at + 1..at + 1 + length).unwrap_or(&[]))
                ));
                at += 1 + length;
            }
            parts.join(" ")
        }
        33 if data.len() > 6 => format!(
            "priority {} weight {} port {} {}",
            u16::from_be_bytes([data[0], data[1]]),
            u16::from_be_bytes([data[2], data[3]]),
            u16::from_be_bytes([data[4], data[5]]),
            read_name(message, start + 6).map_or_else(|problem| problem, |(name, _)| name)
        ),
        6 => {
            let primary = read_name(message, start);
            match primary {
                Ok((primary, after)) => match read_name(message, after) {
                    Ok((mailbox, after)) => {
                        let serial = message.get(after..after + 4).map_or(0, |bytes| {
                            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                        });
                        format!("{primary} {mailbox} serial {serial}")
                    }
                    Err(problem) => problem,
                },
                Err(problem) => problem,
            }
        }
        _ => hex_text(data),
    }
}

/// A DNS message in words: its question, flags and records.
pub fn describe_dns(message: &[u8]) -> Result<String, String> {
    if message.len() < 12 {
        return Err("it is shorter than DNS's 12-byte header".into());
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let counts: Vec<usize> = (0..4)
        .map(|index| {
            usize::from(u16::from_be_bytes([
                message[4 + index * 2],
                message[5 + index * 2],
            ]))
        })
        .collect();
    let answer = flags & 0x8000 != 0;
    let mut at = 12;
    let mut questions = Vec::new();
    for _ in 0..counts[0] {
        let (name, after) = read_name(message, at)?;
        let kind = u16::from_be_bytes([
            *message.get(after).ok_or("cut short")?,
            *message.get(after + 1).ok_or("cut short")?,
        ]);
        questions.push(format!("{} {name}", type_name(kind)));
        at = after + 4;
    }
    let mut lines = vec![format!(
        "{} id {id:#06x}: {}{}",
        if answer { "answer" } else { "query" },
        questions.join(", "),
        if answer {
            format!(", {}", rcode_name((flags & 0xf) as u8))
        } else {
            String::new()
        }
    )];
    let sections = ["", "", "authority: ", "additional: "];
    for (section, count) in counts.iter().enumerate().skip(1) {
        for _ in 0..*count {
            let (name, after) = read_name(message, at)?;
            let header = message
                .get(after..after + 10)
                .ok_or("a record is cut short")?;
            let kind = u16::from_be_bytes([header[0], header[1]]);
            let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
            let start = after + 10;
            let data = message
                .get(start..start + length)
                .ok_or("a record's data is cut short")?;
            if kind != 41 {
                lines.push(format!(
                    "{}{name} {} {} (ttl {ttl} s)",
                    sections[section],
                    type_name(kind),
                    rdata_text(message, kind, start, data)
                ));
            }
            at = start + length;
        }
    }
    Ok(lines.join("\n"))
}

/// Takes the first whole DNS message off a TCP stream, where each has its
/// length in two bytes in front (RFC 1035, 4.2.2).
fn take_dns(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let length = usize::from(u16::from_be_bytes([*buffer.first()?, *buffer.get(1)?]));
    if buffer.len() < 2 + length {
        return None;
    }
    let message = buffer[2..2 + length].to_vec();
    buffer.drain(..2 + length);
    Some(message)
}

/// A DNS message with its length in front, as TCP and TLS carry it.
fn framed_dns(message: Vec<u8>) -> Vec<u8> {
    let mut out = (message.len().min(0xffff) as u16).to_be_bytes().to_vec();
    out.extend(message);
    out
}

/// Asks DNS servers about names.
#[derive(Default)]
pub struct DnsClient {
    next_id: u16,
    /// Over TCP or TLS (DNS over TLS, port 853): what came, until an answer is whole.
    stream: Option<Vec<u8>>,
}

impl DnsClient {
    /// Over TCP or TLS: each message with its length in front.
    pub fn over_stream() -> Self {
        Self {
            next_id: 0,
            stream: Some(Vec::new()),
        }
    }

    fn show(peer: PeerId, bytes: &[u8], io: &mut Io) {
        match describe_dns(bytes) {
            Ok(text) => io.came(peer, &text),
            Err(problem) => io.bad(&format!("Not a DNS answer: {problem}: {}", hex_text(bytes))),
        }
    }
}

impl Engine for DnsClient {
    fn help(&self) -> &'static str {
        "<type> <name>    ask, such as a example.com, aaaa board.local, mx example.com, txt, ns, cname, srv, soa, any
ptr <address>    the name of an address, such as ptr 192.168.1.50"
    }

    fn left(&mut self, _peer: PeerId, _io: &mut Io) {
        if let Some(buffer) = &mut self.stream {
            buffer.clear();
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Some(buffer) = &mut self.stream else {
            Self::show(peer, bytes, io);
            return;
        };
        buffer.extend_from_slice(bytes);
        while let Some(message) = take_dns(buffer) {
            Self::show(peer, &message, io);
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            let first = words.need("the type and the name, such as a example.com")?;
            let (kind, name) = match words.next() {
                Some(name) => (type_number(&first).ok_or(format!("{first} is not a record type: a, aaaa, mx, txt, ns, cname, ptr, srv, soa or any."))?, name),
                None => (1, first),
            };
            let name = if kind == 12 {
                match name.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(ip)) => {
                        let octets = ip.octets();
                        format!(
                            "{}.{}.{}.{}.in-addr.arpa",
                            octets[3], octets[2], octets[1], octets[0]
                        )
                    }
                    Ok(std::net::IpAddr::V6(ip)) => {
                        let nibbles: Vec<String> = ip
                            .octets()
                            .iter()
                            .rev()
                            .flat_map(|byte| {
                                [format!("{:x}", byte & 0xf), format!("{:x}", byte >> 4)]
                            })
                            .collect();
                        format!("{}.ip6.arpa", nibbles.join("."))
                    }
                    Err(_) => name,
                }
            } else {
                name
            };
            self.next_id = self.next_id.wrapping_add(0x3b9d);
            let mut query = Vec::new();
            query.extend_from_slice(&self.next_id.to_be_bytes());
            query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
            put_name(&mut query, &name);
            query.extend_from_slice(&kind.to_be_bytes());
            query.extend_from_slice(&[0, 1]);
            io.went(0, &describe_dns(&query).unwrap_or_default());
            if self.stream.is_some() {
                io.send(Target::Default, framed_dns(query));
            } else {
                io.send(Target::Default, query);
            }
            Ok(())
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }
}

/// A DNS server tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct DnsServerOptions {
    /// Records it answers, as "name=address" with commas between, such as
    /// "board.local=192.168.1.50, sensor.local=fe80::1".
    pub records: String,
}

impl Default for DnsServerOptions {
    fn default() -> Self {
        Self {
            records: "board.local=192.168.1.50, netnima.local=127.0.0.1".into(),
        }
    }
}

/// Answers A, AAAA, TXT and CNAME questions from its own records.
pub struct DnsServer {
    /// By lower-case name: each record's type and data.
    records: BTreeMap<String, Vec<(u16, Vec<u8>)>>,
    /// Over TCP or TLS: what came from each client, until a query is whole.
    streams: Option<BTreeMap<PeerId, Vec<u8>>>,
}

impl DnsServer {
    pub fn new(options: DnsServerOptions) -> Self {
        let mut server = Self {
            records: BTreeMap::new(),
            streams: None,
        };
        for item in options.records.split(',') {
            if let Some((name, value)) = item.split_once('=') {
                let _ = server.add(name.trim(), value.trim());
            }
        }
        server
    }

    /// Over TCP or TLS: each message with its length in front.
    pub fn over_stream(options: DnsServerOptions) -> Self {
        Self {
            streams: Some(BTreeMap::new()),
            ..Self::new(options)
        }
    }

    /// Adds a record: an address makes A or AAAA, "txt:" text makes TXT,
    /// "cname:" a name makes CNAME.
    fn add(&mut self, name: &str, value: &str) -> Result<String, String> {
        let name = name.trim_end_matches('.').to_lowercase();
        let (kind, data) = if let Ok(ip) = value.parse::<Ipv4Addr>() {
            (1, ip.octets().to_vec())
        } else if let Ok(ip) = value.parse::<Ipv6Addr>() {
            (28, ip.octets().to_vec())
        } else if let Some(text) = value.strip_prefix("txt:") {
            let text = &text.as_bytes()[..text.len().min(255)];
            (16, [vec![text.len() as u8], text.to_vec()].concat())
        } else if let Some(target) = value.strip_prefix("cname:") {
            let mut data = Vec::new();
            put_name(&mut data, target);
            (5, data)
        } else {
            return Err(format!(
                "{value} is not an address, txt:<text> or cname:<name>."
            ));
        };
        let records = self.records.entry(name.clone()).or_default();
        records.push((kind, data));
        Ok(format!("{name} {}", type_name(kind)))
    }

    /// Shows a query that came, and gives the answer to send back; none for
    /// what is not a query.
    fn answer(&self, peer: PeerId, bytes: &[u8], io: &mut Io) -> Option<Vec<u8>> {
        match describe_dns(bytes) {
            Ok(text) => io.came(peer, &text),
            Err(problem) => {
                io.bad(&format!("Not a DNS query: {problem}: {}", hex_text(bytes)));
                return None;
            }
        }
        if bytes[2] & 0x80 != 0 {
            return None;
        }
        let (name, after) = read_name(bytes, 12).ok()?;
        let kind_bytes = bytes.get(after..after + 4)?;
        let kind = u16::from_be_bytes([kind_bytes[0], kind_bytes[1]]);
        let found: Vec<(u16, Vec<u8>)> = self
            .records
            .get(&name.to_lowercase())
            .map(|records| {
                records
                    .iter()
                    .filter(|(found, _)| kind == 255 || *found == kind || *found == 5)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let known = self.records.contains_key(&name.to_lowercase());
        let mut answer = Vec::new();
        answer.extend_from_slice(&bytes[..2]);
        let rcode = if known { 0 } else { 3 };
        answer.extend_from_slice(&[0x84 | (bytes[2] & 0x01), 0x80 | rcode]);
        answer.extend_from_slice(&[0, 1]);
        answer.extend_from_slice(&(found.len() as u16).to_be_bytes());
        answer.extend_from_slice(&[0, 0, 0, 0]);
        answer.extend_from_slice(&bytes[12..after + 4]);
        for (record_kind, data) in &found {
            answer.extend_from_slice(&[0xc0, 12]);
            answer.extend_from_slice(&record_kind.to_be_bytes());
            answer.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            answer.extend_from_slice(&(data.len() as u16).to_be_bytes());
            answer.extend_from_slice(data);
        }
        io.went(peer, &describe_dns(&answer).unwrap_or_default());
        Some(answer)
    }
}

impl Engine for DnsServer {
    fn help(&self) -> &'static str {
        "add <name> <value>   a record: an address for A or AAAA, txt:<text>, or cname:<name>
remove <name>        drop a name's records
records              the records"
    }

    fn left(&mut self, peer: PeerId, _io: &mut Io) {
        if let Some(streams) = &mut self.streams {
            streams.remove(&peer);
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let queries = match &mut self.streams {
            None => vec![bytes.to_vec()],
            Some(streams) => {
                let buffer = streams.entry(peer).or_default();
                buffer.extend_from_slice(bytes);
                std::iter::from_fn(|| take_dns(buffer)).collect()
            }
        };
        for query in queries {
            if let Some(answer) = self.answer(peer, &query, io) {
                let answer = if self.streams.is_some() {
                    framed_dns(answer)
                } else {
                    answer
                };
                io.send(Target::Peer(peer), answer);
            }
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.next().unwrap_or_default().to_lowercase().as_str() {
                "add" => {
                    let name = words.need("the name")?;
                    let value = words.need("the value")?;
                    let added = self.add(&name, &value)?;
                    io.note(&format!("{added} added."));
                }
                "remove" => {
                    let name = words.need("the name")?.to_lowercase();
                    if self.records.remove(&name).is_none() {
                        return Err(format!("There is no {name}."));
                    }
                    io.note(&format!("{name} removed."));
                }
                "records" => {
                    let lines: Vec<String> = self
                        .records
                        .iter()
                        .flat_map(|(name, records)| {
                            records.iter().map(move |(kind, data)| {
                                let shown = match kind {
                                    1 | 28 => rdata_text(data, *kind, 0, data),
                                    16 => payload_text(&data[1..]),
                                    _ => {
                                        read_name(data, 0).map(|(name, _)| name).unwrap_or_default()
                                    }
                                };
                                format!("{name} {} {shown}", type_name(*kind))
                            })
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

// ----- TFTP -----

const RRQ: u16 = 1;
const WRQ: u16 = 2;
const DATA: u16 = 3;
const TFTP_ACK: u16 = 4;
const ERROR: u16 = 5;
const OACK: u16 = 6;
const TFTP_TIMEOUT: Duration = Duration::from_secs(2);
const TFTP_TRIES: u32 = 5;

fn tftp_error(code: u16, text: &str) -> Vec<u8> {
    let mut packet = vec![0, ERROR as u8];
    packet.extend_from_slice(&code.to_be_bytes());
    packet.extend_from_slice(text.as_bytes());
    packet.push(0);
    packet
}

/// The strings after a request's opcode: the file, the mode, then options in pairs.
fn tftp_strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

fn describe_tftp(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return format!("not TFTP: {}", hex_text(bytes));
    }
    let opcode = u16::from_be_bytes([bytes[0], bytes[1]]);
    let block = if bytes.len() >= 4 {
        u16::from_be_bytes([bytes[2], bytes[3]])
    } else {
        0
    };
    match opcode {
        RRQ | WRQ => {
            let strings = tftp_strings(&bytes[2..]);
            let options: Vec<String> = strings[2.min(strings.len())..]
                .chunks(2)
                .filter(|pair| pair.len() == 2 && !pair[0].is_empty())
                .map(|pair| format!("{}={}", pair[0], pair[1]))
                .collect();
            format!(
                "{} {} ({}{})",
                if opcode == RRQ {
                    "read request"
                } else {
                    "write request"
                },
                strings.first().cloned().unwrap_or_default(),
                strings.get(1).cloned().unwrap_or_default(),
                if options.is_empty() {
                    String::new()
                } else {
                    format!(", {}", options.join(", "))
                }
            )
        }
        DATA => format!("data block {block}, {} bytes", bytes.len() - 4),
        TFTP_ACK => format!("ack {block}"),
        ERROR => format!(
            "error {block}: {}",
            String::from_utf8_lossy(&bytes[4.min(bytes.len())..]).trim_end_matches('\0')
        ),
        OACK => format!("options taken: {}", tftp_strings(&bytes[2..]).join(" ")),
        other => format!("opcode {other}: {}", hex_text(bytes)),
    }
}

/// The folder files are read from and written to: the one set, or Downloads.
fn files_folder(folder: &str) -> PathBuf {
    if !folder.trim().is_empty() {
        return PathBuf::from(folder.trim());
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join("Downloads")
}

/// A file's name, kept inside its folder.
fn inside(folder: &std::path::Path, name: &str) -> Option<PathBuf> {
    let name = name.replace('\\', "/");
    if name.split('/').any(|part| part == "..") {
        return None;
    }
    Some(folder.join(name.trim_start_matches('/')))
}

/// One transfer, either way.
struct Transfer {
    name: String,
    /// What is sent (a read) or what came so far (a write).
    data: Vec<u8>,
    /// Sending: the last block sent. Receiving: the last block taken.
    block: u16,
    block_size: usize,
    sending: bool,
    /// Where a received file goes when it is whole.
    path: PathBuf,
    last: Vec<u8>,
    sent: Instant,
    tries: u32,
    started: Instant,
    done: bool,
}

impl Transfer {
    fn new(name: &str, sending: bool, data: Vec<u8>, path: PathBuf) -> Self {
        Self {
            name: name.to_string(),
            data,
            block: 0,
            block_size: 512,
            sending,
            path,
            last: Vec::new(),
            sent: Instant::now(),
            tries: 0,
            started: Instant::now(),
            done: false,
        }
    }

    /// The DATA packet of block `block`.
    fn data_packet(&self, block: u16) -> Vec<u8> {
        let start = (usize::from(block) - 1) * self.block_size;
        let end = (start + self.block_size).min(self.data.len());
        let mut packet = vec![0, DATA as u8];
        packet.extend_from_slice(&block.to_be_bytes());
        packet.extend_from_slice(&self.data[start.min(end)..end]);
        packet
    }

    fn blocks(&self) -> usize {
        self.data.len() / self.block_size + 1
    }

    fn rate(&self) -> String {
        let seconds = self.started.elapsed().as_secs_f64().max(0.001);
        format!(
            "{} bytes in {:.2} s, {:.1} KB/s",
            self.data.len(),
            seconds,
            self.data.len() as f64 / 1024.0 / seconds
        )
    }
}

/// Sends `packet` to `peer` and keeps it to send again.
fn tftp_send(
    transfer: &mut Transfer,
    peer: Target,
    shown: PeerId,
    packet: Vec<u8>,
    io: &mut Io,
    quiet: bool,
) {
    if !quiet {
        io.went(shown, &describe_tftp(&packet));
    }
    transfer.last = packet.clone();
    transfer.sent = Instant::now();
    transfer.tries = 0;
    io.send(peer, packet);
}

/// Shows a data or ack line only now and then: the first, every 100th and the last.
fn worth_showing(block: u16, last: bool) -> bool {
    block <= 1 || block.is_multiple_of(100) || last
}

/// Whether a packet about to go ends its transfer: the last DATA, or the ACK of it.
fn last_packet(transfer: &Transfer, packet: &[u8]) -> bool {
    transfer.done
        || (packet.get(1) == Some(&(DATA as u8)) && packet.len() < 4 + transfer.block_size)
}

/// Takes an ACK of a transfer that sends, or a DATA of one that receives.
/// Gives the packet to send next, and whether the transfer ended.
fn tftp_step(transfer: &mut Transfer, bytes: &[u8], io: &mut Io, peer: PeerId) -> Option<Vec<u8>> {
    let opcode = u16::from_be_bytes([bytes[0], bytes[1]]);
    let block = if bytes.len() >= 4 {
        u16::from_be_bytes([bytes[2], bytes[3]])
    } else {
        0
    };
    match opcode {
        TFTP_ACK if transfer.sending => {
            let blocks = transfer.blocks();
            if worth_showing(block, usize::from(block) == blocks) {
                io.came(peer, &describe_tftp(bytes));
            }
            if block != transfer.block {
                return None;
            }
            if usize::from(block) >= blocks {
                transfer.done = true;
                io.note(&format!("{} sent: {}.", transfer.name, transfer.rate()));
                return None;
            }
            transfer.block = block.wrapping_add(1);
            Some(transfer.data_packet(transfer.block))
        }
        DATA if !transfer.sending => {
            let payload = &bytes[4..];
            let last = payload.len() < transfer.block_size;
            if worth_showing(block, last) {
                io.came(peer, &describe_tftp(bytes));
            }
            let mut ack = vec![0, TFTP_ACK as u8];
            ack.extend_from_slice(&block.to_be_bytes());
            if block == transfer.block.wrapping_add(1) {
                transfer.block = block;
                transfer.data.extend_from_slice(payload);
                if last {
                    transfer.done = true;
                    match std::fs::write(&transfer.path, &transfer.data) {
                        Ok(()) => io.note(&format!(
                            "{} saved to {}: {}.",
                            transfer.name,
                            transfer.path.display(),
                            transfer.rate()
                        )),
                        Err(error) => io.bad(&format!(
                            "{} could not be saved to {}: {error}",
                            transfer.name,
                            transfer.path.display()
                        )),
                    }
                }
            }
            Some(ack)
        }
        OACK => {
            io.came(peer, &describe_tftp(bytes));
            let strings = tftp_strings(&bytes[2..]);
            for pair in strings.chunks(2) {
                if pair.len() == 2 && pair[0].eq_ignore_ascii_case("blksize") {
                    transfer.block_size = pair[1].parse().unwrap_or(512);
                }
            }
            if transfer.sending {
                transfer.block = 1;
                Some(transfer.data_packet(1))
            } else {
                Some(vec![0, TFTP_ACK as u8, 0, 0])
            }
        }
        ERROR => {
            io.came(peer, &describe_tftp(bytes));
            transfer.done = true;
            None
        }
        _ => {
            io.came(peer, &describe_tftp(bytes));
            None
        }
    }
}

/// Sends again what each transfer sent last when no answer came.
fn tftp_retry(transfer: &mut Transfer, target: Target, now: Instant, io: &mut Io) -> bool {
    if transfer.done || transfer.last.is_empty() || now.duration_since(transfer.sent) < TFTP_TIMEOUT
    {
        return true;
    }
    if transfer.tries >= TFTP_TRIES {
        io.bad(&format!(
            "{}: no answer after {} tries, given up.",
            transfer.name,
            TFTP_TRIES + 1
        ));
        return false;
    }
    transfer.tries += 1;
    transfer.sent = now;
    io.send(target, transfer.last.clone());
    true
}

/// A TFTP tab's settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct TftpOptions {
    /// The folder files are served from and saved to: empty for Downloads.
    pub folder: String,
}

/// Gets files from TFTP servers and puts files on them.
pub struct TftpClient {
    folder: PathBuf,
    transfer: Option<Transfer>,
    /// The port the server answers from, once it has.
    server: Option<PeerId>,
}

impl TftpClient {
    pub fn new(options: TftpOptions) -> Self {
        Self {
            folder: files_folder(&options.folder),
            transfer: None,
            server: None,
        }
    }

    fn target(&self) -> Target {
        self.server.map_or(Target::Default, Target::Peer)
    }
}

impl Engine for TftpClient {
    fn help(&self) -> &'static str {
        "get <file> [saved as]     read a file from the server, into the tab's folder
put <file> [named]        write a file of the tab's folder to the server
folder                    where files are read from and saved"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let Some(transfer) = &mut self.transfer else {
            io.came(peer, &describe_tftp(bytes));
            return;
        };
        if bytes.len() < 4 {
            io.bad(&format!("Not TFTP: {}", hex_text(bytes)));
            return;
        }
        // The server answers from a port of its own for the transfer.
        self.server.get_or_insert(peer);
        if let Some(next) = tftp_step(transfer, bytes, io, peer) {
            let quiet = !worth_showing(
                u16::from_be_bytes([next[2], next[3]]),
                last_packet(transfer, &next),
            );
            tftp_send(transfer, Target::Peer(peer), peer, next, io, quiet);
        }
        if transfer.done {
            self.transfer = None;
            self.server = None;
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            let command = words.next().unwrap_or_default().to_lowercase();
            match command.as_str() {
                "get" | "put" => {
                    if self.transfer.is_some() {
                        return Err("A transfer is going on: wait for its end.".into());
                    }
                    let name = words.need("the file's name")?;
                    let other = words.next().unwrap_or_else(|| name.clone());
                    let sending = command == "put";
                    let local = inside(&self.folder, if sending { &name } else { &other })
                        .ok_or("A file's name cannot go up with ..")?;
                    let remote = if sending { other } else { name };
                    let data = if sending {
                        std::fs::read(&local).map_err(|error| {
                            format!("Could not read {}: {error}", local.display())
                        })?
                    } else {
                        Vec::new()
                    };
                    let mut request = vec![0, if sending { WRQ as u8 } else { RRQ as u8 }];
                    request.extend_from_slice(remote.as_bytes());
                    request.extend_from_slice(b"\0octet\0");
                    let mut transfer = Transfer::new(&remote, sending, data, local);
                    self.server = None;
                    tftp_send(&mut transfer, Target::Default, 0, request, io, false);
                    self.transfer = Some(transfer);
                }
                "folder" => io.note(&format!(
                    "Files are read from and saved to {}.",
                    self.folder.display()
                )),
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
        let target = self.target();
        if let Some(transfer) = &mut self.transfer
            && !tftp_retry(transfer, target, now, io)
        {
            self.transfer = None;
        }
    }
}

/// Serves a folder's files to TFTP clients, and takes files they put.
pub struct TftpServer {
    folder: PathBuf,
    transfers: BTreeMap<PeerId, Transfer>,
}

impl TftpServer {
    pub fn new(options: TftpOptions) -> Self {
        Self {
            folder: files_folder(&options.folder),
            transfers: BTreeMap::new(),
        }
    }

    fn request(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let opcode = u16::from_be_bytes([bytes[0], bytes[1]]);
        let strings = tftp_strings(&bytes[2..]);
        let name = strings.first().cloned().unwrap_or_default();
        let Some(path) = inside(&self.folder, &name) else {
            let error = tftp_error(2, "access violation");
            io.went(peer, &describe_tftp(&error));
            io.send(Target::Peer(peer), error);
            return;
        };
        let mut options: Vec<(String, String)> = strings
            .get(2..)
            .unwrap_or(&[])
            .chunks(2)
            .filter(|pair| pair.len() == 2 && !pair[0].is_empty())
            .map(|pair| (pair[0].to_lowercase(), pair[1].clone()))
            .collect();
        let data = if opcode == RRQ {
            match std::fs::read(&path) {
                Ok(data) => data,
                Err(_) => {
                    let error = tftp_error(1, "file not found");
                    io.went(peer, &describe_tftp(&error));
                    io.send(Target::Peer(peer), error);
                    return;
                }
            }
        } else {
            Vec::new()
        };
        let mut transfer = Transfer::new(&name, opcode == RRQ, data, path);
        // The options it takes: blksize, tsize and timeout.
        options.retain(|(name, _)| matches!(name.as_str(), "blksize" | "tsize" | "timeout"));
        for (name, value) in &mut options {
            match name.as_str() {
                "blksize" => {
                    let size = value.parse::<usize>().unwrap_or(512).clamp(8, 65464);
                    transfer.block_size = size;
                    *value = size.to_string();
                }
                "tsize" if opcode == RRQ => *value = transfer.data.len().to_string(),
                _ => {}
            }
        }
        let first = if !options.is_empty() {
            let mut oack = vec![0, OACK as u8];
            for (name, value) in &options {
                oack.extend_from_slice(name.as_bytes());
                oack.push(0);
                oack.extend_from_slice(value.as_bytes());
                oack.push(0);
            }
            oack
        } else if opcode == RRQ {
            transfer.block = 1;
            transfer.data_packet(1)
        } else {
            vec![0, TFTP_ACK as u8, 0, 0]
        };
        tftp_send(&mut transfer, Target::Peer(peer), peer, first, io, false);
        self.transfers.insert(peer, transfer);
    }
}

impl Engine for TftpServer {
    fn help(&self) -> &'static str {
        "It serves the files of its folder and saves the files clients put there.
folder      where that is"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        if bytes.len() < 4 {
            io.bad(&format!("Not TFTP: {}", hex_text(bytes)));
            return;
        }
        let opcode = u16::from_be_bytes([bytes[0], bytes[1]]);
        if opcode == RRQ || opcode == WRQ {
            io.came(peer, &describe_tftp(bytes));
            self.request(peer, bytes, io);
            return;
        }
        let Some(transfer) = self.transfers.get_mut(&peer) else {
            io.came(peer, &describe_tftp(bytes));
            return;
        };
        // An ACK of the OACK starts a read.
        if transfer.sending && opcode == TFTP_ACK && transfer.block == 0 {
            transfer.block = 1;
            let first = transfer.data_packet(1);
            tftp_send(transfer, Target::Peer(peer), peer, first, io, false);
            return;
        }
        if let Some(next) = tftp_step(transfer, bytes, io, peer) {
            let quiet = !worth_showing(
                u16::from_be_bytes([next[2], next[3]]),
                last_packet(transfer, &next),
            );
            tftp_send(transfer, Target::Peer(peer), peer, next, io, quiet);
        }
        if transfer.done {
            self.transfers.remove(&peer);
        }
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "folder" => io.note(&format!(
                "Files are served from and saved to {}.",
                self.folder.display()
            )),
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        self.transfers.retain(|peer, transfer| {
            !transfer.done && tftp_retry(transfer, Target::Peer(*peer), now, io)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{listening, shown, start, udp_on_loopback};
    use crate::proto::{SocketKind, SocketSetup};

    fn pair(
        server: Box<dyn Engine>,
        client: Box<dyn Engine>,
    ) -> (
        crate::proto::ProtocolSession,
        std::sync::mpsc::Receiver<crate::net::Event>,
        crate::proto::ProtocolSession,
        std::sync::mpsc::Receiver<crate::net::Event>,
    ) {
        let (server, server_events) = start(
            server,
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            client,
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&client_events);
        (server, server_events, client, client_events)
    }

    #[test]
    fn syslog_in_both_forms() {
        assert_eq!(
            describe_syslog(b"<34>1 2026-01-31T12:00:00Z board app 42 ID47 - started\n"),
            "auth.crit board app[42] ID47: started"
        );
        assert_eq!(
            describe_syslog(b"<13>Jan 31 12:00:00 board app: hi"),
            "user.notice Jan 31 12:00:00 board app: hi"
        );
        let (_receiver, receiver_events, sender, _sender_events) = pair(
            Box::new(SyslogReceiver::default()),
            Box::new(SyslogSender::new(SyslogOptions::default())),
        );
        sender.command("-w the disk is full");
        shown(&receiver_events, "user.warning netnima netnima");
    }

    #[test]
    fn syslog_is_filtered_by_level_and_module() {
        assert_eq!(
            syslog_source(
                b"<14>1 2026-01-31T12:00:00Z board zephyr - - - <inf> net_dhcpv4: Received: 192.168.1.50"
            ),
            (Some(6), "net_dhcpv4".to_string())
        );
        assert_eq!(
            syslog_source(b"<11>Jan  1 12:00:00 board app[42]: disk full"),
            (Some(3), "app".to_string())
        );
        assert_eq!(
            zephyr_module("[00:00:01.000,000] <wrn> main: low battery"),
            Some("main".to_string())
        );
        assert_eq!(severity_number("warning"), Some(4));
        assert_eq!(severity_number("wrn"), Some(4));
        assert_eq!(severity_number("9"), None);
        let (receiver, receiver_events, sender, _sender_events) = pair(
            Box::new(SyslogReceiver::default()),
            Box::new(SyslogSender::new(SyslogOptions::default())),
        );
        receiver.command("level warning");
        receiver.command("module net_dhcpv4");
        sender.command("-i <inf> net_dhcpv4: hidden for its level");
        sender.command("-w <wrn> main: hidden for its module");
        sender.command("-w <wrn> net_dhcpv4: no lease yet");
        let text = shown(&receiver_events, "no lease yet");
        assert!(!text.contains("hidden for"), "{text}");
        receiver.command("filter");
        shown(&receiver_events, "2 hidden so far");
        receiver.command("level all");
        receiver.command("module all");
        sender.command("-d <dbg> main: shown again");
        shown(&receiver_events, "shown again");
    }

    /// A server and a client over TCP on the loopback.
    fn tcp_pair(
        server: Box<dyn Engine>,
        client: Box<dyn Engine>,
    ) -> (
        crate::proto::ProtocolSession,
        std::sync::mpsc::Receiver<crate::net::Event>,
        crate::proto::ProtocolSession,
        std::sync::mpsc::Receiver<crate::net::Event>,
    ) {
        use crate::proto::tests::{client_to, server_on_loopback};
        let (server, server_events) = start(
            server,
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            client,
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        (server, server_events, client, client_events)
    }

    #[test]
    fn syslog_over_tcp_with_lengths_and_with_lines() {
        let mut buffer = b"11 <13>1 hello<14>line one\n8 <15>abc".to_vec();
        assert_eq!(take_syslog(&mut buffer).unwrap(), b"<13>1 hello");
        assert_eq!(take_syslog(&mut buffer).unwrap(), b"<14>line one");
        assert_eq!(take_syslog(&mut buffer), None, "the rest has not come");
        buffer.extend_from_slice(b"d");
        assert_eq!(take_syslog(&mut buffer).unwrap(), b"<15>abcd");
        for lines in [false, true] {
            let (_receiver, receiver_events, sender, _sender_events) = tcp_pair(
                Box::new(SyslogReceiver::over_stream()),
                Box::new(SyslogSender::over_stream(SyslogOptions {
                    lines,
                    ..SyslogOptions::default()
                })),
            );
            sender.command("-r the first");
            sender.command("-n the second");
            let text = shown(&receiver_events, "user.notice netnima netnima");
            assert!(text.contains("user.err netnima netnima"), "{text}");
            assert!(text.contains(": the second"), "{text}");
        }
    }

    #[test]
    fn dns_over_tcp_asks_and_answers() {
        let (_server, _server_events, client, client_events) = tcp_pair(
            Box::new(DnsServer::over_stream(DnsServerOptions::default())),
            Box::new(DnsClient::over_stream()),
        );
        client.command("a board.local");
        shown(&client_events, "board.local A 192.168.1.50 (ttl 60 s)");
        client.command("a netnima.local");
        shown(&client_events, "netnima.local A 127.0.0.1");
    }

    #[test]
    fn ntp_asks_and_answers() {
        let (_server, _server_events, client, client_events) =
            pair(Box::new(NtpServer), Box::new(NtpClient::default()));
        client.command("ask");
        let text = shown(&client_events, "round trip took");
        assert!(text.contains("stratum 1, reference LOCL"), "{text}");
    }

    #[test]
    fn wake_on_lan_packets_are_made_and_found() {
        let (_listener, listener_events, sender, _sender_events) =
            pair(Box::new(WakeListener), Box::new(WakeSender));
        sender.command("wake 00-11-22-AA-BB-CC");
        shown(&listener_events, "magic packet for 00:11:22:aa:bb:cc");
        assert!(magic_packet(b"nothing").is_none());
    }

    #[test]
    fn dns_asks_and_answers() {
        let (server, _server_events, client, client_events) = pair(
            Box::new(DnsServer::new(DnsServerOptions::default())),
            Box::new(DnsClient::default()),
        );
        client.command("a board.local");
        shown(&client_events, "board.local A 192.168.1.50 (ttl 60 s)");
        server.command("add sensor.local txt:v=1");
        client.command("txt sensor.local");
        shown(&client_events, "sensor.local TXT \"v=1\"");
        client.command("a nothing.local");
        shown(&client_events, "no such name");
    }

    #[test]
    fn tftp_gets_and_puts_files() {
        let folder = crate::certs::tests::scratch("tftp");
        let served = folder.join("served");
        let saved = folder.join("saved");
        std::fs::create_dir_all(&served).unwrap();
        std::fs::create_dir_all(&saved).unwrap();
        let firmware: Vec<u8> = (0..5000u32).map(|n| (n % 253) as u8).collect();
        std::fs::write(served.join("firmware.bin"), &firmware).unwrap();
        std::fs::write(saved.join("config.txt"), b"rate=10\n").unwrap();
        let (_server, _server_events, client, client_events) = pair(
            Box::new(TftpServer::new(TftpOptions {
                folder: served.display().to_string(),
            })),
            Box::new(TftpClient::new(TftpOptions {
                folder: saved.display().to_string(),
            })),
        );
        client.command("get firmware.bin");
        shown(&client_events, "firmware.bin saved to");
        assert_eq!(std::fs::read(saved.join("firmware.bin")).unwrap(), firmware);
        client.command("put config.txt");
        shown(&client_events, "config.txt sent");
        assert_eq!(
            std::fs::read(served.join("config.txt")).unwrap(),
            b"rate=10\n"
        );
        client.command("get missing.bin");
        shown(&client_events, "error 1: file not found");
        let _ = std::fs::remove_dir_all(folder);
    }
}

/// On Windows, a UDP read that timed out could lose the datagram that came at
/// that moment: twenty answers in a row, each of which must come.
#[cfg(test)]
mod lost_datagrams {
    use super::*;
    use crate::proto::tests::{listening, shown, start, udp_on_loopback};
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn every_answer_comes() {
        for _ in 0..20 {
            let (_server, server_events) = start(
                Box::new(NtpServer),
                SocketKind::Udp,
                SocketSetup {
                    udp: Some(udp_on_loopback(0)),
                    ..SocketSetup::default()
                },
            );
            let port = listening(&server_events);
            let (client, client_events) = start(
                Box::new(NtpClient::default()),
                SocketKind::Udp,
                SocketSetup {
                    udp: Some(udp_on_loopback(port)),
                    ..SocketSetup::default()
                },
            );
            listening(&client_events);
            client.command("ask");
            shown(&client_events, "round trip took");
        }
    }
}
