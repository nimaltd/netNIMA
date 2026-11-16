//! Throughput, as iperf2 and Zephyr's zperf measure it: a client that sends
//! for a while at a rate, and a server that counts what comes each second,
//! over TCP, or over UDP with each datagram's number and time for losses and
//! jitter, and the server's report at the end.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use super::{Engine, Io, Words};
use crate::net::{Peer, PeerId, Target};

/// What each datagram of a UDP test starts with: its number, then the time
/// it was sent, as seconds and microseconds.
const UDP_HEADER: usize = 12;

/// "10M" as bits per second: K, M and G, in 1000s.
pub fn rate(text: &str) -> Option<u64> {
    let text = text.trim();
    let (number, factor) = match text.chars().last()? {
        'k' | 'K' => (&text[..text.len() - 1], 1_000.0),
        'm' | 'M' => (&text[..text.len() - 1], 1_000_000.0),
        'g' | 'G' => (&text[..text.len() - 1], 1_000_000_000.0),
        _ => (text, 1.0),
    };
    let value: f64 = number.parse().ok()?;
    (value > 0.0).then_some((value * factor) as u64)
}

/// Bits per second as people read them: "9.87 Mbit/s".
fn rate_text(bytes: u64, seconds: f64) -> String {
    let bits = bytes as f64 * 8.0 / seconds.max(0.000_001);
    if bits >= 1e9 {
        format!("{:.2} Gbit/s", bits / 1e9)
    } else if bits >= 1e6 {
        format!("{:.2} Mbit/s", bits / 1e6)
    } else {
        format!("{:.1} kbit/s", bits / 1e3)
    }
}

fn size_text(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    }
}

fn now_parts() -> (u32, u32) {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (since.as_secs() as u32, since.subsec_micros())
}

/// An iperf2 client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// How long a test sends, in seconds.
    pub seconds: u32,
    /// The rate it sends at, such as "10M".
    pub bandwidth: String,
    /// The bytes of each write, or each datagram on UDP.
    pub length: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            seconds: 10,
            bandwidth: "10M".into(),
            length: 1470,
        }
    }
}

/// A test being sent.
struct Sending {
    until: Instant,
    started: Instant,
    /// Bytes a second.
    rate: u64,
    sent: u64,
    datagrams: i32,
    /// Bytes owed to the rate since the last tick.
    owed: f64,
    last: Instant,
}

/// Sends a test to an iperf2 or zperf server.
pub struct Client {
    options: ClientOptions,
    udp: bool,
    connected: bool,
    sending: Option<Sending>,
    /// UDP: the end of a test sent, waiting for the server's report.
    finishing: Option<(Instant, u32, i32)>,
}

impl Client {
    pub fn new(options: ClientOptions, udp: bool) -> Self {
        Self {
            options,
            udp,
            connected: false,
            sending: None,
            finishing: None,
        }
    }

    fn datagram(&self, number: i32, length: usize) -> Vec<u8> {
        let (seconds, micros) = now_parts();
        let mut datagram = Vec::with_capacity(length.max(UDP_HEADER));
        datagram.extend_from_slice(&number.to_be_bytes());
        datagram.extend_from_slice(&seconds.to_be_bytes());
        datagram.extend_from_slice(&micros.to_be_bytes());
        // The rest as iperf2 fills it: digits over and over.
        datagram
            .extend((0..length.saturating_sub(UDP_HEADER)).map(|index| b'0' + (index % 10) as u8));
        datagram
    }

    fn finish(&mut self, io: &mut Io) {
        let Some(sending) = self.sending.take() else {
            return;
        };
        let seconds = sending.started.elapsed().as_secs_f64();
        io.note(&format!(
            "Sent {} in {seconds:.1} s: {}{}",
            size_text(sending.sent),
            rate_text(sending.sent, seconds),
            if self.udp {
                format!(", {} datagrams", sending.datagrams)
            } else {
                String::new()
            }
        ));
        if self.udp {
            // The end: the last number, negative, a few times, as iperf2 does.
            let last = -(sending.datagrams.max(1));
            for _ in 0..3 {
                io.send(
                    Target::Default,
                    self.datagram(last, self.options.length.max(UDP_HEADER)),
                );
            }
            self.finishing = Some((Instant::now(), 0, last));
        }
    }
}

impl Engine for Client {
    fn help(&self) -> &'static str {
        "run [seconds] [-b 10M] [-l 1470]   send a test: how long, at what rate, in writes or datagrams of what size
stop                               end the test now"
    }

    fn joined(&mut self, _peer: &Peer, _io: &mut Io) {
        self.connected = true;
    }

    fn left(&mut self, _peer: PeerId, io: &mut Io) {
        if !self.udp {
            self.connected = false;
            if self.sending.is_some() {
                io.bad("The server closed the connection during the test.");
                self.sending = None;
            }
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        if !self.udp || bytes.len() < UDP_HEADER + 40 {
            return;
        }
        let number = i32::from_be_bytes(bytes[0..4].try_into().unwrap_or_default());
        if number >= 0 || self.finishing.is_none() {
            return;
        }
        self.finishing = None;
        // The server's report, after the datagram's own header.
        let field = |index: usize| {
            i32::from_be_bytes(
                bytes[UDP_HEADER + index * 4..UDP_HEADER + index * 4 + 4]
                    .try_into()
                    .unwrap_or_default(),
            )
        };
        let total = (u64::from(field(1) as u32) << 32) | u64::from(field(2) as u32);
        let seconds = f64::from(field(3)) + f64::from(field(4)) / 1e6;
        let lost = field(5);
        let out_of_order = field(6);
        let datagrams = field(7);
        let jitter = f64::from(field(8)) + f64::from(field(9)) / 1e6;
        io.came(
            peer,
            &format!(
                "server report: {} in {seconds:.1} s, {}, jitter {:.3} ms, {lost} of {datagrams} lost ({:.2}%), {out_of_order} out of order",
                size_text(total),
                rate_text(total, seconds),
                jitter * 1000.0,
                if datagrams > 0 { f64::from(lost) * 100.0 / f64::from(datagrams) } else { 0.0 }
            ),
        );
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        let result = (|| -> Result<(), String> {
            match words.next().unwrap_or_default().to_lowercase().as_str() {
                "run" | "send" => {
                    if !self.udp && !self.connected {
                        return Err("Not connected: is the iperf2 server there?".into());
                    }
                    let mut seconds = self.options.seconds;
                    let mut bandwidth = self.options.bandwidth.clone();
                    let mut length = self.options.length;
                    // Flags as iperf takes them: -b 10M, or -b10M.
                    while let Some(word) = words.next() {
                        let Some(flag) = word.strip_prefix('-').filter(|flag| !flag.is_empty())
                        else {
                            seconds = word
                                .parse()
                                .map_err(|_| format!("{word} is not seconds."))?;
                            continue;
                        };
                        let letter = flag.chars().next().unwrap_or('?');
                        let attached = &flag[letter.len_utf8()..];
                        let value = if attached.is_empty() {
                            words.next().ok_or(format!("-{letter} needs a value."))?
                        } else {
                            attached.to_string()
                        };
                        match letter {
                            'b' => bandwidth = value,
                            'l' => {
                                length = value
                                    .parse()
                                    .map_err(|_| format!("{value} is not a length."))?
                            }
                            't' => {
                                seconds = value
                                    .parse()
                                    .map_err(|_| format!("{value} is not seconds."))?
                            }
                            other => {
                                return Err(format!("-{other} is not a flag here: -b, -l or -t."));
                            }
                        }
                    }
                    let bits = rate(&bandwidth)
                        .ok_or(format!("{bandwidth} is not a rate, such as 10M."))?;
                    let length = length.clamp(UDP_HEADER, 65_000);
                    let now = Instant::now();
                    self.options.length = length;
                    self.sending = Some(Sending {
                        until: now + Duration::from_secs(u64::from(seconds.max(1))),
                        started: now,
                        rate: bits / 8,
                        sent: 0,
                        datagrams: 0,
                        owed: 0.0,
                        last: now,
                    });
                    self.finishing = None;
                    io.went(
                        0,
                        &format!(
                            "{} test: {seconds} s at {bandwidth}bit/s, {length}-byte {}",
                            if self.udp { "UDP" } else { "TCP" },
                            if self.udp { "datagrams" } else { "writes" }
                        ),
                    );
                    Ok(())
                }
                "stop" => {
                    self.finish(io);
                    Ok(())
                }
                other => Err(format!(
                    "{other} is not a command here. Type help for the list."
                )),
            }
        })();
        if let Err(problem) = result {
            io.bad(&problem);
        }
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        if let Some((sent, tries, last)) = self.finishing
            && now.duration_since(sent) > Duration::from_millis(500)
        {
            if tries >= 6 {
                io.note("No report came from the server: zperf and some servers send none.");
                self.finishing = None;
            } else {
                self.finishing = Some((now, tries + 1, last));
                let datagram = self.datagram(last, self.options.length.max(UDP_HEADER));
                io.send(Target::Default, datagram);
            }
        }
        let length = self.options.length;
        let udp = self.udp;
        let Some(sending) = &mut self.sending else {
            return;
        };
        if now >= sending.until {
            self.finish(io);
            return;
        }
        sending.owed += sending.rate as f64 * now.duration_since(sending.last).as_secs_f64();
        sending.last = now;
        // Not more than a second's worth at once, if the ticks were late.
        sending.owed = sending.owed.min(sending.rate as f64);
        let mut burst = Vec::new();
        while sending.owed >= length as f64 {
            sending.owed -= length as f64;
            sending.sent += length as u64;
            if udp {
                let number = sending.datagrams;
                sending.datagrams += 1;
                let (seconds, micros) = now_parts();
                let mut datagram = Vec::with_capacity(length);
                datagram.extend_from_slice(&number.to_be_bytes());
                datagram.extend_from_slice(&seconds.to_be_bytes());
                datagram.extend_from_slice(&micros.to_be_bytes());
                datagram.extend((0..length - UDP_HEADER).map(|index| b'0' + (index % 10) as u8));
                io.send(Target::Default, datagram);
            } else {
                burst.extend((0..length).map(|index| b'0' + (index % 10) as u8));
            }
        }
        if !burst.is_empty() {
            io.send(Target::Default, burst);
        }
    }
}

/// What a server counts of one client.
struct Count {
    started: Instant,
    bytes: u64,
    interval_bytes: u64,
    interval_start: Instant,
    /// UDP: the next number expected, the losses, those out of order, and jitter.
    next: i32,
    lost: i32,
    out_of_order: i32,
    datagrams: i32,
    jitter: f64,
    last_transit: Option<f64>,
    done: bool,
}

impl Count {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            bytes: 0,
            interval_bytes: 0,
            interval_start: now,
            next: 0,
            lost: 0,
            out_of_order: 0,
            datagrams: 0,
            jitter: 0.0,
            last_transit: None,
            done: false,
        }
    }
}

/// Counts what iperf2 and zperf clients send, each second and in all.
pub struct Server {
    udp: bool,
    counts: BTreeMap<PeerId, Count>,
}

impl Server {
    pub fn new(udp: bool) -> Self {
        Self {
            udp,
            counts: BTreeMap::new(),
        }
    }

    fn summary(count: &Count) -> String {
        let seconds = count.started.elapsed().as_secs_f64();
        let mut line = format!(
            "in all: {} in {seconds:.1} s, {}",
            size_text(count.bytes),
            rate_text(count.bytes, seconds)
        );
        if count.datagrams > 0 {
            line.push_str(&format!(
                ", jitter {:.3} ms, {} of {} lost ({:.2}%), {} out of order",
                count.jitter * 1000.0,
                count.lost,
                count.datagrams + count.lost,
                f64::from(count.lost) * 100.0 / f64::from((count.datagrams + count.lost).max(1)),
                count.out_of_order
            ));
        }
        line
    }
}

impl Engine for Server {
    fn help(&self) -> &'static str {
        "It counts what each client sends and shows its rate each second, and in all at the end.
On UDP it also counts the datagrams lost, those out of order, and the jitter, and sends iperf2 its report."
    }

    fn joined(&mut self, peer: &Peer, io: &mut Io) {
        if !self.udp {
            io.note(&format!("{} connected: counting.", peer.address));
            self.counts.insert(peer.id, Count::new());
        }
    }

    fn left(&mut self, peer: PeerId, io: &mut Io) {
        if let Some(count) = self.counts.remove(&peer) {
            io.came(peer, &Self::summary(&count));
        }
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        let udp = self.udp;
        let count = self.counts.entry(peer).or_insert_with(Count::new);
        if !udp {
            count.bytes += bytes.len() as u64;
            count.interval_bytes += bytes.len() as u64;
            return;
        }
        if bytes.len() < UDP_HEADER {
            return;
        }
        let number = i32::from_be_bytes(bytes[0..4].try_into().unwrap_or_default());
        if number < 0 {
            // The end: the report goes back, as iperf2's server sends it.
            if !count.done {
                count.done = true;
                io.came(peer, &Self::summary(count));
            }
            let seconds = count.started.elapsed();
            let mut report = bytes[..UDP_HEADER].to_vec();
            let fields: [i32; 10] = [
                i32::MIN, // flags: HEADER_VERSION1
                (count.bytes >> 32) as i32,
                count.bytes as i32,
                seconds.as_secs() as i32,
                seconds.subsec_micros() as i32,
                count.lost,
                count.out_of_order,
                count.datagrams + count.lost,
                count.jitter.trunc() as i32,
                (count.jitter.fract() * 1e6) as i32,
            ];
            for field in fields {
                report.extend_from_slice(&field.to_be_bytes());
            }
            io.send(Target::Peer(peer), report);
            return;
        }
        if count.done {
            *count = Count::new();
        }
        count.bytes += bytes.len() as u64;
        count.interval_bytes += bytes.len() as u64;
        count.datagrams += 1;
        if number > count.next {
            count.lost += number - count.next;
            count.next = number + 1;
        } else if number < count.next {
            count.out_of_order += 1;
            count.lost = (count.lost - 1).max(0);
        } else {
            count.next = number + 1;
        }
        // Jitter, as RTP measures it: the change in transit time, smoothed.
        let sent = f64::from(u32::from_be_bytes(
            bytes[4..8].try_into().unwrap_or_default(),
        )) + f64::from(u32::from_be_bytes(
            bytes[8..12].try_into().unwrap_or_default(),
        )) / 1e6;
        let (now_seconds, now_micros) = now_parts();
        let transit = f64::from(now_seconds) + f64::from(now_micros) / 1e6 - sent;
        if let Some(last) = count.last_transit {
            count.jitter += ((transit - last).abs() - count.jitter) / 16.0;
        }
        count.last_transit = Some(transit);
    }

    fn command(&mut self, _words: &mut Words, io: &mut Io) {
        io.bad("An iperf2 server only counts.");
    }

    fn tick(&mut self, now: Instant, io: &mut Io) {
        let mut lines = Vec::new();
        for (peer, count) in &mut self.counts {
            let interval = now.duration_since(count.interval_start);
            if interval < Duration::from_secs(1) || count.done {
                continue;
            }
            if count.interval_bytes > 0 {
                let from = count
                    .interval_start
                    .duration_since(count.started)
                    .as_secs_f64();
                let to = now.duration_since(count.started).as_secs_f64();
                lines.push((
                    *peer,
                    format!(
                        "{from:.1}-{to:.1} s: {}, {}",
                        size_text(count.interval_bytes),
                        rate_text(count.interval_bytes, interval.as_secs_f64())
                    ),
                ));
            }
            count.interval_bytes = 0;
            count.interval_start = now;
        }
        for (peer, line) in lines {
            io.came(peer, &line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tests::{
        client_to, listening, server_on_loopback, shown, start, udp_on_loopback,
    };
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn rates_are_read_as_people_write_them() {
        assert_eq!(rate("10M"), Some(10_000_000));
        assert_eq!(rate("1.5k"), Some(1500));
        assert_eq!(rate("2G"), Some(2_000_000_000));
        assert_eq!(rate("fast"), None);
        assert_eq!(rate_text(1_250_000, 1.0), "10.00 Mbit/s");
    }

    #[test]
    fn a_tcp_test_is_counted() {
        let (_server, server_events) = start(
            Box::new(Server::new(false)),
            SocketKind::Server,
            SocketSetup {
                server: Some(server_on_loopback()),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions::default(), false)),
            SocketKind::Client,
            SocketSetup {
                client: Some(client_to(port)),
                ..SocketSetup::default()
            },
        );
        crate::net::tests::joined(&client_events);
        client.command("run 2 -b 8M");
        shown(&server_events, "Mbit/s");
        shown(&client_events, "Sent ");
    }

    #[test]
    fn a_udp_test_gets_its_report() {
        let (_server, server_events) = start(
            Box::new(Server::new(true)),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(0)),
                ..SocketSetup::default()
            },
        );
        let port = listening(&server_events);
        let (client, client_events) = start(
            Box::new(Client::new(ClientOptions::default(), true)),
            SocketKind::Udp,
            SocketSetup {
                udp: Some(udp_on_loopback(port)),
                ..SocketSetup::default()
            },
        );
        listening(&client_events);
        client.command("run 1 -b 4M -l 1000");
        let text = shown(&client_events, "out of order");
        assert!(text.contains("Sent "), "{text}");
        assert!(text.contains("server report:"), "{text}");
    }
}
