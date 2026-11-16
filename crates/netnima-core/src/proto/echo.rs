//! Echo (RFC 862), over TCP or UDP: a server that sends back what comes,
//! as Zephyr's echo_server does, and a client that sends, checks what comes
//! back byte for byte, and times each round trip, to test a board's network
//! stack.
//!
//! The client does its own sending and reading, on a thread of its own with
//! blocking sockets, as ping does: a round trip it times is the network's
//! and the other end's, not the time a message waits to be sent.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{Engine, Io, Words, payload_text};
use crate::net::{PeerId, Target};

/// How long an echo is waited for before it is counted lost.
const WAIT: Duration = Duration::from_secs(2);

/// The most of a piece shown in its line.
const SHOWN: usize = 200;

fn short(bytes: &[u8]) -> String {
    let text = payload_text(&bytes[..bytes.len().min(SHOWN)]);
    if bytes.len() > SHOWN {
        format!("{text} ...")
    } else {
        text
    }
}

fn millis(time: Duration) -> String {
    format!("{:.2} ms", time.as_secs_f64() * 1000.0)
}

// ----- The server -----

/// An echo server tab's settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServerOptions {
    /// Counts what comes rather than showing each piece.
    pub quiet: bool,
}

/// Sends back what comes, to whoever sent it.
pub struct Server {
    quiet: bool,
    bytes: u64,
    pieces: u64,
}

impl Server {
    pub fn new(options: ServerOptions) -> Self {
        Self {
            quiet: options.quiet,
            bytes: 0,
            pieces: 0,
        }
    }
}

impl Engine for Server {
    fn help(&self) -> &'static str {
        "It sends back everything that comes, to its sender.
quiet on|off   only count what comes, or show each piece
stats          how much came and went back"
    }

    fn received(&mut self, peer: PeerId, bytes: &[u8], io: &mut Io) {
        self.bytes += bytes.len() as u64;
        self.pieces += 1;
        if !self.quiet {
            io.came(peer, &format!("{} bytes: {}", bytes.len(), short(bytes)));
        }
        io.send(Target::Peer(peer), bytes.to_vec());
    }

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "quiet" => {
                self.quiet = words.next().is_none_or(|word| word != "off");
                io.note(if self.quiet {
                    "It counts what comes; stats shows how much."
                } else {
                    "It shows each piece that comes."
                });
            }
            "stats" => io.note(&format!(
                "{} bytes came and went back, in {} pieces.",
                self.bytes, self.pieces
            )),
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }
}

// ----- The client -----

/// An echo client tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    /// The echo server: a name or an address.
    pub host: String,
    pub port: u16,
    /// What a test sends unless told: how many messages, of how many bytes,
    /// how many milliseconds apart.
    pub count: u32,
    pub size: usize,
    pub interval: u64,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            host: "192.168.1.50".into(),
            port: 4242,
            count: 100,
            size: 64,
            interval: 0,
        }
    }
}

/// What the tab asks the client's thread to do.
enum Order {
    Send(Vec<u8>),
    Test {
        count: u32,
        size: usize,
        interval: Duration,
    },
    Stop,
}

/// What the client's thread tells the tab.
enum Report {
    Went(String),
    Came(String),
    Note(String),
    Bad(String),
}

/// The connection to the echo server.
enum Line {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Line {
    fn open(host: &str, port: u16, udp: bool) -> Result<Line, String> {
        let address: SocketAddr = (host.trim(), port)
            .to_socket_addrs()
            .map_err(|error| format!("Cannot find the host {host}: {error}"))?
            .next()
            .ok_or(format!("{host} has no address."))?;
        if udp {
            let local: SocketAddr = if address.is_ipv6() {
                "[::]:0".parse().unwrap_or(address)
            } else {
                "0.0.0.0:0".parse().unwrap_or(address)
            };
            let socket = UdpSocket::bind(local).map_err(|error| error.to_string())?;
            socket.connect(address).map_err(|error| error.to_string())?;
            socket
                .set_read_timeout(Some(WAIT))
                .map_err(|error| error.to_string())?;
            Ok(Line::Udp(socket))
        } else {
            let stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))
                .map_err(|error| format!("Could not connect to {address}: {error}"))?;
            let _ = stream.set_nodelay(true);
            stream
                .set_read_timeout(Some(WAIT))
                .map_err(|error| error.to_string())?;
            Ok(Line::Tcp(stream))
        }
    }

    /// Sends a message and reads its echo: what came back, and when, or
    /// none when nothing came within the wait.
    fn round_trip(&mut self, message: &[u8]) -> Result<Option<(Vec<u8>, Duration)>, String> {
        let started = Instant::now();
        match self {
            Line::Tcp(stream) => {
                stream
                    .write_all(message)
                    .map_err(|error| format!("The connection broke: {error}"))?;
                let mut back = vec![0u8; message.len()];
                let mut have = 0;
                while have < back.len() {
                    match stream.read(&mut back[have..]) {
                        Ok(0) => return Err("The server closed the connection.".into()),
                        Ok(count) => have += count,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            return Ok(None);
                        }
                        Err(error) => return Err(format!("The connection broke: {error}")),
                    }
                }
                Ok(Some((back, started.elapsed())))
            }
            Line::Udp(socket) => {
                socket
                    .send(message)
                    .map_err(|error| format!("Could not send: {error}"))?;
                let mut back = vec![0u8; 65536];
                loop {
                    let left = WAIT.saturating_sub(started.elapsed());
                    if left.is_zero() {
                        return Ok(None);
                    }
                    let _ = socket.set_read_timeout(Some(left.max(Duration::from_millis(1))));
                    match socket.recv(&mut back) {
                        Ok(count) => {
                            // The late echo of a test message before this one
                            // ("#00000007 ...") is passed over.
                            let numbered = |bytes: &[u8]| bytes.len() >= 10 && bytes[0] == b'#';
                            if numbered(message)
                                && numbered(&back[..count])
                                && back[..10] != message[..10]
                            {
                                continue;
                            }
                            back.truncate(count);
                            return Ok(Some((back, started.elapsed())));
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            return Ok(None);
                        }
                        Err(error) => return Err(format!("Nothing came back: {error}")),
                    }
                }
            }
        }
    }
}

/// A test's message: its number, then letters to its size.
fn test_message(number: u32, size: usize) -> Vec<u8> {
    let mut message = format!("#{number:08} ").into_bytes();
    let size = size.max(message.len());
    while message.len() < size {
        message.push(b'a' + (message.len() % 26) as u8);
    }
    message
}

/// The client's thread: it connects when first asked, and keeps the
/// connection for the orders after.
fn run(options: ClientOptions, udp: bool, orders: Receiver<Order>, reports: Sender<Report>) {
    let mut line: Option<Line> = None;
    let tell = |report: Report| {
        let _ = reports.send(report);
    };
    while let Ok(order) = orders.recv() {
        if line.is_none() {
            match Line::open(&options.host, options.port, udp) {
                Ok(opened) => line = Some(opened),
                Err(problem) => {
                    tell(Report::Bad(problem));
                    continue;
                }
            }
        }
        let Some(connection) = line.as_mut() else {
            continue;
        };
        match order {
            Order::Stop => {}
            Order::Send(message) => {
                tell(Report::Went(format!(
                    "{} bytes: {}",
                    message.len(),
                    short(&message)
                )));
                match connection.round_trip(&message) {
                    Ok(Some((back, time))) if back == message => tell(Report::Came(format!(
                        "The same {} bytes, back in {}.",
                        back.len(),
                        millis(time)
                    ))),
                    Ok(Some((back, time))) => tell(Report::Came(format!(
                        "{} bytes in {}, not what went: {}",
                        back.len(),
                        millis(time),
                        short(&back)
                    ))),
                    Ok(None) => tell(Report::Bad("No echo came within 2 s.".into())),
                    Err(problem) => {
                        tell(Report::Bad(problem));
                        line = None;
                    }
                }
            }
            Order::Test {
                count,
                size,
                interval,
            } => {
                let started = Instant::now();
                let (mut good, mut wrong, mut lost, mut sent) = (0u32, 0u32, 0u32, 0u32);
                let mut times = Vec::new();
                let mut stopped = false;
                for number in 1..=count {
                    match orders.try_recv() {
                        Ok(Order::Stop) | Err(TryRecvError::Disconnected) => {
                            stopped = true;
                            break;
                        }
                        _ => {}
                    }
                    let message = test_message(number, size);
                    sent += 1;
                    match connection.round_trip(&message) {
                        Ok(Some((back, time))) if back == message => {
                            good += 1;
                            times.push(time);
                        }
                        Ok(Some((back, _))) => {
                            wrong += 1;
                            tell(Report::Bad(format!(
                                "Message {number} came back changed: {}",
                                short(&back)
                            )));
                        }
                        Ok(None) => {
                            lost += 1;
                            if !udp {
                                tell(Report::Bad(
                                    "No echo for 2 s over TCP: the test stops.".into(),
                                ));
                                line = None;
                                break;
                            }
                        }
                        Err(problem) => {
                            tell(Report::Bad(problem));
                            line = None;
                            break;
                        }
                    }
                    if number * 4 / count != (number - 1) * 4 / count && number < count {
                        tell(Report::Note(format!("{number} of {count} sent.")));
                    }
                    if !interval.is_zero() {
                        thread::sleep(interval);
                    }
                }
                let over = if udp { "UDP" } else { "TCP" };
                let mut text = format!(
                    "Echo test over {over}{}: {sent} sent, {good} came back right, {lost} lost, {wrong} wrong",
                    if stopped { ", stopped" } else { "" }
                );
                if let (Some(least), Some(most)) = (times.iter().min(), times.iter().max()) {
                    let mean = times.iter().sum::<Duration>() / times.len() as u32;
                    text.push_str(&format!(
                        "; round trip least {}, mean {}, most {}",
                        millis(*least),
                        millis(mean),
                        millis(*most)
                    ));
                }
                let seconds = started.elapsed().as_secs_f64().max(0.000_001);
                text.push_str(&format!(
                    "; {size} bytes each, {:.1} KB/s back.",
                    (u64::from(good) * size as u64) as f64 / seconds / 1000.0
                ));
                tell(Report::Note(text));
            }
        }
    }
}

/// Sends messages to an echo server and checks that each comes back as it went.
pub struct Client {
    options: ClientOptions,
    orders: Sender<Order>,
    reports: Receiver<Report>,
}

impl Client {
    pub fn new(options: ClientOptions, udp: bool) -> Self {
        let (orders, ordered) = mpsc::channel();
        let (told, reports) = mpsc::channel();
        let for_thread = options.clone();
        let _ = thread::Builder::new()
            .name("netnima-echo".into())
            .spawn(move || run(for_thread, udp, ordered, told));
        Self {
            options,
            orders,
            reports,
        }
    }
}

const CLIENT_HELP: &str = "<text>                          send it, and time its echo
test [count] [size] [interval]  send count messages of size bytes, interval ms apart, and check each echo
stop                            stop the test
The echo server is the host and port in the settings: port 7, or 4242 for Zephyr's echo_server.";

impl Engine for Client {
    fn help(&self) -> &'static str {
        CLIENT_HELP
    }

    fn received(&mut self, _peer: PeerId, _bytes: &[u8], _io: &mut Io) {}

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.peek().unwrap_or_default().to_lowercase().as_str() {
            "test" => {
                words.next();
                let result = (|| -> Result<(), String> {
                    let count = words.number_or("how many messages", self.options.count)?;
                    let size = words.number_or("how many bytes each", self.options.size)?;
                    let interval: u64 =
                        words.number_or("the milliseconds between", self.options.interval)?;
                    if count == 0 {
                        return Err("A test sends one message at least.".into());
                    }
                    if size > 60_000 {
                        return Err("A message is 60000 bytes at most.".into());
                    }
                    io.note(&format!(
                        "Sending {count} messages of {size} bytes to {}, each when the one before is back.",
                        crate::net::host_and_port(&self.options.host, self.options.port)
                    ));
                    let _ = self.orders.send(Order::Test {
                        count,
                        size,
                        interval: Duration::from_millis(interval),
                    });
                    Ok(())
                })();
                if let Err(problem) = result {
                    io.bad(&problem);
                }
            }
            "stop" => {
                words.next();
                let _ = self.orders.send(Order::Stop);
            }
            _ => {
                let text = words.rest();
                if !text.is_empty() {
                    let _ = self.orders.send(Order::Send(text));
                }
            }
        }
    }

    fn tick(&mut self, _now: Instant, io: &mut Io) {
        while let Ok(report) = self.reports.try_recv() {
            match report {
                Report::Went(text) => io.went(0, &text),
                Report::Came(text) => io.came(0, &text),
                Report::Note(text) => io.note(&text),
                Report::Bad(text) => io.bad(&text),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Timing;
    use crate::net::tests::{AT_ONCE, SLOW_POLL};
    use crate::proto::tests::{
        listening, server_on_loopback, shown, start, start_timed, udp_on_loopback,
    };
    use crate::proto::{SocketKind, SocketSetup};

    #[test]
    fn the_server_answers_at_once_over_tcp_and_udp() {
        // Its socket's waits end only when something comes: an answer that
        // waited for one to time out would take seconds.
        let timing = Timing {
            batch: Duration::ZERO,
            ..SLOW_POLL
        };
        for udp in [false, true] {
            let (kind, setup) = if udp {
                let udp = Some(udp_on_loopback(0));
                (
                    SocketKind::Udp,
                    SocketSetup {
                        udp,
                        ..SocketSetup::default()
                    },
                )
            } else {
                let server = Some(server_on_loopback());
                (
                    SocketKind::Server,
                    SocketSetup {
                        server,
                        ..SocketSetup::default()
                    },
                )
            };
            let (_server, events) = start_timed(
                Box::new(Server::new(ServerOptions::default())),
                kind,
                setup,
                timing,
            );
            let port = listening(&events);
            let mut buf = [0u8; 16];
            let mut round_trip: Box<dyn FnMut() -> Vec<u8>> = if udp {
                let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket.connect(("127.0.0.1", port)).unwrap();
                Box::new(move || {
                    socket.send(b"ping").unwrap();
                    let count = socket.recv(&mut buf).unwrap();
                    buf[..count].to_vec()
                })
            } else {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream.set_nodelay(true).unwrap();
                Box::new(move || {
                    stream.write_all(b"ping").unwrap();
                    stream.read_exact(&mut buf[..4]).unwrap();
                    buf[..4].to_vec()
                })
            };
            // The first wakes the threads from their first waits.
            assert_eq!(round_trip(), b"ping");
            thread::sleep(Duration::from_millis(50));
            for _ in 0..5 {
                let start = Instant::now();
                assert_eq!(round_trip(), b"ping");
                assert!(
                    start.elapsed() < AT_ONCE,
                    "udp {udp}: {:?}",
                    start.elapsed()
                );
            }
        }
    }

    #[test]
    fn echoes_come_back_right_over_tcp_and_udp() {
        for udp in [false, true] {
            let (server, server_events) = start(
                Box::new(Server::new(ServerOptions::default())),
                if udp {
                    SocketKind::Udp
                } else {
                    SocketKind::Server
                },
                if udp {
                    SocketSetup {
                        udp: Some(udp_on_loopback(0)),
                        ..SocketSetup::default()
                    }
                } else {
                    SocketSetup {
                        server: Some(server_on_loopback()),
                        ..SocketSetup::default()
                    }
                },
            );
            let port = listening(&server_events);
            let (client, client_events) = start(
                Box::new(Client::new(
                    ClientOptions {
                        host: "127.0.0.1".into(),
                        port,
                        ..ClientOptions::default()
                    },
                    udp,
                )),
                SocketKind::None,
                SocketSetup::default(),
            );
            client.command("hello board");
            shown(&client_events, "The same 11 bytes, back in");
            shown(&server_events, "11 bytes: hello board");
            server.command("quiet");
            client.command("test 50 1000");
            let text = shown(&client_events, "Echo test over");
            assert!(
                text.contains("50 sent, 50 came back right, 0 lost, 0 wrong"),
                "{text}"
            );
            assert!(text.contains("round trip least"), "{text}");
            server.command("stats");
            shown(&server_events, "bytes came and went back");
        }
    }
}
