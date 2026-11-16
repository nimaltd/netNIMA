//! Ping: ICMP echo, with times, losses and the TTL that came back. On
//! Windows it asks the OS's ICMP API, which needs no rights; on Linux and
//! macOS it uses an ICMP datagram socket, which ordinary users may open.
//!
//! The pings run on a thread of their own, so a host that does not answer
//! never holds the tab up.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{Engine, Io, Words};
use crate::net::PeerId;

/// What one echo request found.
#[derive(Clone, Debug, PartialEq)]
pub enum Answer {
    /// It came back, in this many ms, from this address, with this TTL.
    Reply {
        from: Ipv4Addr,
        ms: f64,
        ttl: u8,
        bytes: usize,
    },
    /// Nothing within the time allowed.
    TimedOut,
    /// A router said why it could not deliver it.
    Failed(String),
}

/// A ping tab's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct PingOptions {
    pub host: String,
    /// Between two pings, in ms.
    pub interval: u64,
    /// How many to send: 0 for until stopped.
    pub count: u32,
    /// The bytes of data in each.
    pub size: u16,
    /// How long each waits for its answer, in ms.
    pub timeout: u64,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            interval: 1000,
            count: 0,
            size: 32,
            timeout: 1000,
        }
    }
}

/// The IPv4 address of a host.
fn resolve(host: &str) -> Result<Ipv4Addr, String> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    (host, 0)
        .to_socket_addrs()
        .map_err(|error| format!("Cannot find the host {host}: {error}"))?
        .find_map(|address| match address.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("{host} has no IPv4 address."))
}

#[cfg(windows)]
mod icmp {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    };

    use super::Answer;

    /// The OS's ICMP handle, closed when dropped.
    pub struct Pinger(HANDLE);

    // Safe: the handle is only used from the thread that owns the pinger.
    unsafe impl Send for Pinger {}

    impl Pinger {
        pub fn new() -> Result<Self, String> {
            // Safe: no arguments; the handle is checked before it is used.
            let handle = unsafe { IcmpCreateFile() };
            if handle == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "Windows could not open ICMP: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self(handle))
        }

        pub fn ping(
            &mut self,
            to: Ipv4Addr,
            _sequence: u16,
            size: u16,
            timeout: Duration,
        ) -> Answer {
            let data: Vec<u8> = (0..size).map(|index| b'a' + (index % 23) as u8).collect();
            let mut reply =
                vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + usize::from(size) + 64];
            let started = Instant::now();
            // Safe: the buffers live through the call and their sizes are the ones given.
            let count = unsafe {
                IcmpSendEcho(
                    self.0,
                    u32::from_ne_bytes(to.octets()),
                    data.as_ptr().cast(),
                    size,
                    std::ptr::null(),
                    reply.as_mut_ptr().cast(),
                    reply.len() as u32,
                    timeout.as_millis().clamp(1, u128::from(u32::MAX)) as u32,
                )
            };
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            // Safe: the buffer is at least one reply long, and IcmpSendEcho filled it.
            let answer: ICMP_ECHO_REPLY =
                unsafe { std::ptr::read_unaligned(reply.as_ptr().cast()) };
            if count == 0 {
                return if answer.Status == 11010 || answer.Status == 0 {
                    Answer::TimedOut
                } else {
                    Answer::Failed(status_text(answer.Status))
                };
            }
            if answer.Status != 0 {
                return Answer::Failed(status_text(answer.Status));
            }
            Answer::Reply {
                from: Ipv4Addr::from(answer.Address.to_ne_bytes()),
                ms: if answer.RoundTripTime == 0 {
                    elapsed.min(1.0)
                } else {
                    f64::from(answer.RoundTripTime).min(elapsed)
                },
                ttl: answer.Options.Ttl,
                bytes: usize::from(answer.DataSize),
            }
        }
    }

    impl Drop for Pinger {
        fn drop(&mut self) {
            // Safe: the handle was opened by IcmpCreateFile and is closed once.
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }

    fn status_text(status: u32) -> String {
        match status {
            11002 => "the destination network is unreachable".into(),
            11003 => "the destination host is unreachable".into(),
            11004 => "the destination protocol is unreachable".into(),
            11005 => "the destination port is unreachable".into(),
            11010 => "timed out".into(),
            11013 => "the TTL ran out on the way".into(),
            11050 => "a general failure: is the network up?".into(),
            other => format!("ICMP status {other}"),
        }
    }
}

#[cfg(unix)]
mod icmp {
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, Socket, Type};

    use super::Answer;

    pub struct Pinger(Socket);

    impl Pinger {
        pub fn new() -> Result<Self, String> {
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).map(Self).map_err(|error| {
                format!("An ICMP socket could not be opened: {error}. On Linux, ping_group_range must take this user.")
            })
        }

        pub fn ping(
            &mut self,
            to: Ipv4Addr,
            sequence: u16,
            size: u16,
            timeout: Duration,
        ) -> Answer {
            let mut packet = vec![8, 0, 0, 0, 0x4e, 0x4e];
            packet.extend_from_slice(&sequence.to_be_bytes());
            packet.extend((0..size).map(|index| b'a' + (index % 23) as u8));
            let sum = checksum(&packet);
            packet[2..4].copy_from_slice(&sum.to_be_bytes());
            let started = Instant::now();
            let address = SocketAddr::from((to, 0));
            if let Err(error) = self.0.send_to(&packet, &address.into()) {
                return Answer::Failed(error.to_string());
            }
            let until = started + timeout;
            let mut buffer = [MaybeUninit::<u8>::uninit(); 2048];
            loop {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Answer::TimedOut;
                }
                let _ = self.0.set_read_timeout(Some(left));
                let Ok((count, from)) = self.0.recv_from(&mut buffer) else {
                    return Answer::TimedOut;
                };
                // Safe: recv_from filled the first `count` bytes.
                let bytes: Vec<u8> = buffer[..count]
                    .iter()
                    .map(|byte| unsafe { byte.assume_init() })
                    .collect();
                // macOS gives the IP header too; Linux does not.
                let (ttl, icmp) = if bytes.first().is_some_and(|first| first >> 4 == 4) {
                    let header = usize::from(bytes[0] & 0x0f) * 4;
                    (
                        bytes.get(8).copied().unwrap_or(0),
                        bytes.get(header..).unwrap_or(&[]).to_vec(),
                    )
                } else {
                    (0, bytes)
                };
                if icmp.first() == Some(&0) && icmp.get(6..8) == Some(&sequence.to_be_bytes()[..]) {
                    let from = from.as_socket_ipv4().map_or(to, |from| *from.ip());
                    return Answer::Reply {
                        from,
                        ms: started.elapsed().as_secs_f64() * 1000.0,
                        ttl,
                        bytes: icmp.len().saturating_sub(8),
                    };
                }
            }
        }
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = bytes
            .chunks(2)
            .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// What the pinging thread tells the tab.
enum Report {
    Answer { sequence: u16, answer: Answer },
    Problem(String),
    Done,
}

struct Running {
    stop: Arc<AtomicBool>,
    reports: Receiver<Report>,
    host: String,
    address: Ipv4Addr,
    sent: u32,
    received: u32,
    times: Vec<f64>,
}

/// Pings a host, and says how it went.
pub struct Ping {
    options: PingOptions,
    running: Option<Running>,
    /// Whether the pings the tab was set up for have started.
    begun: bool,
}

impl Ping {
    pub fn new(options: PingOptions) -> Self {
        Self {
            options,
            running: None,
            begun: false,
        }
    }

    fn start(&mut self, host: &str, io: &mut Io) {
        self.stop(io);
        let address = match resolve(host) {
            Ok(address) => address,
            Err(problem) => {
                io.bad(&problem);
                return;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, reports): (Sender<Report>, Receiver<Report>) = mpsc::channel();
        let options = self.options.clone();
        let stopped = stop.clone();
        let spawned = thread::Builder::new()
            .name("netnima-ping".into())
            .spawn(move || {
                let mut pinger = match icmp::Pinger::new() {
                    Ok(pinger) => pinger,
                    Err(problem) => {
                        let _ = sender.send(Report::Problem(problem));
                        return;
                    }
                };
                let mut sequence: u16 = 0;
                while !stopped.load(Ordering::Relaxed)
                    && (options.count == 0 || u32::from(sequence) < options.count)
                {
                    let started = Instant::now();
                    sequence = sequence.wrapping_add(1);
                    let answer = pinger.ping(
                        address,
                        sequence,
                        options.size,
                        Duration::from_millis(options.timeout.max(10)),
                    );
                    if sender.send(Report::Answer { sequence, answer }).is_err() {
                        return;
                    }
                    let interval = Duration::from_millis(options.interval.max(100));
                    while started.elapsed() < interval && !stopped.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_millis(20));
                    }
                }
                let _ = sender.send(Report::Done);
            });
        if let Err(error) = spawned {
            io.bad(&format!("Could not start pinging: {error}"));
            return;
        }
        io.went(
            0,
            &format!(
                "ping {host} ({address}), {} bytes of data",
                self.options.size
            ),
        );
        self.running = Some(Running {
            stop,
            reports,
            host: host.to_string(),
            address,
            sent: 0,
            received: 0,
            times: Vec::new(),
        });
    }

    fn stop(&mut self, io: &mut Io) {
        if let Some(running) = self.running.take() {
            running.stop.store(true, Ordering::Relaxed);
            summary(&running, io);
        }
    }
}

fn summary(running: &Running, io: &mut Io) {
    let lost = running.sent.saturating_sub(running.received);
    let mut line = format!(
        "{} ({}): {} sent, {} came back, {lost} lost ({:.0}%)",
        running.host,
        running.address,
        running.sent,
        running.received,
        if running.sent > 0 {
            f64::from(lost) * 100.0 / f64::from(running.sent)
        } else {
            0.0
        }
    );
    if !running.times.is_empty() {
        let min = running.times.iter().copied().fold(f64::MAX, f64::min);
        let max = running.times.iter().copied().fold(0.0, f64::max);
        let average = running.times.iter().sum::<f64>() / running.times.len() as f64;
        line.push_str(&format!(
            "; time min {min:.2} ms, average {average:.2} ms, max {max:.2} ms"
        ));
    }
    io.note(&line);
}

impl Engine for Ping {
    fn help(&self) -> &'static str {
        "ping [host]     ping the host set, or another; again to start over
stop            stop, and say how it went
stats           how it goes so far"
    }

    fn received(&mut self, _peer: PeerId, _bytes: &[u8], _io: &mut Io) {}

    fn command(&mut self, words: &mut Words, io: &mut Io) {
        match words.next().unwrap_or_default().to_lowercase().as_str() {
            "ping" | "start" => {
                let host = words.next().unwrap_or_else(|| self.options.host.clone());
                self.start(&host, io);
            }
            "stop" => self.stop(io),
            "stats" => match &self.running {
                Some(running) => summary(running, io),
                None => io.note("Not pinging: type ping."),
            },
            other => io.bad(&format!(
                "{other} is not a command here. Type help for the list."
            )),
        }
    }

    fn tick(&mut self, _now: Instant, io: &mut Io) {
        // The first tick starts the pings the tab was set up for.
        if !self.begun {
            self.begun = true;
            let host = self.options.host.trim().to_string();
            if !host.is_empty() {
                self.start(&host, io);
            }
        }
        let Some(running) = &mut self.running else {
            return;
        };
        let mut done = false;
        while let Ok(report) = running.reports.try_recv() {
            match report {
                Report::Answer { sequence, answer } => {
                    running.sent += 1;
                    match answer {
                        Answer::Reply {
                            from,
                            ms,
                            ttl,
                            bytes,
                        } => {
                            running.received += 1;
                            running.times.push(ms);
                            let ttl = if ttl > 0 {
                                format!(", ttl {ttl}")
                            } else {
                                String::new()
                            };
                            io.came(0, &format!("{bytes} bytes from {from}: seq {sequence}, time {ms:.2} ms{ttl}"));
                        }
                        Answer::TimedOut => io.bad(&format!("seq {sequence}: no answer")),
                        Answer::Failed(why) => io.bad(&format!("seq {sequence}: {why}")),
                    }
                }
                Report::Problem(problem) => {
                    io.bad(&problem);
                    done = true;
                }
                Report::Done => done = true,
            }
        }
        if done {
            let running = self.running.take();
            if let Some(running) = running {
                summary(&running, io);
            }
        }
    }
}

impl Drop for Ping {
    fn drop(&mut self) {
        if let Some(running) = &self.running {
            running.stop.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_found() {
        assert_eq!(resolve("127.0.0.1").unwrap(), Ipv4Addr::LOCALHOST);
        assert_eq!(resolve("localhost").unwrap(), Ipv4Addr::LOCALHOST);
        assert!(resolve("no.such.host.invalid").is_err());
    }

    #[test]
    fn the_loopback_answers() {
        // An ICMP socket may be closed to ordinary users on some Linux
        // systems: then there is nothing to test here.
        let Ok(mut pinger) = icmp::Pinger::new() else {
            return;
        };
        match pinger.ping(Ipv4Addr::LOCALHOST, 1, 32, Duration::from_secs(2)) {
            Answer::Reply { from, ms, .. } => {
                assert_eq!(from, Ipv4Addr::LOCALHOST);
                assert!(ms < 1000.0);
            }
            other => panic!("the loopback did not answer: {other:?}"),
        }
    }
}
