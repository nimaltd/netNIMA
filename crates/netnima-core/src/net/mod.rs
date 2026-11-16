//! The sockets: UDP, TCP clients and servers, and Telnet and TLS on top of TCP.
//!
//! Each session runs on its own thread, which waits on its sockets and on a
//! wake-up socket that each command from the app wakes, so what is sent goes
//! out at once. It tells the app what happens through one callback: its
//! state, the peers that come and go, and the data, each piece with the peer
//! it came from.

mod config;
mod dtls;
mod interfaces;
mod legacy;
mod link;
pub(crate) mod secure;
mod tcp_client;
mod tcp_server;
mod telnet;
pub mod tls;
#[cfg(test)]
mod tls_tests;
mod udp;
mod wake;

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use config::{
    DEFAULT_TTL, Multicast, TcpClientConfig, TcpServerConfig, UdpConfig, host_and_port,
};
pub use dtls::{DtlsOptions, DtlsSession, DtlsVersion, psk_key};
pub use interfaces::{InterfaceInfo, interfaces, own_addresses};
pub use tcp_client::TcpClient;
pub use tcp_server::TcpServer;
pub use tls::{
    Agreed, CertInfo, ClientAuth, Engine, TlsClientOptions, TlsServerOptions, Verify, Versions,
};
pub use udp::UdpSession;

/// A peer's number: from 1 up, in the order a session met them, so the app
/// can name one when it sends. Each session counts its own.
pub type PeerId = u32;

/// Another end a session talks to: the server a client connected to, a
/// client a server took, or the sender of a datagram.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Peer {
    pub id: PeerId,
    /// Its address and port, such as "192.168.1.50:5683" or "[::1]:4000".
    pub address: String,
}

/// Where a session is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NetState {
    /// Not connected or listening yet. `problem` says why, when something is
    /// wrong, such as a port in use; without it, the other end is not there yet.
    Waiting { problem: Option<String> },
    /// A client, connected: `address` is the other end, `local` this end.
    Connected { address: String, local: String },
    /// A client whose connection ended, which does not connect again by
    /// itself: `problem` says why.
    Ended { problem: Option<String> },
    /// A server or a UDP socket, open on `local`.
    Listening { local: String },
}

/// What a session tells the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    State(NetState),
    /// A peer came: a client connected, a server was connected to, or a
    /// datagram came from an address not heard before.
    PeerJoined(Peer),
    /// A peer went: its connection ended. UDP peers stay until the session ends.
    PeerLeft(PeerId),
    /// Bytes that came from a peer: a piece of its stream, or one datagram.
    Data {
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A peer's TLS handshake ended well: what the two ends agreed.
    Secure {
        peer: PeerId,
        agreed: Agreed,
    },
    /// Something went wrong that does not end the session, such as a
    /// datagram that could not be sent.
    Problem(String),
    /// What a protocol's engine tells its tab's view, as an object the view
    /// reads rather than a line people read: an MQTT message that came,
    /// with its topic and payload, or a client that connected to a broker.
    Report(serde_json::Value),
}

/// Who a write goes to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(tag = "to", content = "peer", rename_all = "snake_case")]
pub enum Target {
    /// The other end a client is connected to, or a UDP tab's remote address
    /// as set; on a server, the peer heard from last.
    #[default]
    Default,
    /// One peer, by its number.
    Peer(PeerId),
    /// Every peer at once.
    All,
}

/// How long things take. Tests make the times shorter.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// Between two tries to connect or to open a socket.
    pub retry: Duration,
    /// The longest one try to connect to one address takes.
    pub connect: Duration,
    /// The longest a session's thread waits on its sockets before it looks at
    /// its timers again. What the app sends wakes it at once.
    pub poll: Duration,
    /// The longest received bytes of a stream wait before they are passed
    /// on, so the screen updates about 60 times a second.
    pub batch: Duration,
    /// The longest a DTLS handshake may take.
    pub handshake: Duration,
}

pub(crate) const TIMING: Timing = Timing {
    retry: Duration::from_secs(1),
    connect: Duration::from_secs(3),
    poll: Duration::from_millis(10),
    batch: Duration::from_millis(16),
    handshake: Duration::from_secs(15),
};

impl Timing {
    /// A tab's socket's timing: the usual, which gathers what a stream brings
    /// for the screen; or, `at_once`, what passes it on as it comes, for a
    /// view that times what it hears, as the Modbus view times each answer.
    pub fn of_tab(at_once: bool) -> Self {
        if at_once {
            Timing {
                batch: Duration::ZERO,
                ..TIMING
            }
        } else {
            TIMING
        }
    }
}

/// The most bytes of a stream passed on at once.
pub(crate) const BATCH_MAX: usize = 64 * 1024;

/// Errors that only mean nothing arrived during a read.
pub(crate) fn is_quiet(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
    )
}

/// Errors that only mean nothing listens there yet, which is waited out.
pub(crate) fn is_not_there(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
    )
}

/// Where a host is, IPv4 first: most devices listen there, and on Windows a
/// refused connection to localhost's IPv6 address takes seconds.
pub(crate) fn addresses(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let mut addresses: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    addresses.sort_by_key(SocketAddr::is_ipv6);
    Ok(addresses)
}

/// Why a socket could not be opened on `local`, in words: a port taken, one
/// that needs rights, or an address this computer does not have.
pub(crate) fn open_problem(local: &str, error: &io::Error) -> String {
    match error.kind() {
        ErrorKind::AddrInUse => format!(
            "Port {} is in use by another program, or by another tab. Close it there, or choose another port.",
            port_of(local)
        ),
        ErrorKind::PermissionDenied => {
            if cfg!(target_os = "linux") {
                format!(
                    "Linux lets only programs with the right open port {} and the others below 1024. Choose a port from 1024 up.",
                    port_of(local)
                )
            } else {
                format!("This computer did not let netNIMA open {local}: {error}")
            }
        }
        ErrorKind::AddrNotAvailable => {
            format!(
                "This computer has no address {local}. Choose one of its own, or leave it empty for all."
            )
        }
        _ => format!("Could not open {local}: {error}"),
    }
}

/// The port in "host:port", for messages.
fn port_of(address: &str) -> &str {
    address.rsplit(':').next().unwrap_or(address)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::mpsc::Receiver;
    use std::time::Instant;

    use super::*;

    pub(crate) const FAST: Timing = Timing {
        retry: Duration::from_millis(20),
        connect: Duration::from_secs(2),
        poll: Duration::from_millis(5),
        batch: Duration::from_millis(5),
        handshake: Duration::from_secs(3),
    };

    /// Waits that end only when something comes: a session that does what it
    /// is asked within `AT_ONCE` with these was woken, not timed out.
    pub(crate) const SLOW_POLL: Timing = Timing {
        poll: Duration::from_secs(3),
        ..FAST
    };

    /// The longest a send may take with `SLOW_POLL`.
    pub(crate) const AT_ONCE: Duration = Duration::from_millis(1000);

    /// Waits for the first event that `wanted` accepts, skipping the others.
    pub(crate) fn expect(
        events: &Receiver<Event>,
        what: &str,
        wanted: impl Fn(&Event) -> bool,
    ) -> Event {
        let until = Instant::now() + Duration::from_secs(5);
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match events.recv_timeout(left) {
                Ok(event) if wanted(&event) => return event,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("no {what} within 5 s");
    }

    /// Waits for a new peer, and gives it back.
    pub(crate) fn joined(events: &Receiver<Event>) -> Peer {
        match expect(events, "peer", |event| {
            matches!(event, Event::PeerJoined(_))
        }) {
            Event::PeerJoined(peer) => peer,
            _ => unreachable!(),
        }
    }

    /// Waits for the peer at `address` to come, past any other.
    pub(crate) fn joined_from(events: &Receiver<Event>, address: &str) -> Peer {
        match expect(
            events,
            "peer",
            |event| matches!(event, Event::PeerJoined(peer) if peer.address == address),
        ) {
            Event::PeerJoined(peer) => peer,
            _ => unreachable!(),
        }
    }

    /// Waits for the session's state to be one that `wanted` accepts.
    pub(crate) fn state(
        events: &Receiver<Event>,
        what: &str,
        wanted: impl Fn(&NetState) -> bool,
    ) -> NetState {
        match expect(
            events,
            what,
            |event| matches!(event, Event::State(state) if wanted(state)),
        ) {
            Event::State(state) => state,
            _ => unreachable!(),
        }
    }

    /// Collects the data of one peer until `count` bytes have come.
    pub(crate) fn received(events: &Receiver<Event>, from: PeerId, count: usize) -> Vec<u8> {
        let mut data = Vec::new();
        while data.len() < count {
            if let Event::Data { bytes, .. } = expect(
                events,
                "data",
                |event| matches!(event, Event::Data { peer, .. } if *peer == from),
            ) {
                data.extend(bytes);
            }
        }
        data
    }

    #[test]
    fn a_taken_port_is_said_in_words() {
        let error = io::Error::from(ErrorKind::AddrInUse);
        let text = open_problem("0.0.0.0:5683", &error);
        assert!(text.contains("Port 5683 is in use"), "{text}");
        let missing = io::Error::from(ErrorKind::AddrNotAvailable);
        assert!(open_problem("10.9.9.9:1", &missing).contains("no address 10.9.9.9:1"));
    }

    #[test]
    fn targets_read_from_the_ui() {
        let all: Target = serde_json::from_str(r#"{"to":"all"}"#).unwrap();
        assert_eq!(all, Target::All);
        let one: Target = serde_json::from_str(r#"{"to":"peer","peer":3}"#).unwrap();
        assert_eq!(one, Target::Peer(3));
        let usual: Target = serde_json::from_str(r#"{"to":"default"}"#).unwrap();
        assert_eq!(usual, Target::Default);
    }
}
