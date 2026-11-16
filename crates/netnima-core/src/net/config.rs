//! How each kind of socket is set up: what the tab's settings hold, and the
//! words that say what is missing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use super::tls::{TlsClientOptions, TlsServerOptions};

/// Hops a datagram may make on its way: 1 keeps multicast on the local network.
pub const DEFAULT_TTL: u32 = 64;

/// A multicast group a UDP tab joins, to hear what is sent to it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Multicast {
    /// The group, such as 239.1.2.3 or ff02::fb.
    pub group: String,
    /// For an IPv4 group, an address of the interface to join it on; empty
    /// for the one the OS picks.
    pub interface: String,
    /// For an IPv6 group, the number of the interface to join it on; 0 for
    /// the one the OS picks.
    pub interface_index: u32,
    /// Our own datagrams to the group come back to this tab too.
    pub loopback: bool,
}

/// A UDP tab: it listens, sends, or both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpConfig {
    /// The address it listens on: empty for every IPv4 address of this
    /// computer, "::" for every IPv6 one, or one address of its own.
    pub local_address: String,
    /// The port it listens on: 0 for any free one, enough for a tab that
    /// only sends and hears the answers.
    pub local_port: u16,
    /// Where the send box sends: a host name or an address. Empty to answer
    /// the peer heard from last.
    pub remote_host: String,
    pub remote_port: u16,
    /// Lets datagrams go to a broadcast address, such as 255.255.255.255.
    pub broadcast: bool,
    /// A multicast group to join.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multicast: Option<Multicast>,
    /// Hops a datagram may make, for plain and multicast datagrams alike.
    pub ttl: u32,
    /// Lets other programs listen on the same port too, as listeners on one
    /// multicast group do.
    pub reuse_address: bool,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            local_address: String::new(),
            local_port: 0,
            remote_host: String::new(),
            remote_port: 0,
            broadcast: false,
            multicast: None,
            ttl: DEFAULT_TTL,
            reuse_address: false,
        }
    }
}

impl UdpConfig {
    /// Says what is wrong, if the tab cannot open as it is.
    pub fn problem(&self) -> Option<String> {
        if let Err(problem) = local_address(&self.local_address, self.local_port) {
            return Some(problem);
        }
        if !self.remote_host.trim().is_empty() && self.remote_port == 0 {
            return Some("Enter the remote port: a number from 1 to 65535.".into());
        }
        if let Some(multicast) = &self.multicast {
            match multicast.group.trim().parse::<IpAddr>() {
                Ok(group) if group.is_multicast() => {}
                _ => {
                    return Some(format!(
                        "{} is not a multicast group: those are 224.0.0.0 to 239.255.255.255, and ff00::/8.",
                        multicast.group.trim()
                    ));
                }
            }
            if !multicast.interface.trim().is_empty()
                && multicast.interface.trim().parse::<Ipv4Addr>().is_err()
            {
                return Some(format!(
                    "{} is not an IPv4 address of an interface.",
                    multicast.interface.trim()
                ));
            }
        }
        None
    }

    /// The address it listens on, as a socket takes it.
    pub fn local(&self) -> Result<SocketAddr, String> {
        local_address(&self.local_address, self.local_port)
    }

    /// The remote address as people write it, such as "192.168.1.50:5683";
    /// empty when none is set.
    pub fn remote(&self) -> String {
        if self.remote_host.trim().is_empty() {
            String::new()
        } else {
            host_and_port(&self.remote_host, self.remote_port)
        }
    }
}

/// A TCP or Telnet client tab.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpClientConfig {
    /// A host name or an IP address.
    pub host: String,
    pub port: u16,
    /// The port to connect from: 0 for any free one, as usual.
    pub local_port: u16,
    /// Speaks Telnet: its option talk is answered and kept out of the data.
    pub telnet: bool,
    /// Sends small writes at once rather than waiting to fill a packet.
    pub no_delay: bool,
    /// Seconds between keep-alive probes on a quiet connection; 0 for none.
    pub keep_alive: u32,
    /// Connects again by itself when the other end goes away.
    pub reconnect: bool,
    /// Speaks TLS over the connection, with these settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsClientOptions>,
}

impl Default for TcpClientConfig {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 0,
            local_port: 0,
            telnet: false,
            no_delay: true,
            keep_alive: 0,
            reconnect: true,
            tls: None,
        }
    }
}

impl TcpClientConfig {
    /// Says what is wrong, if the tab cannot connect as it is.
    pub fn problem(&self) -> Option<String> {
        if self.host.trim().is_empty() {
            return Some("Enter the host: a name or an IP address, such as 192.168.1.50.".into());
        }
        if self.port == 0 {
            return Some("Enter the port: a number from 1 to 65535.".into());
        }
        None
    }

    /// "192.168.1.50:23", or "[::1]:23" for an IPv6 address.
    pub fn address(&self) -> String {
        host_and_port(&self.host, self.port)
    }
}

/// A TCP or Telnet server tab.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpServerConfig {
    /// The address it listens on: empty for every IPv4 address of this
    /// computer, "::" for every IPv6 one, or one address of its own.
    pub address: String,
    /// The port it listens on: 0 for any free one.
    pub port: u16,
    /// Speaks Telnet with each client.
    pub telnet: bool,
    /// Sends small writes at once rather than waiting to fill a packet.
    pub no_delay: bool,
    /// Seconds between keep-alive probes on a quiet connection; 0 for none.
    pub keep_alive: u32,
    /// The most clients at once; one more is closed as it comes. 0 for no limit.
    pub max_clients: u32,
    /// Speaks TLS with each client, with these settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsServerOptions>,
}

impl Default for TcpServerConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: 0,
            telnet: false,
            no_delay: true,
            keep_alive: 0,
            max_clients: 0,
            tls: None,
        }
    }
}

impl TcpServerConfig {
    /// Says what is wrong, if the tab cannot listen as it is. Port 0 takes
    /// any free port, which the tab then shows.
    pub fn problem(&self) -> Option<String> {
        local_address(&self.address, self.port).err()
    }

    /// The address it listens on, as a socket takes it.
    pub fn local(&self) -> Result<SocketAddr, String> {
        local_address(&self.address, self.port)
    }
}

/// An address of this computer and a port: empty is every IPv4 address,
/// "::" every IPv6 one. Names are not taken here: a tab listens on addresses.
pub(crate) fn local_address(address: &str, port: u16) -> Result<SocketAddr, String> {
    let address = address.trim().trim_start_matches('[').trim_end_matches(']');
    let ip = if address.is_empty() || address == "*" {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else if address == "::" {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        address.parse::<IpAddr>().map_err(|_| {
            format!(
                "{address} is not an IP address. Enter one of this computer's own, or leave it empty for all of them."
            )
        })?
    };
    Ok(SocketAddr::new(ip, port))
}

/// "localhost:19021", or "[::1]:23" for an IPv6 address.
pub fn host_and_port(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addresses_are_all_or_one_of_ours() {
        assert_eq!(
            local_address("", 5683).unwrap(),
            "0.0.0.0:5683".parse().unwrap()
        );
        assert_eq!(local_address("::", 1).unwrap(), "[::]:1".parse().unwrap());
        assert_eq!(
            local_address("[::1]", 2).unwrap(),
            "[::1]:2".parse().unwrap()
        );
        assert_eq!(
            local_address(" 192.168.1.10 ", 3).unwrap(),
            "192.168.1.10:3".parse().unwrap()
        );
        assert!(
            local_address("myhost", 4)
                .unwrap_err()
                .contains("not an IP address")
        );
    }

    #[test]
    fn a_udp_tab_needs_a_port_with_a_remote_host() {
        assert_eq!(UdpConfig::default().problem(), None);
        let no_port = UdpConfig {
            remote_host: "10.0.0.5".into(),
            ..UdpConfig::default()
        };
        assert!(no_port.problem().unwrap().contains("remote port"));
        let ok = UdpConfig {
            remote_port: 5683,
            ..no_port
        };
        assert_eq!(ok.problem(), None);
        assert_eq!(ok.remote(), "10.0.0.5:5683");
    }

    #[test]
    fn a_multicast_group_must_be_one() {
        let config = |group: &str| UdpConfig {
            multicast: Some(Multicast {
                group: group.into(),
                ..Multicast::default()
            }),
            ..UdpConfig::default()
        };
        assert_eq!(config("239.1.2.3").problem(), None);
        assert_eq!(config("ff02::fb").problem(), None);
        assert!(
            config("192.168.1.1")
                .problem()
                .unwrap()
                .contains("not a multicast group")
        );
        assert!(config("nonsense").problem().is_some());
    }

    #[test]
    fn clients_and_servers_need_a_port() {
        assert!(
            TcpClientConfig::default()
                .problem()
                .unwrap()
                .contains("port")
        );
        let client = TcpClientConfig {
            host: "::1".into(),
            port: 23,
            ..TcpClientConfig::default()
        };
        assert_eq!(client.problem(), None);
        assert_eq!(client.address(), "[::1]:23");

        assert_eq!(TcpServerConfig::default().problem(), None);
        let server = TcpServerConfig {
            address: "server".into(),
            port: 502,
            ..TcpServerConfig::default()
        };
        assert!(server.problem().unwrap().contains("not an IP address"));
    }

    #[test]
    fn settings_read_back_from_toml() {
        let config = UdpConfig {
            local_port: 5683,
            multicast: Some(Multicast {
                group: "239.1.2.3".into(),
                interface: "192.168.1.10".into(),
                interface_index: 0,
                loopback: true,
            }),
            ..UdpConfig::default()
        };
        let text = toml::to_string(&config).unwrap();
        assert_eq!(toml::from_str::<UdpConfig>(&text).unwrap(), config);
        // A value missing from the file takes its default.
        let partial: TcpClientConfig = toml::from_str("host = \"board\"\nport = 23\n").unwrap();
        assert!(partial.no_delay && partial.reconnect && !partial.telnet);
    }
}
