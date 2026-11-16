//! The computer's network interfaces: for a tab to listen on one or join a
//! multicast group on one, and for the Interfaces window, which shows each
//! with its addresses, MAC address, MTU, state, speed, gateway and DNS
//! servers, and says which are Wi-Fi.

use std::net::IpAddr;

use netdev::interface::types::InterfaceType;
use serde::Serialize;

/// One interface, with all its addresses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfaceInfo {
    /// The name people know it by, such as "Ethernet 2" or "Wi-Fi" on
    /// Windows, "eth0" on Linux or "en0" on macOS.
    pub name: String,
    /// The OS's own name for it when that differs, such as an adapter's GUID
    /// on Windows; empty otherwise.
    pub id: String,
    /// What it is, as its driver says, such as "Intel(R) Ethernet Connection I219-V".
    pub description: String,
    /// Its number, which an IPv6 multicast group is joined with; 0 when the OS gives none.
    pub index: u32,
    /// Its kind in a word: "Ethernet", "Wi-Fi", "Loopback", "Tunnel", "PPP",
    /// "Bridge", "Mobile", "Wi-Fi Direct", "CAN" or "Other".
    pub kind: String,
    pub wifi: bool,
    pub up: bool,
    pub loopback: bool,
    /// Whether it is a card of the PC's own, such as its Ethernet port or a
    /// USB adapter, rather than one a VM, a VPN or the OS made.
    pub physical: bool,
    /// Whether the OS sends to the internet through it: it has the default route.
    pub default: bool,
    /// Its MAC address, such as "a4:c3:f0:12:34:56"; empty when it has none.
    pub mac: String,
    pub mtu: Option<u32>,
    /// Its link's speeds, in bits per second, when the OS says.
    pub transmit_speed: Option<u64>,
    pub receive_speed: Option<u64>,
    /// Its addresses alone, for the lists of addresses to listen on.
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// The same addresses with their prefix lengths, such as "192.168.1.10/24".
    pub ipv4_networks: Vec<String>,
    pub ipv6_networks: Vec<String>,
    /// Whether DHCP gives it its IPv4 address, when the OS says; false is a fixed address.
    pub dhcp: Option<bool>,
    /// Its default gateway's addresses and MAC address, when it has one.
    pub gateway: Vec<String>,
    pub gateway_mac: String,
    pub dns: Vec<String>,
    /// The bytes it received and sent since the OS started counting, when it says.
    pub received: Option<u64>,
    pub sent: Option<u64>,
}

/// An interface's kind in a word.
fn kind_name(kind: InterfaceType) -> String {
    match kind {
        InterfaceType::Ethernet
        | InterfaceType::Ethernet3Megabit
        | InterfaceType::FastEthernetT
        | InterfaceType::FastEthernetFx
        | InterfaceType::GigabitEthernet => "Ethernet".into(),
        InterfaceType::Wireless80211 => "Wi-Fi".into(),
        InterfaceType::PeerToPeerWireless => "Wi-Fi Direct".into(),
        InterfaceType::Loopback => "Loopback".into(),
        InterfaceType::Tunnel => "Tunnel".into(),
        InterfaceType::Ppp => "PPP".into(),
        InterfaceType::Bridge => "Bridge".into(),
        InterfaceType::Wwan | InterfaceType::Wwanpp | InterfaceType::Wwanpp2 => "Mobile".into(),
        InterfaceType::Can => "CAN".into(),
        _ => "Other".into(),
    }
}

/// The first three bytes of MAC addresses that VMs and the OS give their own
/// adapters, beside those netdev knows: Hyper-V's, as WSL's vEthernet has,
/// QEMU's and VirtualBox's host-only adapters'.
const VIRTUAL_MACS: [[u8; 3]; 3] = [[0x00, 0x15, 0x5d], [0x52, 0x54, 0x00], [0x0a, 0x00, 0x27]];

/// The DNS servers Windows lists on an interface given none: the old
/// site-local addresses fec0:0:0:ffff::1 to ::3, which no one answers at.
fn placeholder_dns(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[..7] == [0xfec0, 0, 0, 0xffff, 0, 0, 0] && (1..=3).contains(&v6.segments()[7]))
}

/// What the OS says of one interface, as the views want it.
fn info(interface: &netdev::Interface) -> InterfaceInfo {
    let name = interface
        .friendly_name
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| interface.name.clone());
    let id = if name == interface.name {
        String::new()
    } else {
        interface.name.clone()
    };
    let gateway = interface.gateway.as_ref();
    let gateway_mac = gateway
        .map(|device| device.mac_addr)
        .filter(|mac| *mac != netdev::MacAddr::zero())
        .map(|mac| mac.to_string())
        .unwrap_or_default();
    let loopback = interface.is_loopback();
    let virtual_mac = interface.mac_addr.is_some_and(|mac| {
        let octets = mac.octets();
        VIRTUAL_MACS.iter().any(|prefix| octets[..3] == prefix[..])
    });
    let mut dns: Vec<String> = Vec::new();
    for server in interface
        .dns_servers
        .iter()
        .filter(|ip| !placeholder_dns(ip))
    {
        let server = server.to_string();
        if !dns.contains(&server) {
            dns.push(server);
        }
    }
    InterfaceInfo {
        name,
        id,
        description: interface.description.clone().unwrap_or_default(),
        index: interface.index,
        kind: kind_name(interface.if_type),
        wifi: interface.if_type == InterfaceType::Wireless80211,
        up: interface.is_up() || interface.is_oper_up(),
        loopback,
        physical: interface.is_physical() && !virtual_mac && !loopback,
        default: interface.default,
        mac: interface
            .mac_addr
            .filter(|mac| *mac != netdev::MacAddr::zero())
            .map(|mac| mac.to_string())
            .unwrap_or_default(),
        // A loopback says it takes any size, and any speed: neither is worth showing.
        mtu: interface.mtu.filter(|mtu| *mtu != u32::MAX && !loopback),
        transmit_speed: interface
            .transmit_speed
            .filter(|speed| *speed > 0 && !loopback),
        receive_speed: interface
            .receive_speed
            .filter(|speed| *speed > 0 && !loopback),
        ipv4: interface
            .ipv4
            .iter()
            .map(|net| net.addr().to_string())
            .collect(),
        ipv6: interface
            .ipv6
            .iter()
            .map(|net| net.addr().to_string())
            .collect(),
        ipv4_networks: interface.ipv4.iter().map(ToString::to_string).collect(),
        ipv6_networks: interface.ipv6.iter().map(ToString::to_string).collect(),
        dhcp: interface.dhcp_v4_enabled,
        gateway: gateway
            .map(|device| {
                device
                    .ipv4
                    .iter()
                    .map(ToString::to_string)
                    .chain(device.ipv6.iter().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        gateway_mac,
        dns,
        received: interface.stats.as_ref().map(|stats| stats.rx_bytes),
        sent: interface.stats.as_ref().map(|stats| stats.tx_bytes),
    }
}

/// Every address of the interfaces that are up, the loopback's too: for a
/// certificate made for this PC, or the address an FTP server gives for PASV.
pub fn own_addresses() -> Vec<IpAddr> {
    netdev::get_interfaces()
        .iter()
        .filter(|interface| interface.is_up() || interface.is_oper_up())
        .flat_map(netdev::Interface::ip_addrs)
        .collect()
}

/// Every interface the OS lists: those that are up first, the one with the
/// default route first among them, then the PC's own cards before the
/// virtual ones, those with addresses, Ethernet and Wi-Fi, and the loopback
/// last of those that are up.
pub fn interfaces() -> Vec<InterfaceInfo> {
    let mut list: Vec<InterfaceInfo> = netdev::get_interfaces().iter().map(info).collect();
    list.sort_by_key(|entry| {
        (
            !entry.up,
            entry.loopback,
            !entry.default,
            !entry.physical,
            entry.ipv4.is_empty() && entry.ipv6.is_empty(),
            !matches!(entry.kind.as_str(), "Ethernet" | "Wi-Fi"),
        )
    });
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_interface_listed_has_a_name_and_its_addresses_twice() {
        let all = interfaces();
        assert!(!all.is_empty(), "the OS lists no interface");
        for entry in &all {
            assert!(!entry.name.is_empty(), "{entry:?}");
            assert_eq!(entry.ipv4.len(), entry.ipv4_networks.len(), "{entry:?}");
            assert_eq!(entry.ipv6.len(), entry.ipv6_networks.len(), "{entry:?}");
            for (address, network) in entry.ipv4.iter().zip(&entry.ipv4_networks) {
                assert!(network.starts_with(&format!("{address}/")), "{entry:?}");
            }
            if !entry.mac.is_empty() {
                assert_eq!(entry.mac.len(), 17, "{entry:?}");
            }
        }
        // The loopback, if the OS lists it, comes after every interface that is up.
        if let Some(loopback) = all.iter().position(|entry| entry.loopback) {
            assert!(
                all[loopback + 1..]
                    .iter()
                    .all(|entry| !entry.up || entry.loopback),
                "{all:?}"
            );
        }
        // Of those that are down, the PC's own cards come before the virtual ones.
        let down: Vec<&InterfaceInfo> = all.iter().filter(|entry| !entry.up).collect();
        if let Some(first_virtual) = down.iter().position(|entry| !entry.physical) {
            assert!(
                down[first_virtual..].iter().all(|entry| !entry.physical),
                "{all:?}"
            );
        }
    }

    #[test]
    fn windows_placeholder_dns_servers_are_left_out() {
        for placeholder in ["fec0:0:0:ffff::1", "fec0:0:0:ffff::3"] {
            assert!(placeholder_dns(&placeholder.parse().unwrap()));
        }
        for real in ["fec0:0:0:ffff::4", "192.168.0.1", "2a02:8388::1"] {
            assert!(!placeholder_dns(&real.parse().unwrap()));
        }
    }

    #[test]
    fn kinds_are_said_in_a_word() {
        assert_eq!(kind_name(InterfaceType::GigabitEthernet), "Ethernet");
        assert_eq!(kind_name(InterfaceType::Wireless80211), "Wi-Fi");
        assert_eq!(kind_name(InterfaceType::Wwanpp2), "Mobile");
        assert_eq!(kind_name(InterfaceType::Unknown), "Other");
    }
}
