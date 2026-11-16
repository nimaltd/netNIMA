// The PC's network interfaces as the Interfaces window and the settings
// dialogs see them: as `InterfaceInfo` in interfaces.rs gives them, with
// speeds, byte counts and rates in words, which are shown at first, and an
// interface as text to copy. It has no imports, so its tests run in Node as
// they are.

/** One interface, as `InterfaceInfo` in interfaces.rs gives it. */
export type Interface = {
  /** The name people know it by: "Wi-Fi", "Ethernet 2", "eth0", "en0". */
  name: string;
  /** The OS's own name when that differs, such as an adapter's GUID on Windows. */
  id: string;
  description: string;
  index: number;
  /** "Ethernet", "Wi-Fi", "Loopback", "Tunnel", "PPP", "Bridge", "Mobile", "Wi-Fi Direct", "CAN" or "Other". */
  kind: string;
  wifi: boolean;
  up: boolean;
  loopback: boolean;
  /** A card of the PC's own, rather than one a VM, a VPN or the OS made. */
  physical: boolean;
  /** It has the default route: the OS sends to the internet through it. */
  default: boolean;
  mac: string;
  mtu: number | null;
  transmit_speed: number | null;
  receive_speed: number | null;
  ipv4: string[];
  ipv6: string[];
  /** The addresses with their prefixes, such as "192.168.1.10/24". */
  ipv4_networks: string[];
  ipv6_networks: string[];
  /** Whether DHCP gives its IPv4 address; null when the OS does not say. */
  dhcp: boolean | null;
  gateway: string[];
  gateway_mac: string;
  dns: string[];
  received: number | null;
  sent: number | null;
};

/** A link's speed in words, such as "1 Gbit/s" or "866.7 Mbit/s"; both ways when they differ. */
export function speedText(transmit: number | null, receive: number | null): string {
  const one = (bits: number) => {
    const [value, unit] =
      bits >= 1e9 ? [bits / 1e9, "Gbit/s"] : bits >= 1e6 ? [bits / 1e6, "Mbit/s"] : bits >= 1e3 ? [bits / 1e3, "kbit/s"] : [bits, "bit/s"];
    return `${Number(value.toFixed(1))} ${unit}`;
  };
  if (transmit === null && receive === null) return "";
  if (transmit === null || receive === null || transmit === receive) return one((transmit ?? receive) as number);
  return `${one(transmit)} out, ${one(receive)} in`;
}

/** Bytes in words: 512 B, 3.2 KB, 1.4 MB, 2.31 GB. */
export function bytesText(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${Number(value.toFixed(unit >= 2 ? 2 : 1))} ${units[unit]}`;
}

/** Bytes a second, from two counts some milliseconds apart; null when a count is missing or went back. */
export function rate(before: number | null, after: number | null, ms: number): number | null {
  if (before === null || after === null || ms <= 0 || after < before) return null;
  return ((after - before) * 1000) / ms;
}

/**
 * Whether an interface is listed before "Show all": a card of the PC's own,
 * up or down, as an Ethernet port with no cable is worth seeing; and any
 * other that is up with an address, but the loopback.
 */
export function shownAtFirst(entry: Interface): boolean {
  if (entry.loopback) return false;
  return entry.physical || (entry.up && (entry.ipv4.length > 0 || entry.ipv6.length > 0));
}

/** An IPv4 address the OS gave itself, 169.254.x.x, because no DHCP server answered. */
export function selfAssigned(address: string): boolean {
  return address.startsWith("169.254.");
}

/** An interface as text, to paste in a message or a note. */
export function summary(entry: Interface): string {
  const lines = [`${entry.name}${entry.description ? ` (${entry.description})` : ""}`];
  const add = (label: string, value: string) => {
    if (value) lines.push(`  ${label}: ${value}`);
  };
  add("State", `${entry.up ? "up" : "down"}, ${entry.kind}${entry.default ? ", default route" : ""}`);
  add("IPv4", entry.ipv4_networks.join(", "));
  add("IPv6", entry.ipv6_networks.join(", "));
  add("Address by", entry.dhcp === null ? "" : entry.dhcp ? "DHCP" : "fixed");
  add("MAC", entry.mac);
  add("MTU", entry.mtu === null ? "" : String(entry.mtu));
  add("Speed", speedText(entry.transmit_speed, entry.receive_speed));
  add("Gateway", [...entry.gateway, entry.gateway_mac ? `(${entry.gateway_mac})` : ""].filter(Boolean).join(" "));
  add("DNS", entry.dns.join(", "));
  add("Index", entry.index ? String(entry.index) : "");
  return lines.join("\n");
}
