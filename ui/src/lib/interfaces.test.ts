// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesText, rate, selfAssigned, shownAtFirst, speedText, summary, type Interface } from "./interfaces.ts";

const WIFI: Interface = {
  name: "Wi-Fi",
  id: "{5A1B}",
  description: "Intel(R) Wi-Fi 6 AX201",
  index: 12,
  kind: "Wi-Fi",
  wifi: true,
  up: true,
  loopback: false,
  physical: true,
  default: true,
  mac: "a4:c3:f0:12:34:56",
  mtu: 1500,
  transmit_speed: 866_700_000,
  receive_speed: 866_700_000,
  ipv4: ["192.168.1.20"],
  ipv6: ["fe80::1"],
  ipv4_networks: ["192.168.1.20/24"],
  ipv6_networks: ["fe80::1/64"],
  dhcp: true,
  gateway: ["192.168.1.1"],
  gateway_mac: "12:34:56:78:9a:bc",
  dns: ["192.168.1.1"],
  received: 1_177_611_192,
  sent: 52_000,
};

test("speeds, bytes and rates are said in words", () => {
  assert.equal(speedText(866_700_000, 866_700_000), "866.7 Mbit/s");
  assert.equal(speedText(1_000_000_000, null), "1 Gbit/s");
  assert.equal(speedText(144_000_000, 72_000_000), "144 Mbit/s out, 72 Mbit/s in");
  assert.equal(speedText(null, null), "");
  assert.equal(bytesText(512), "512 B");
  assert.equal(bytesText(3277), "3.2 KB");
  assert.equal(bytesText(1_177_611_192), "1.1 GB");
  assert.equal(rate(1000, 3048, 2000), 1024);
  assert.equal(rate(5000, 10, 1000), null);
  assert.equal(rate(null, 10, 1000), null);
});

test("cards of the PC's own come first, up or down; the rest wait for Show all", () => {
  assert.equal(shownAtFirst(WIFI), true);
  // An Ethernet port with no cable: down, with only the address it gave itself.
  assert.equal(shownAtFirst({ ...WIFI, up: false, kind: "Ethernet", ipv4: ["169.254.1.2"] }), true);
  // WSL's adapter: not the PC's own, but up with an address.
  assert.equal(shownAtFirst({ ...WIFI, physical: false, kind: "Ethernet" }), true);
  // A Wi-Fi Direct adapter that is down.
  assert.equal(shownAtFirst({ ...WIFI, physical: false, up: false }), false);
  assert.equal(shownAtFirst({ ...WIFI, physical: false, loopback: true, kind: "Loopback" }), false);
  assert.equal(selfAssigned("169.254.123.23"), true);
  assert.equal(selfAssigned("192.168.1.20"), false);
});

test("an interface is copied as text", () => {
  const text = summary(WIFI);
  assert.match(text, /^Wi-Fi \(Intel\(R\) Wi-Fi 6 AX201\)\n/);
  assert.match(text, /  State: up, Wi-Fi, default route\n/);
  assert.match(text, /  IPv4: 192\.168\.1\.20\/24\n/);
  assert.match(text, /  Address by: DHCP\n/);
  assert.match(text, /  Gateway: 192\.168\.1\.1 \(12:34:56:78:9a:bc\)\n/);
  assert.doesNotMatch(summary({ ...WIFI, mtu: null, dhcp: null }), /MTU|Address by/);
});
