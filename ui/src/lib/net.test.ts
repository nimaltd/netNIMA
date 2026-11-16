// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { clientText, hostAndPort, localText, portProblem, readFrame, serverText, targetOf, udpText } from "./net.ts";
import { DEFAULT_TCP_CLIENT, DEFAULT_TCP_SERVER, DEFAULT_UDP } from "./net.ts";

test("a frame gives back its flags, peer, time and bytes", () => {
  const bytes = new Uint8Array(13 + 2);
  const view = new DataView(bytes.buffer);
  bytes[0] = 1;
  view.setUint32(1, 7, true);
  view.setFloat64(5, 1_700_000_000_000.5, true);
  bytes.set([104, 105], 13);
  const frame = readFrame(bytes.buffer);
  assert.ok(frame);
  assert.equal(frame.sent, true);
  assert.equal(frame.peer, 7);
  assert.equal(frame.at, 1_700_000_000_000.5);
  assert.deepEqual([...frame.bytes], [104, 105]);
  assert.equal(readFrame(new Uint8Array(5)), null);
});

test("addresses are written as people read them", () => {
  assert.equal(hostAndPort("192.168.1.50", 5683), "192.168.1.50:5683");
  assert.equal(hostAndPort("::1", 23), "[::1]:23");
  assert.equal(localText("", 0), "all addresses, any free port");
  assert.equal(localText("127.0.0.1", 502), "127.0.0.1, port 502");
});

test("each kind's settings in a few words", () => {
  assert.equal(udpText({ ...DEFAULT_UDP, local_port: 5683 }), "UDP :5683");
  assert.equal(
    udpText({ ...DEFAULT_UDP, remote_host: "10.0.0.5", remote_port: 5683 }),
    "UDP any port → 10.0.0.5:5683",
  );
  assert.equal(clientText({ ...DEFAULT_TCP_CLIENT, host: "board", port: 23, telnet: true }), "Telnet to board:23");
  assert.equal(serverText({ ...DEFAULT_TCP_SERVER, port: 502 }), "TCP server on :502");
});

test("ports are checked before they are asked for", () => {
  assert.equal(portProblem(502, true), null);
  assert.equal(portProblem(0, false), null);
  assert.match(portProblem(0, true) ?? "", /Enter the port/);
  assert.match(portProblem(70000, false) ?? "", /whole number/);
});

test("the send box's target reads back", () => {
  assert.deepEqual(targetOf("all"), { to: "all" });
  assert.deepEqual(targetOf("peer:3"), { to: "peer", peer: 3 });
  assert.deepEqual(targetOf("default"), { to: "default" });
  assert.deepEqual(targetOf("peer:x"), { to: "default" });
});

test("a TLS tab says it speaks TLS, and what TLS agreed reads in one line", async () => {
  const { DEFAULT_TLS_CLIENT, DEFAULT_TLS_SERVER, agreedText, certText } = await import("./net.ts");
  assert.equal(clientText({ ...DEFAULT_TCP_CLIENT, host: "10.0.0.5", port: 8883, tls: DEFAULT_TLS_CLIENT }), "TLS to 10.0.0.5:8883");
  assert.equal(serverText({ ...DEFAULT_TCP_SERVER, port: 443, tls: DEFAULT_TLS_SERVER }), "TLS server on :443");
  assert.equal(
    agreedText({ version: "TLS 1.3", suite: "TLS13_AES_128_GCM_SHA256", group: "X25519", alpn: "mqtt", name: "", resumed: false, chain: [] }),
    "TLS 1.3, TLS13_AES_128_GCM_SHA256, X25519, ALPN mqtt",
  );
  assert.equal(
    agreedText({ version: "DTLS 1.2", suite: "TLS_PSK_WITH_AES_128_CCM_8", group: "", alpn: "", name: "PSK identity board", resumed: false, chain: [] }),
    "DTLS 1.2, TLS_PSK_WITH_AES_128_CCM_8, PSK identity board",
  );
  const cert = { subject: "CN=board", issuer: "CN=board", names: ["board.local"], not_before: "a", not_after: "b", key: "EC 256 bits", sha256: "AB" };
  assert.equal(certText(cert), "CN=board for board.local, self-signed, EC 256 bits, valid a to b, SHA-256 AB");
});

test("a DTLS tab picks OpenSSL as dtls.rs does: for DTLS 1.0, a cipher list, or when chosen", async () => {
  const { DEFAULT_DTLS, dtlsOverOpenssl } = await import("./net.ts");
  assert.equal(dtlsOverOpenssl(DEFAULT_DTLS), false);
  assert.equal(dtlsOverOpenssl({ ...DEFAULT_DTLS, psk: true }), false, "dimpl has a PSK suite");
  assert.equal(dtlsOverOpenssl({ ...DEFAULT_DTLS, version: "dtls10" }), true);
  assert.equal(dtlsOverOpenssl({ ...DEFAULT_DTLS, version: "all" }), true);
  assert.equal(dtlsOverOpenssl({ ...DEFAULT_DTLS, ciphers: "PSK-AES128-CBC-SHA256" }), true);
  assert.equal(dtlsOverOpenssl({ ...DEFAULT_DTLS, engine: "openssl" }), true);
  assert.equal(dtlsOverOpenssl({ ...DEFAULT_DTLS, engine: "rustls", ciphers: "PSK-AES128-CCM8" }), false);
});
