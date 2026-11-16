// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { ENDS, GROUPS, endOf, findProtocols, linesOf } from "./new-tab.ts";
import { PHASES } from "./roadmap.ts";

test("every kind of tab is one of its own, a word as workspace.toml keeps it", () => {
  const kinds = ENDS.map(({ end }) => end.kind);
  assert.equal(new Set(kinds).size, kinds.length);
  for (const kind of kinds) {
    assert.match(kind, /^[a-z][a-z0-9_]*$/);
  }
});

test("every new tab has a name of its own", () => {
  const titles = ENDS.map(({ end }) => end.title);
  assert.equal(new Set(titles).size, titles.length);
});

test("a protocol's ends come in pairs, a client and a server, named as it names them", () => {
  for (const { protocols } of GROUPS) {
    for (const protocol of protocols) {
      // One end, or pairs: iperf2 has a client and a server for TCP, and for UDP.
      assert.ok(protocol.ends.length === 1 || protocol.ends.length % 2 === 0, protocol.name);
      if (protocol.ends.length > 1) {
        protocol.ends.forEach((end, index) => assert.match(end.kind, index % 2 === 0 ? /_client$/ : /_server$/));
      }
    }
  }
  assert.deepEqual(
    endOf("mqtt_server")?.end,
    { kind: "mqtt_server", label: "Broker", title: "MQTT broker" },
  );
  assert.equal(endOf("modbus_client")?.end.title, "Modbus TCP master");
  assert.equal(endOf("udp")?.end.title, "UDP");
});

test("a protocol over more than one transport has a line of buttons for each", () => {
  const protocols = GROUPS.flatMap((group) => group.protocols);
  const lines = (name: string) => {
    const protocol = protocols.find((each) => each.name === name);
    assert.ok(protocol, name);
    return linesOf(protocol).map((line) => [line.transport, ...line.ends.map((end) => end.label)]);
  };
  assert.deepEqual(lines("CoAP"), [
    ["UDP", "Client", "Server"],
    ["TCP", "Client", "Server"],
    ["WebSocket", "Client", "Server"],
  ]);
  assert.deepEqual(lines("Echo"), [
    ["TCP", "Client", "Server"],
    ["UDP", "Client", "Server"],
  ]);
  assert.deepEqual(lines("MQTT"), [[undefined, "Client", "Broker"]]);
  assert.deepEqual(lines("UDP"), [[undefined, "Open"]]);
  assert.equal(endOf("coap_ws_server")?.end.title, "CoAP WebSocket server");
  assert.equal(endOf("iperf_client")?.end.title, "iperf2 TCP client");

  for (const protocol of protocols) {
    const [first, ...more] = linesOf(protocol);
    for (const line of [first, ...more]) {
      // Two buttons a line leave the name its room, and the same two on each
      // line sit under each other.
      assert.ok(line.ends.length <= 2, protocol.name);
      assert.deepEqual(
        line.ends.map((end) => end.label),
        first.ends.map((end) => end.label),
        protocol.name,
      );
      // A line says what it runs over only beside another.
      assert.equal(line.transport !== undefined, more.length > 0, protocol.name);
    }
  }
});

test("every protocol comes in a phase of the roadmap after the skeleton", () => {
  const phases = new Set(PHASES.map((phase) => phase.number));
  for (const { protocol } of ENDS) {
    assert.ok(phases.has(protocol.phase) && protocol.phase > 0, protocol.name);
  }
});

test("a kind this netNIMA does not know has no end", () => {
  assert.equal(endOf("from_the_future"), undefined);
  assert.equal(endOf(""), undefined);
});

test("protocols are found by their name, their words or their ends", () => {
  const names = (query: string) => findProtocols(query).flatMap((group) => group.protocols.map((p) => p.name));
  assert.deepEqual(names("mqtt"), ["MQTT", "MQTT-SN"]);
  assert.deepEqual(names("mqtt-sn gateway"), ["MQTT-SN"]);
  assert.deepEqual(names("broker"), ["MQTT", "MQTT-SN"]);
  assert.deepEqual(names("snmp agent"), ["SNMP"]);
  assert.deepEqual(names("U-BOOT files"), ["TFTP"]);
  assert.deepEqual(names("boot"), ["LwM2M", "TFTP"]);
  assert.ok(names("tls").includes("TLS") && names("tls").includes("MQTT"));
  assert.deepEqual(names("no such thing"), []);
  assert.equal(findProtocols("  ").length, GROUPS.length);
});
