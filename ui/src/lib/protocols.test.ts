// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { READY, endOf } from "./new-tab.ts";
import { PROTOCOL_SETUPS, optionsOf, setupOf } from "./protocols.ts";

/** The kinds of tab that are sockets themselves, with no engine on top. */
const SOCKETS = ["udp", "tcp_client", "tcp_server", "telnet_client", "telnet_server", "tls_client", "tls_server", "dtls_client", "dtls_server"];

test("every kind built is a socket or has a protocol setup, and the other way round", () => {
  for (const kind of READY) {
    assert.ok(SOCKETS.includes(kind) || setupOf(kind) !== undefined, kind);
    assert.ok(endOf(kind) !== undefined, `${kind} is in the New tab dialog`);
  }
  for (const kind of Object.keys(PROTOCOL_SETUPS)) {
    assert.ok(READY.has(kind), `${kind} is built`);
  }
});

test("every field of a protocol has a default, and a select's default is one of its choices", () => {
  for (const [kind, setup] of Object.entries(PROTOCOL_SETUPS)) {
    for (const field of setup.fields) {
      assert.ok(field.key in setup.defaults, `${kind}: ${field.key}`);
      if (field.type === "select") {
        const values = (field.choices ?? []).map(([value]) => value);
        assert.ok(values.includes(setup.defaults[field.key] as string | number), `${kind}: ${field.key}`);
      }
    }
  }
});

test("a tab's options are what was saved, with the defaults for the rest", () => {
  assert.deepEqual(optionsOf("coap_client", { token_length: 8 }), { non: false, token_length: 8 });
  assert.equal(optionsOf("mqtt_client", { client_id: "board" }).keep_alive, 60);
  assert.deepEqual(optionsOf("udp", undefined), {});
});
