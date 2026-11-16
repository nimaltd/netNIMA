// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { endOf } from "./new-tab.ts";
import { reopened } from "./reopen.ts";

const known = (kind: string) => endOf(kind) !== undefined;

test("the tabs of the kinds netNIMA knows open again, in their order", () => {
  const saved = [
    { kind: "udp" },
    { kind: "from_the_future" },
    { kind: "mqtt_server" },
    { kind: "" },
    { kind: "capture" },
  ];
  assert.deepEqual(reopened(saved, known), [0, 2, 4]);
});

test("nothing saved, nothing opens", () => {
  assert.deepEqual(reopened([], known), []);
  assert.deepEqual(reopened([{ kind: "x" }], known), []);
});
