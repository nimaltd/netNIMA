// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  DEFAULT_COAP_ROW,
  codeClass,
  coapLine,
  headerLine,
  httpLine,
  parseLinks,
  routeLine,
  setLine,
  statusClass,
} from "./requests.ts";

test("a CoAP row is sent as the line a person would type", () => {
  assert.deepEqual(coapLine(DEFAULT_COAP_ROW), { line: "get /sensors/temp", problem: "" });
  assert.equal(coapLine({ ...DEFAULT_COAP_ROW, method: "OBSERVE", path: "led" }).line, "observe /led");
  const put = { ...DEFAULT_COAP_ROW, method: "PUT" as const, path: "/led", format: "json", payload: '{"on":true}' };
  assert.equal(coapLine(put).line, 'put -f json /led {"on":true}');
  assert.equal(coapLine({ ...put, non: true, accept: "cbor" }).line, 'put -n -a cbor -f json /led {"on":true}');
  assert.equal(coapLine({ ...put, payload: "01 ff", hex: true }).line, "put -f json /led \\x01\\xff");
  // A GET takes no payload, and a path is needed.
  assert.equal(coapLine({ ...DEFAULT_COAP_ROW, payload: "x" }).line, "get /sensors/temp");
  assert.match(coapLine({ ...DEFAULT_COAP_ROW, path: " " }).problem, /path is needed/);
  assert.match(coapLine({ ...put, payload: "zz", hex: true }).problem, /not hex/);
  assert.equal(setLine("/sensors/temp", "22.5"), "set /sensors/temp 22.5");
});

test("a CoAP server's resources are read from its link format", () => {
  assert.deepEqual(parseLinks("</led>;ct=0;obs,</sensors/temp>;ct=0;obs,</x>"), [
    { path: "/led", attributes: "ct=0;obs" },
    { path: "/sensors/temp", attributes: "ct=0;obs" },
    { path: "/x", attributes: "" },
  ]);
  assert.deepEqual(parseLinks(""), []);
  assert.equal(codeClass("2.05 Content"), 2);
  assert.equal(codeClass("4.04 Not Found"), 4);
});

test("an HTTP row, a header and a route are sent as typed lines", () => {
  assert.deepEqual(httpLine({ method: "GET", path: "/api/status", body: "ignored" }), { line: "get /api/status", problem: "" });
  assert.equal(httpLine({ method: "POST", path: "/api/led", body: '{"on": true}' }).line, 'post /api/led {"on": true}');
  assert.match(httpLine({ method: "PUT", path: "", body: "" }).problem, /path is needed/);
  assert.equal(headerLine("Authorization", "Bearer abc"), "header Authorization: Bearer abc");
  assert.equal(headerLine("Authorization", ""), "header Authorization:");
  assert.deepEqual(routeLine({ method: "get", path: "api/temp", status: 200, body: '{"t":21.5}' }), {
    line: 'route GET /api/temp 200 {"t":21.5}',
    problem: "",
  });
  assert.match(routeLine({ method: "GET", path: "/x", status: 99, body: "" }).problem, /100 to 599/);
  assert.equal(statusClass(404), 4);
});
