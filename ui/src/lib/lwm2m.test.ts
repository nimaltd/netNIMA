// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { askLine, byPath, isExecutable, meaning, objectName, parsePath, resourceName, resourcesOf, setLine, word } from "./lwm2m.ts";

test("paths are read as LwM2M's numbers", () => {
  assert.deepEqual(parsePath("/3/0/1"), [3, 0, 1]);
  assert.deepEqual(parsePath("3303/0/"), [3303, 0]);
  assert.equal(parsePath("/3/a"), null);
  assert.equal(parsePath("/1/2/3/4/5"), null);
  assert.equal(parsePath("/70000"), null);
  assert.equal(parsePath(""), null);
});

test("objects and resources are named as OMA's registry names them", () => {
  assert.equal(objectName(3), "Device");
  assert.equal(objectName(3303), "Temperature");
  assert.equal(objectName(32769), "Object 32769");
  assert.equal(resourceName(3, 0), "Manufacturer");
  assert.equal(resourceName(3303, 5700), "Sensor Value");
  assert.equal(resourceName(3, 5700), "");
  assert.equal(isExecutable(3, 4), true);
  assert.equal(isExecutable(3303, 5605), true);
  assert.equal(isExecutable(3, 0), false);
});

test("values say what they mean", () => {
  assert.equal(meaning("/5/0/3", "2"), "Downloaded");
  assert.equal(meaning("/5/0/5", "1"), "Success");
  assert.equal(meaning("/3/0/13", "1700000000"), "2023-11-14 22:13:20 UTC");
  assert.equal(meaning("/1/0/7", "UQ"), "UDP, queue mode");
  assert.equal(meaning("/3/0/0", "netNIMA"), "");
  assert.equal(meaning("/5/0", "1"), "");
});

test("a server's requests are the lines a person would type", () => {
  assert.deepEqual(askLine("1", { what: "read", path: "3/0" }), { line: "read 1 /3/0", problem: "" });
  assert.equal(askLine("1", { what: "read", path: "/3303/0", format: "senml-cbor" }).line, "read 1 /3303/0 -f senml-cbor");
  assert.equal(askLine("2", { what: "observe", path: "/3303/0/5700" }).line, "observe 2 /3303/0/5700");
  assert.equal(askLine("2", { what: "write", path: "/3311/0/5850", value: "1" }).line, "write 2 /3311/0/5850 1");
  assert.equal(askLine("2", { what: "execute", path: "/3/0/4" }).line, "execute 2 /3/0/4");
  assert.equal(askLine("2", { what: "attributes", path: "/3303/0/5700", query: "?pmin=2&pmax=10" }).line, "attributes 2 /3303/0/5700 pmin=2&pmax=10");
  assert.equal(askLine("1", { what: "firmware", file: "C:\\Fw files\\app.bin" }).line, 'firmware 1 "C:\\\\Fw files\\\\app.bin"');
  assert.equal(askLine("1", { what: "firmware", file: "app.bin" }).line, "firmware 1 app.bin");
  assert.equal(askLine("1", { what: "firmware-uri", uri: "coap://10.0.0.2/fw.bin" }).line, "firmware 1 uri coap://10.0.0.2/fw.bin");
  assert.match(askLine("", { what: "read", path: "/3/0" }).problem, /device first/);
  assert.match(askLine("1", { what: "write", path: "/3/0", value: "x" }).problem, /one resource/);
  assert.match(askLine("1", { what: "write", path: "/3/0/14", value: "" }).problem, /value/);
  assert.match(askLine("1", { what: "read", path: "/x" }).problem, /not an LwM2M path/);
  assert.match(askLine("1", { what: "attributes", path: "/3/0/9", query: "pmin 2" }).problem, /pmin=2/);
  assert.match(askLine("1", { what: "firmware-uri", uri: "fw.bin" }).problem, /URI/);
  assert.deepEqual(setLine("/3303/0/5700", "30.5"), { line: "set /3303/0/5700 30.5", problem: "" });
  assert.match(setLine("/3303/0", "1").problem, /one resource/);
  assert.equal(word("plain"), "plain");
  assert.equal(word('say "hi"'), '"say \\"hi\\""');
});

test("an instance's resources come in order, with what a server executes", () => {
  const known = ["/3/0/13", "/3/0/0", "/3/0/9", "/3/1/0", "/3303/0/5700", "/3/0"];
  assert.deepEqual(resourcesOf("/3/0", known), ["/3/0/0", "/3/0/4", "/3/0/5", "/3/0/9", "/3/0/12", "/3/0/13"]);
  assert.deepEqual(resourcesOf("/3303/0", known), ["/3303/0/5700"]);
  assert.deepEqual(resourcesOf("/3", known), []);
  assert.deepEqual(["/3303/0", "/3/0/10", "/3/0/9", "/1/0"].sort(byPath), ["/1/0", "/3/0/9", "/3/0/10", "/3303/0"]);
});
