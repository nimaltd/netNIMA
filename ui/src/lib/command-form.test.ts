// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { hexEscapes, lineOf, partsOf, startingValues, type Part } from "./command-form.ts";

const value = (name: string, more: Partial<Part> = {}): Part => ({
  kind: "value",
  name,
  flag: "",
  optional: false,
  many: false,
  suffix: "",
  data: false,
  ...more,
} as Part);

test("a usage is read into words, values, switches and choices", () => {
  assert.deepEqual(partsOf("pub [-q0|-q1|-q2] [-r] <topic> <payload>"), [
    { kind: "word", text: "pub" },
    { kind: "choice", options: ["-q0", "-q1", "-q2"], optional: true },
    { kind: "switch", flag: "-r" },
    value("topic"),
    value("payload", { data: true }),
  ]);
  assert.deepEqual(partsOf("coil <address> on|off"), [
    { kind: "word", text: "coil" },
    value("address"),
    { kind: "choice", options: ["on", "off"], optional: false },
  ]);
  assert.deepEqual(partsOf("get <path> [-a json]"), [
    { kind: "word", text: "get" },
    value("path"),
    value("json", { flag: "-a", optional: true }),
  ]);
  assert.deepEqual(partsOf("sub [-q0|-q1|-q2] <filter> [<filter>...]").slice(2), [
    value("filter"),
    value("filter", { optional: true, many: true }),
  ]);
});

test("names with spaces, many words, a colon after, and groups", () => {
  assert.deepEqual(partsOf("raw <pdu in hex>")[1], value("pdu in hex"));
  assert.deepEqual(partsOf("get <file> [saved as]")[2], value("saved as", { optional: true }));
  assert.deepEqual(partsOf("module <name> [name...]")[2], value("name", { optional: true, many: true }));
  assert.deepEqual(partsOf("write-coils <start> <1|0>...")[2], value("1|0", { many: true }));
  assert.deepEqual(partsOf("header <Name>: <value>")[1], value("Name", { suffix: ":" }));
  assert.deepEqual(partsOf("exception <code>|off")[1], value("code|off"));
  assert.deepEqual(partsOf("trap [<oid> <type> <value>]").slice(1), [
    value("oid", { optional: true }),
    value("type", { optional: true }),
    value("value", { optional: true }),
  ]);
  assert.deepEqual(partsOf("[-e|-a|-c|-r|-w|-n|-i|-d] <message>"), [
    { kind: "choice", options: ["-e", "-a", "-c", "-r", "-w", "-n", "-i", "-d"], optional: true },
    value("message", { data: true }),
  ]);
  assert.deepEqual(partsOf("firmware <client> uri <uri>")[2], { kind: "word", text: "uri" });
  assert.deepEqual(partsOf("<type> <name>"), [value("type"), value("name")]);
});

test("the fields make the line the engine reads", () => {
  const pub = partsOf("pub [-q0|-q1|-q2] [-r] <topic> <payload>");
  assert.deepEqual(startingValues(pub), ["", "", "", "", ""]);
  assert.equal(lineOf(pub, ["", "", "", "sensors/temp", "21.5"], false).line, "pub sensors/temp 21.5");
  assert.equal(lineOf(pub, ["", "-q1", "on", "sensors/temp", "21.5 C"], false).line, "pub -q1 -r sensors/temp 21.5 C");
  // Hex data goes as escapes; text data as it is, escapes and all.
  assert.equal(lineOf(pub, ["", "", "", "t", "01 02 FF"], true).line, "pub t \\x01\\x02\\xff");
  assert.equal(lineOf(pub, ["", "", "", "t", "a\\r\\n"], false).line, "pub t a\\r\\n");
  // A word with spaces that is not the last goes in quotes.
  assert.equal(lineOf(pub, ["", "", "", "my topic", "x"], false).line, 'pub "my topic" x');
  const coil = partsOf("coil <address> on|off");
  assert.deepEqual(startingValues(coil), ["", "", "on"]);
  assert.equal(lineOf(coil, ["", "0x10", "off"], false).line, "coil 0x10 off");
  assert.equal(lineOf(partsOf("get <path> [-a json]"), ["", "/x", "cbor"], false).line, "get /x -a cbor");
  assert.equal(lineOf(partsOf("header <Name>: <value>"), ["", "Accept", "text/plain"], false).line, "header Accept: text/plain");
  assert.equal(lineOf(partsOf("ping"), [""], false).line, "ping");
});

test("what is missing or wrong says so", () => {
  const pub = partsOf("pub [-q0|-q1|-q2] [-r] <topic> <payload>");
  assert.equal(lineOf(pub, ["", "", "", "", "x"], false).problem, "The topic is needed.");
  assert.equal(lineOf(pub, ["", "", "", "t", "zz"], true).problem, "The payload is not hex bytes, such as 01 02 ff.");
  const echoTest = partsOf("test [count] [size] [interval]");
  assert.equal(lineOf(echoTest, ["", "", "64", ""], false).problem, "Fill in the count too, or leave the size empty.");
  assert.equal(lineOf(echoTest, ["", "10", "64", ""], false).line, "test 10 64");
  // A value after a flag may stay empty on its own.
  const run = partsOf("run [seconds] [-b 10M] [-l 1470]");
  assert.equal(lineOf(run, ["", "", "", "1000"], false).line, "run -l 1000");
});

test("hex bytes are read as people write them", () => {
  assert.equal(hexEscapes("01 02 ff"), "\\x01\\x02\\xff");
  assert.equal(hexEscapes("0x01,0x02"), "\\x01\\x02");
  assert.equal(hexEscapes("01:02:FF"), "\\x01\\x02\\xff");
  assert.equal(hexEscapes(""), "");
  assert.equal(hexEscapes("123"), null);
  assert.equal(hexEscapes("xyz1"), null);
});
