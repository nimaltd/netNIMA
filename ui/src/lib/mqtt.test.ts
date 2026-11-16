// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  bytesOf,
  keep,
  listed,
  matches,
  publishLine,
  showPayload,
  subscribeLine,
  unsubscribeLine,
  word,
  type Heard,
  type TopicState,
} from "./mqtt.ts";

const text = (value: string) => new TextEncoder().encode(value);

test("payloads come in hex and are shown as each is best", () => {
  assert.deepEqual(bytesOf("01ff"), Uint8Array.of(1, 255));
  assert.deepEqual(showPayload(text("21.5"), "auto"), { text: "21.5", as: "text" });
  assert.deepEqual(showPayload(text('{"t": 21.5}'), "auto"), { text: '{"t":21.5}', as: "json" });
  assert.equal(showPayload(text('{"t": 21.5}'), "auto", true).text, '{\n  "t": 21.5\n}');
  assert.deepEqual(showPayload(Uint8Array.of(1, 255), "auto"), { text: "01 ff", as: "hex" });
  // Lines are text; other control bytes are not.
  assert.equal(showPayload(text("a\r\nb"), "auto").as, "text");
  assert.equal(showPayload(text("a\u0001b"), "auto").as, "hex");
  // As asked: text stays text, and what cannot be text is hex.
  assert.deepEqual(showPayload(text('{"t":1}'), "text"), { text: '{"t":1}', as: "text" });
  assert.deepEqual(showPayload(text("on"), "hex"), { text: "6f 6e", as: "hex" });
  assert.equal(showPayload(text("{broken"), "json").as, "text");
});

test("the view gives the engine the lines a person would type", () => {
  const row = { topic: "sensors/temp", qos: 1, retain: true, payload: "21.5", hex: false };
  assert.deepEqual(publishLine(row), { line: "pub -q1 -r sensors/temp 21.5", problem: "" });
  assert.equal(publishLine({ ...row, qos: 0, retain: false, payload: "" }).line, "pub -q0 sensors/temp");
  assert.equal(publishLine({ ...row, payload: "01 02 FF", hex: true }).line, "pub -q1 -r sensors/temp \\x01\\x02\\xff");
  assert.equal(publishLine({ ...row, topic: "my room/temp" }).line, 'pub -q1 -r "my room/temp" 21.5');
  assert.equal(publishLine({ ...row, topic: " " }).problem, "The topic is needed.");
  assert.match(publishLine({ ...row, topic: "sensors/#" }).problem, /no \+ or #/);
  assert.match(publishLine({ ...row, payload: "zz", hex: true }).problem, /not hex/);
  assert.equal(subscribeLine("sensors/#", 2), "sub -q2 sensors/#");
  assert.equal(unsubscribeLine(" a b "), 'unsub "a b"');
  assert.equal(word('say "hi"'), '"say \\"hi\\""');
});

test("filters take in topics as MQTT says", () => {
  assert.ok(matches("sensors/#", "sensors/temp/room"));
  assert.ok(matches("sensors/+/temp", "sensors/kitchen/temp"));
  assert.ok(!matches("sensors/+", "sensors/a/b"));
  assert.ok(matches("#", "anything/at/all"));
  assert.ok(!matches("#", "$SYS/broker"));
  assert.ok(matches("a/b", "a/b") && !matches("a/b", "a/c"));
});

test("each topic keeps its last messages, the newest first, and topics are found", () => {
  const topics = new Map<string, TopicState>();
  const heard = (topic: string, value: string, at: number): Heard => ({ at, topic, payload: text(value), qos: 0, retain: false });
  for (let index = 0; index < 5; index++) keep(topics, heard("b/temp", String(index), index), 3);
  keep(topics, heard("a/led", "on", 9));
  const temp = topics.get("b/temp")!;
  assert.equal(temp.count, 5);
  assert.deepEqual(temp.history.map((each) => new TextDecoder().decode(each.payload)), ["4", "3", "2"]);
  assert.deepEqual(listed(topics, "").map((state) => state.topic), ["a/led", "b/temp"]);
  assert.deepEqual(listed(topics, "TEMP").map((state) => state.topic), ["b/temp"]);
  assert.deepEqual(listed(topics, "on").map((state) => state.topic), ["a/led"]);
});
