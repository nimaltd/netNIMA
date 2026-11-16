// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { completed, matching, typing, withCommand, wordOf, type CommandHelp } from "./commands.ts";

const command = (usage: string, what = "it does this"): CommandHelp => ({ usage, what });

// As MQTT's client, Syslog's receiver, WebSocket's client and Echo's client have them.
const PUB = command("pub [-q1] [-r] <topic> <payload>");
const PING = command("ping");
const LEVEL = command("level <level>");
const LEVEL_ALL = command("level all");
const CLOSE = command("/close [code] [reason]");
const TEXT = command("<text>");
const COIL = command("coil <address> on|off");
const VERSION = command("version 1|2c");
const COMMANDS = [PUB, PING, LEVEL, LEVEL_ALL, CLOSE, TEXT, COIL, VERSION];

test("a command is typed with its first word; <text> stands for any line", () => {
  assert.equal(wordOf(PUB), "pub");
  assert.equal(wordOf(CLOSE), "/close");
  assert.equal(wordOf(command("-e <message>")), "-e");
  assert.equal(wordOf(TEXT), null);
  assert.equal(wordOf(command("<type> <name>")), null);
  assert.equal(wordOf(command("[-e|-a|-c] <message>")), null);
});

test("while the first word is typed, the commands it starts are offered", () => {
  assert.deepEqual(matching(COMMANDS, "p"), [PUB, PING]);
  assert.deepEqual(matching(COMMANDS, "  PI"), [PING]);
  assert.deepEqual(matching(COMMANDS, "le"), [LEVEL, LEVEL_ALL]);
  assert.deepEqual(matching(COMMANDS, "/"), [CLOSE]);
  // The whole word still shows the command, with how it goes on.
  assert.deepEqual(matching(COMMANDS, "pub"), [PUB]);
  // Nothing typed, text that is no command, or more after the word: no list.
  assert.deepEqual(matching(COMMANDS, ""), []);
  assert.deepEqual(matching(COMMANDS, "hello"), []);
  assert.deepEqual(matching(COMMANDS, "pub "), []);
});

test("after the word, the command shows how it goes on", () => {
  assert.deepEqual(typing(COMMANDS, "pub "), [PUB]);
  assert.deepEqual(typing(COMMANDS, "PUB sensors/temp"), [PUB]);
  assert.deepEqual(typing(COMMANDS, "level 3"), [LEVEL, LEVEL_ALL]);
  assert.deepEqual(typing(COMMANDS, "pub"), []);
  assert.deepEqual(typing(COMMANDS, "pu x"), []);
  assert.deepEqual(typing(COMMANDS, "hello there"), []);
});

test("a command picked gives its fixed words, and a space when it takes more", () => {
  assert.equal(completed(PUB), "pub ");
  assert.equal(completed(PING), "ping");
  assert.equal(completed(LEVEL), "level ");
  assert.equal(completed(LEVEL_ALL), "level all");
  assert.equal(completed(CLOSE), "/close ");
  assert.equal(completed(COIL), "coil ");
  assert.equal(completed(VERSION), "version ");
  assert.equal(completed(command("firmware <client> uri <uri>")), "firmware ");
});

test("a command picked takes the place of the one typed, and keeps other text", () => {
  // Being typed.
  assert.equal(withCommand("pu", PUB, COMMANDS), "pub ");
  assert.equal(withCommand("", PING, COMMANDS), "ping");
  // Typed already: its words after it stay.
  assert.equal(withCommand("ping now", PUB, COMMANDS), "pub now");
  assert.equal(withCommand("pub a/b 1", LEVEL_ALL, COMMANDS), "level all a/b 1");
  // Text that is no command stays after the command.
  assert.equal(withCommand("sensors/temp 21.5", PUB, COMMANDS), "pub sensors/temp 21.5");
});
