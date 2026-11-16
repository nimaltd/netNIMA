// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { CURRENT_PHASE, LAST_PHASE, PHASES, isBuilt, phaseName } from "./roadmap.ts";

test("the phases are numbered from 0, one after another, up to 1.0", () => {
  PHASES.forEach((phase, index) => assert.equal(phase.number, index));
  assert.equal(phaseName(LAST_PHASE), "1.0");
});

test("a phase is built up to the one being built now", () => {
  assert.equal(isBuilt(0), true);
  assert.equal(isBuilt(CURRENT_PHASE), true);
  assert.equal(isBuilt(CURRENT_PHASE + 1), false);
});

test("a phase is named by its number", () => {
  assert.equal(phaseName(1), "UDP, TCP and Telnet");
  assert.equal(phaseName(10), "Sniffer");
  assert.equal(phaseName(99), "");
});
