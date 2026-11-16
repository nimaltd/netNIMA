// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { helperIsGood, helperText } from "./helper.ts";

test("a helper that is there says its version", () => {
  const info = { path: "C:\\netNIMA\\netnima-helper.exe", version: "0.1.0", problem: "" };
  assert.equal(helperText(info), "netnima-helper 0.1.0, beside the app");
  assert.equal(helperIsGood(info), true);
});

test("a helper that is missing or of another version says what is wrong", () => {
  const missing = { path: "x", version: "", problem: "not found beside the app" };
  assert.equal(helperText(missing), "netnima-helper not found beside the app");
  assert.equal(helperIsGood(missing), false);

  const other = { path: "x", version: "0.0.9", problem: "it is version 0.0.9, and the app 0.1.0: install netNIMA again" };
  assert.equal(helperText(other), "netnima-helper 0.0.9: it is version 0.0.9, and the app 0.1.0: install netNIMA again");
  assert.equal(helperIsGood(other), false);
});

test("while it is looked for, it says so", () => {
  assert.equal(helperText(null), "...");
  assert.equal(helperIsGood(null), false);
});
