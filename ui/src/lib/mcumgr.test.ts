// Run with npm test: Node runs TypeScript as it is.

import assert from "node:assert/strict";
import { test } from "node:test";
import { baseName, flagsOf, imagesOf, markLine, shortHash, size, tasksOf, uploadLine } from "./mcumgr.ts";

test("images and threads are read out of the answers' bodies", () => {
  const images = imagesOf({
    images: [
      { image: 0, slot: 0, version: "1.0.0", hash: "ab01", bootable: true, confirmed: true, active: true },
      { image: 0, slot: 1, version: "1.4.0+0", hash: "cd02", bootable: true, pending: true },
    ],
    splitStatus: 0,
  });
  assert.equal(images.length, 2);
  assert.deepEqual(flagsOf(images[0]), ["active", "confirmed", "bootable"]);
  assert.deepEqual(flagsOf(images[1]), ["pending", "bootable"]);
  assert.equal(images[1].version, "1.4.0+0");
  assert.deepEqual(imagesOf({ rc: 3 }), []);
  assert.deepEqual(imagesOf(null), []);
  const tasks = tasksOf({
    tasks: {
      idle: { prio: 15, stkuse: 64, stksiz: 320 },
      main: { prio: 0, stkuse: 712, stksiz: 2048, cswcnt: 4 },
    },
  });
  assert.deepEqual(
    tasks.map((task) => [task.name, task.priority, task.stackUsed, task.stackSize, task.switches]),
    [
      ["main", 0, 712, 2048, 4],
      ["idle", 15, 64, 320, 0],
    ],
  );
});

test("a client's commands are the lines a person would type", () => {
  assert.deepEqual(uploadLine("zephyr.signed.bin", 0), { line: "upload zephyr.signed.bin", problem: "" });
  assert.equal(uploadLine("C:\\Build out\\app.bin", 1).line, 'upload "C:\\\\Build out\\\\app.bin" 1');
  assert.match(uploadLine(" ", 0).problem, /file first/);
  assert.match(uploadLine("a.bin", 300).problem, /0 to 255/);
  assert.equal(markLine("test", "ABcd01").line, "test ABcd01");
  assert.equal(markLine("confirm", "").line, "confirm");
  assert.match(markLine("test", "").problem, /hex/);
  assert.match(markLine("test", "abc").problem, /hex/);
  assert.equal(shortHash("0123456789abcdef"), "01234567…");
  assert.equal(size(512), "512 B");
  assert.equal(size(3277), "3.2 KB");
  assert.equal(size(1468006), "1.4 MB");
  assert.equal(baseName("C:\\Build out\\zephyr.signed.bin"), "zephyr.signed.bin");
  assert.equal(baseName("/home/me/app.bin"), "app.bin");
  assert.equal(baseName("app.bin"), "app.bin");
});
