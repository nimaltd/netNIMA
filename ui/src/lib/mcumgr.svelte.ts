// An MCUmgr tab's view: what its engine reports, kept for the view to show,
// and what the view asks of the engine, as the lines a person would type.
// A client's answers by command, the board's images and threads, and an
// upload going on; or a simulated board's images and what it was asked.

import { baseName, imagesOf, markLine, uploadLine, type Image } from "./mcumgr";

export type McumgrSetup = {
  /** What Echo sends. */
  echo: string;
  /** The image to upload, and its number on a board with more than one. */
  file: string;
  image: number;
};

export const DEFAULT_MCUMGR: McumgrSetup = { echo: "hello", file: "", image: 0 };

/** What the tab gives the view: its engine, as typed lines, and its saved settings. */
export type McumgrHost = {
  /** Gives the engine a line, as if typed; rejects with the reason when it cannot. */
  command(line: string): Promise<void>;
  setup(): McumgrSetup;
  connected(): boolean;
};

/** A command's last answer. */
export type Answer = {
  at: number;
  /** Its result, 0 when it went well; null when the answer had none. */
  rc: number | null;
  /** What went wrong, in words; null when nothing did. */
  problem: string | null;
  body: unknown;
  ms: number | null;
};

/** An upload, as the client said last. */
export type UploadProgress = {
  at: number;
  name: string;
  version: string | null;
  sha: string;
  sent: number;
  total: number;
  done: boolean;
  problem: string | null;
  kbps: number;
};

/** A request in the log: one the client made, with its answer; or one a board heard. */
export type LogEntry = {
  id: number;
  at: number;
  seq: number;
  /** Its group and command, such as "os echo". */
  what: string;
  op: string;
  rc: number | null;
  problem: string | null;
  ms: number | null;
  /** Its body, or its answer's, in a line. */
  text: string;
  answered: boolean;
};

const text = (value: unknown) => (typeof value === "string" ? value : "");
const number = (value: unknown) => (typeof value === "number" ? value : 0);

/** How many entries the logs keep. */
const LOG_MAX = 300;

/** What went wrong in an answer: its rc, or SMP 2's error with its group. */
function problemOf(report: Record<string, unknown>): string | null {
  const error = report.error as Record<string, unknown> | null | undefined;
  if (error && typeof error === "object") return `${error.group ?? "group ?"} error ${number(error.rc)}: ${text(error.text)}`;
  if (typeof report.rc === "number" && report.rc !== 0) return `rc ${report.rc}: ${text(report.rcText)}`;
  return null;
}

/** A body in one line, for the log. */
function brief(body: unknown): string {
  const line = JSON.stringify(body ?? {});
  return line === "{}" ? "" : line.length > 300 ? `${line.slice(0, 300)}…` : line;
}

export class McumgrSession {
  /** Each command's last answer, by its name: echo, info, params, taskstat, datetime, state, reset, erase. */
  answers: Record<string, Answer> = $state({});
  /** The board's images, as image state, test or confirm said last. */
  images: Image[] = $state([]);
  upload: UploadProgress | null = $state(null);
  log: LogEntry[] = $state([]);
  /** Why the view's last request could not go. */
  problem = $state("");
  /** A simulated board's images, an upload coming to it, and what it was asked. */
  boardImages: Image[] = $state([]);
  receiving: { got: number; total: number } | null = $state(null);
  heard: LogEntry[] = $state([]);

  private readonly host: McumgrHost;
  private next = 0;

  constructor(host: McumgrHost) {
    this.host = host;
  }

  private add(into: LogEntry[], entry: Omit<LogEntry, "id">): void {
    into.unshift({ id: ++this.next, ...entry });
    if (into.length > LOG_MAX) into.length = LOG_MAX;
  }

  report(report: Record<string, unknown>): void {
    const at = Date.now();
    const what = `${text(report.group)} ${text(report.command)}`;
    switch (report.type) {
      case "request":
        // An upload's progress has its own place; its chunks are not listed.
        if (report.command === "upload") return;
        this.add(this.log, { at, seq: number(report.seq), what, op: text(report.op), rc: null, problem: null, ms: null, text: "", answered: false });
        return;
      case "answer": {
        const problem = problemOf(report);
        const answer: Answer = {
          at,
          rc: typeof report.rc === "number" ? report.rc : null,
          problem,
          body: report.body,
          ms: typeof report.ms === "number" ? report.ms : null,
        };
        const command = text(report.command);
        this.answers[command] = answer;
        if (command === "state") {
          const images = imagesOf(report.body);
          if (images.length > 0 || problem === null) this.images = images;
        }
        const entry = this.log.find((each) => !each.answered && each.seq === number(report.seq) && each.what === what);
        if (entry) {
          entry.answered = true;
          entry.rc = answer.rc;
          entry.problem = problem;
          entry.ms = answer.ms;
          entry.text = brief(report.body);
        } else {
          this.add(this.log, { at, seq: number(report.seq), what, op: text(report.op), rc: answer.rc, problem, ms: answer.ms, text: brief(report.body), answered: true });
        }
        // An erased slot is gone: the images are read again.
        if (command === "erase" && problem === null) void this.run("images");
        return;
      }
      case "timeout": {
        const entry = this.log.find((each) => !each.answered && each.what === what);
        if (entry) {
          entry.answered = true;
          entry.problem = `no answer after ${number(report.tries)} tries`;
        }
        this.problem = `No answer to ${what}: is an SMP server on that port?`;
        return;
      }
      case "upload": {
        const before = this.upload;
        this.upload = {
          at,
          name: text(report.name),
          version: typeof report.version === "string" ? report.version : null,
          sha: text(report.sha),
          sent: number(report.sent),
          total: number(report.total),
          done: report.done === true,
          problem: typeof report.problem === "string" ? report.problem : null,
          kbps: number(report.kbps),
        };
        const ended = this.upload.done || this.upload.problem !== null;
        const endedBefore = before !== null && before.name === this.upload.name && (before.done || before.problem !== null) && before.sent === this.upload.sent;
        if (ended && !endedBefore) {
          this.add(this.log, {
            at,
            seq: 0,
            what: "image upload",
            op: "write",
            rc: this.upload.problem ? null : 0,
            problem: this.upload.problem,
            ms: null,
            text: `${baseName(this.upload.name)}: ${this.upload.sent} of ${this.upload.total} bytes${this.upload.version ? `, version ${this.upload.version}` : ""}`,
            answered: true,
          });
          // The image is in its slot now: the images are read again.
          if (this.upload.done) void this.run("images");
        }
        return;
      }
      case "images": {
        this.boardImages = imagesOf(report);
        const receiving = report.receiving as Record<string, unknown> | null | undefined;
        this.receiving = receiving && typeof receiving === "object" ? { got: number(receiving.got), total: number(receiving.total) } : null;
        return;
      }
      case "heard":
        this.add(this.heard, {
          at,
          seq: number(report.seq),
          what,
          op: text(report.op),
          rc: typeof report.rc === "number" ? report.rc : null,
          problem: problemOf(report),
          ms: null,
          text: brief(report.body),
          answered: true,
        });
        return;
    }
  }

  private async run(line: string): Promise<void> {
    if (!this.host.connected()) {
      this.problem = "Not open: open the tab first.";
      return;
    }
    this.problem = "";
    try {
      await this.host.command(line);
    } catch (failed) {
      this.problem = String(failed);
    }
  }

  /** A command that takes nothing: info, params, taskstat, datetime, reset, images, erase. */
  async ask(command: "info" | "params" | "taskstat" | "datetime" | "reset" | "images" | "erase"): Promise<void> {
    await this.run(command);
  }

  async echo(): Promise<void> {
    await this.run(`echo ${this.host.setup().echo}`);
  }

  async mark(what: "test" | "confirm", hash: string): Promise<void> {
    const { line, problem } = markLine(what, hash);
    if (problem) {
      this.problem = problem;
      return;
    }
    await this.run(line);
  }

  async startUpload(): Promise<void> {
    const setup = this.host.setup();
    const { line, problem } = uploadLine(setup.file, Number(setup.image));
    if (problem) {
      this.problem = problem;
      return;
    }
    await this.run(line);
  }

  /** Whether an upload is going on. */
  get uploading(): boolean {
    return this.upload !== null && !this.upload.done && this.upload.problem === null;
  }

  /** The tab stopped: nothing it asked is answered now. */
  closed(): void {
    for (const entry of this.log) {
      if (!entry.answered) {
        entry.answered = true;
        entry.problem = "the tab closed";
      }
    }
    if (this.uploading && this.upload) this.upload = { ...this.upload, problem: "The tab closed." };
  }

  clearLog(): void {
    this.log = [];
  }

  clearHeard(): void {
    this.heard = [];
  }
}
