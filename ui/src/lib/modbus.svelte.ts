// A Modbus tab's master or slave, on its connection: asking a device and
// keeping what it answers, or answering the masters that connect from
// tables; and every frame that went or came, for the Traffic view. terNIMA's
// serial Modbus, with TCP added: transaction ids, and a slave that answers
// each master on its own connection.

import {
  BusReader,
  ModbusReader,
  answer,
  describeRequest,
  describeResponse,
  frame,
  parseRequest,
  parseResponse,
  requestPdu,
  type BusFrame,
  type FunctionCode,
  type Message,
  type ModbusMode,
  type Request,
  type Response,
} from "./modbus";

export type RegisterFormat = "unsigned" | "signed" | "hex" | "float" | "float_swapped";

/** One request in the master's list, as workspace.toml keeps it. */
export type ModbusRequestRow = {
  unit: number;
  function: number;
  address: number;
  count: number;
  /** What a write writes, such as "1, 2, 3". */
  values: string;
  /** Asked again and again while polling. */
  poll: boolean;
};

/** How a tab's Modbus view asks or answers, as workspace.toml keeps it. */
export type ModbusSetup = {
  /** The master's requests or the slave's tables, or every frame on the line. */
  page: "tester" | "traffic";
  role: "master" | "slave";
  mode: ModbusMode;
  timeout_ms: number;
  poll_ms: number;
  format: RegisterFormat;
  requests: ModbusRequestRow[];
  /** The slave's own unit, 0 for any, and its tables from address `start` on. */
  unit: number;
  start: number;
  holding: number[];
  input: number[];
  coils: boolean[];
  discrete: boolean[];
};

const TABLE = 20;

export const DEFAULT_MODBUS: ModbusSetup = {
  page: "tester",
  role: "master",
  mode: "tcp",
  timeout_ms: 1000,
  poll_ms: 1000,
  format: "unsigned",
  requests: [{ unit: 1, function: 3, address: 0, count: 10, values: "", poll: true }],
  unit: 0,
  start: 0,
  holding: new Array(TABLE).fill(0),
  input: new Array(TABLE).fill(0),
  coils: new Array(TABLE).fill(false),
  discrete: new Array(TABLE).fill(false),
};

export type LogEntry = {
  at: number;
  /** Sent, came in, or went wrong. */
  kind: "out" | "in" | "problem";
  text: string;
  hex: string;
};

/** What a request in the list got last. */
export type RowResult = { at: number; ms: number; values: number[] | null; text: string | null; problem: string | null };

/** Values read, for the plot. */
export type Sample = { n: number; at: number; ok: boolean; values: [string, number][] };

/** A frame on the line as the Traffic view keeps it: numbered from the tab's first. */
export type TrafficFrame = BusFrame & { n: number };

/** Whether a frame on the line is one to look at: broken, an exception, or a request nothing answered. */
export const isBad = (frame: BusFrame) => !frame.ok || frame.problem !== null || frame.unanswered;

type Outcome = { response?: Response; problem?: string; ms: number };

/** What the tab gives its Modbus. */
export type ModbusHost = {
  /** Sends to the connection a master is on, or to one master of a slave's. */
  send(bytes: Uint8Array, peer?: number): void;
  setup(): ModbusSetup;
  /** Saves the setup: the slave's tables change as a master writes them. */
  changed(): void;
  connected(): boolean;
};

const LOG_MAX = 300;
const SAMPLES_MAX = 50_000;
/** The most frames the Traffic view keeps; a tenth of them go when there are more. */
const TRAFFIC_MAX = 50_000;
/** How long after the last bytes the line is taken as quiet, so a frame left half way is given. */
const QUIET_MS = 100;
/** How long a scan waits for each unit. */
const SCAN_TIMEOUT_MS = 150;

const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");

/** Whether a request to unit 0 goes to every unit, which act on it and do not answer: on a serial line, not on TCP. */
const broadcast = (unit: number, mode: string) => unit === 0 && mode !== "tcp";

/** Reads "1, 2, 0x10" into numbers; a problem in plain words when it cannot. */
export function parseValues(text: string): number[] | string {
  const words = text.split(/[\s,;]+/).filter(Boolean);
  const values = words.map((word) => Number(word));
  const bad = words.find((_, index) => !Number.isInteger(values[index]) || values[index] < -32768 || values[index] > 0xffff);
  return bad === undefined ? values.map((value) => value & 0xffff) : `"${bad}" is not a value from -32768 to 65535`;
}

/** A row of the list as a request, or what is wrong with it. */
export function requestOf(row: ModbusRequestRow): Request | string {
  const fc = row.function as FunctionCode;
  if (fc === 5 || fc === 6 || fc === 15 || fc === 16) {
    const values = parseValues(row.values);
    if (typeof values === "string") return values;
    const count = fc === 5 || fc === 6 ? 1 : values.length;
    if (count === 0) return "Write the values to write, such as 1, 2, 3.";
    return { unit: row.unit, fc, address: row.address, count, values: fc === 5 || fc === 15 ? values.map((value) => (value ? 1 : 0)) : values };
  }
  return { unit: row.unit, fc, address: row.address, count: row.count, values: [] };
}

/** Registers shown in a format: a float takes two, so the second shows nothing. */
export function formatRegisters(values: number[], format: RegisterFormat): string[] {
  switch (format) {
    case "signed":
      return values.map((value) => String(value >= 0x8000 ? value - 0x10000 : value));
    case "hex":
      return values.map((value) => `0x${value.toString(16).toUpperCase().padStart(4, "0")}`);
    case "float":
    case "float_swapped": {
      const view = new DataView(new ArrayBuffer(4));
      return values.map((value, index) => {
        if (index % 2 === 1) return "";
        const next = values[index + 1];
        if (next === undefined) return "—";
        const [high, low] = format === "float" ? [value, next] : [next, value];
        view.setUint16(0, high);
        view.setUint16(2, low);
        return String(Number(view.getFloat32(0).toPrecision(7)));
      });
    }
    default:
      return values.map(String);
  }
}

export class ModbusSession {
  log: LogEntry[] = $state([]);
  /** Each request's last result, by its place in the list. */
  results: (RowResult | null)[] = $state([]);
  stats = $state({ sent: 0, answered: 0, timeouts: 0, problems: 0 });
  polling = $state(false);
  /** Whether the slave answers what it is asked. */
  answering = $state(false);
  scan: { unit: number; found: number[]; running: boolean } | null = $state(null);
  /** Values read, for the plot. Plain values, as there can be many: `version` changes with them. */
  readonly samples: Sample[] = [];
  version = $state(0);
  /** The number of the first sample the plot reads: Clear in the Plot view moves it on. */
  plotFrom = $state(0);
  private nextSample = 0;
  /** When the newest sample was read, so frames read again add none twice. */
  private sampledAt = 0;
  /**
   * Every frame on the line lately, oldest first, for the Traffic view.
   * Plain values, as there can be many: `trafficVersion` changes with them.
   */
  readonly traffic: TrafficFrame[] = [];
  trafficVersion = $state(0);
  /** How many of the frames kept are bad, and the units and functions seen, for the filters. */
  badFrames = 0;
  readonly units = new Set<number>();
  readonly functions = new Set<number>();
  /** A reader of the frames on each connection, by its peer: a slave's masters each have their own. */
  private buses = new Map<number, BusReader>();
  private busMode = "";
  private nextFrame = 0;
  /** The newest request kept, which a request after it can mark as unanswered. */
  private lastRequest: TrafficFrame | null = null;
  private quietTimer: ReturnType<typeof setTimeout> | undefined;

  private readonly host: ModbusHost;
  /** The master's reader, and a slave's for each master, by its peer. */
  private readers = new Map<number, ModbusReader>();
  private readerFor = "";
  /** The transaction id of the master's last request on TCP. */
  private tid = 0;
  private waiting: { unit: number; fc: number; count: number; tid: number | null; done: (outcome: Outcome) => void } | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  private pollTimer: ReturnType<typeof setTimeout> | undefined;
  private wake: (() => void) | null = null;

  constructor(host: ModbusHost) {
    this.host = host;
  }

  /** The number the next sample gets, for Clear in the Plot view. */
  get nextNumber(): number {
    return this.nextSample;
  }

  /** Bytes from `peer`: an answer the master waits for, or requests to the slave. */
  receive(bytes: Uint8Array, at: number, peer = 0): void {
    const setup = this.host.setup();
    const master = setup.role === "master";
    if (master ? !this.waiting : !this.answering) return;
    // The master has one connection: what comes on it is the answer, whatever its peer number.
    for (const message of this.readerOf(setup, master ? 0 : peer).feed(bytes, at)) {
      if (master) this.onAnswer(message);
      else this.onRequest(message, setup, peer);
    }
  }

  /** The reader for a peer, as the role and mode read; a new one leaves behind what the old one held. */
  private readerOf(setup: ModbusSetup, peer: number, fresh = false): ModbusReader {
    const key = `${setup.role} ${setup.mode}`;
    if (key !== this.readerFor) {
      this.readers.clear();
      this.readerFor = key;
    }
    let reader = this.readers.get(peer);
    if (fresh || !reader) {
      reader = new ModbusReader(setup.mode, setup.role === "master" ? "responses" : "requests");
      this.readers.set(peer, reader);
    }
    return reader;
  }

  /** Forgets what a peer that went had left half way. */
  forget(peer: number): void {
    this.readers.delete(peer);
    this.buses.delete(peer);
  }

  private addLog(kind: LogEntry["kind"], text: string, bytes?: Uint8Array): void {
    this.log.push({ at: Date.now(), kind, text, hex: bytes ? hex(bytes) : "" });
    if (this.log.length > LOG_MAX) this.log.splice(0, this.log.length - LOG_MAX);
  }

  clearLog(): void {
    this.log = [];
    this.stats = { sent: 0, answered: 0, timeouts: 0, problems: 0 };
  }

  /** Asks a device, one request at a time, and says what came back. */
  ask(request: Request, timeoutMs?: number): Promise<Outcome> {
    const next = this.queue.then(() => this.askNow(request, timeoutMs));
    this.queue = next.catch(() => {});
    return next;
  }

  private askNow(request: Request, timeoutMs?: number): Promise<Outcome> {
    return new Promise((resolve) => {
      const setup = this.host.setup();
      if (!this.host.connected()) {
        resolve({ problem: "Not connected.", ms: 0 });
        return;
      }
      const tid = setup.mode === "tcp" ? (this.tid = (this.tid + 1) & 0xffff) : null;
      const bytes = frame(setup.mode, request.unit, requestPdu(request), tid ?? 0);
      const reader = this.readerOf(setup, 0, true);
      const sentAt = performance.now();
      const elapsed = () => Math.round(performance.now() - sentAt);
      this.stats.sent++;
      this.addLog("out", describeRequest(request), bytes);
      if (broadcast(request.unit, setup.mode)) {
        // Every unit acts on a broadcast; none answers it.
        this.host.send(bytes);
        resolve({ problem: "sent to every unit, which do not answer", ms: 0 });
        return;
      }
      const wait = timeoutMs ?? setup.timeout_ms;
      const timer = setTimeout(() => {
        this.waiting = null;
        this.stats.timeouts++;
        const problem = reader.problem ? `no answer in ${wait} ms, only ${reader.problem}` : `no answer in ${wait} ms`;
        if (timeoutMs === undefined) this.addLog("problem", problem);
        resolve({ problem, ms: elapsed() });
      }, wait);
      this.waiting = {
        unit: request.unit,
        fc: request.fc,
        count: request.count,
        tid,
        done: (outcome) => {
          clearTimeout(timer);
          this.waiting = null;
          resolve({ ...outcome, ms: elapsed() });
        },
      };
      this.host.send(bytes);
    });
  }

  private onAnswer(message: Message): void {
    const waiting = this.waiting;
    if (!waiting) return;
    if (!message.ok) {
      this.addLog("problem", message.problem ?? "a broken message", message.raw);
      return;
    }
    if (message.unit !== waiting.unit || (message.pdu[0] & 0x7f) !== waiting.fc) {
      this.addLog("problem", `an answer to something else, from unit ${message.unit}`, message.raw);
      return;
    }
    if (waiting.tid !== null && message.tid !== waiting.tid) {
      this.addLog("problem", `an answer to an earlier request, transaction ${message.tid}`, message.raw);
      return;
    }
    const response = parseResponse(message.unit, message.pdu, waiting.count);
    if (typeof response === "string") {
      this.stats.problems++;
      this.addLog("problem", response, message.raw);
      waiting.done({ problem: response, ms: 0 });
      return;
    }
    if (response.exception !== undefined) this.stats.problems++;
    else this.stats.answered++;
    this.addLog(response.exception !== undefined ? "problem" : "in", describeResponse(response), message.raw);
    waiting.done({ response, ms: 0 });
  }

  /** Sends a request of the list, and keeps what came back. */
  async sendRow(index: number): Promise<void> {
    const row = this.host.setup().requests[index];
    if (!row) return;
    const request = requestOf(row);
    if (typeof request === "string") {
      this.results[index] = { at: Date.now(), ms: 0, values: null, text: null, problem: request };
      return;
    }
    const outcome = await this.ask(request);
    const response = outcome.response;
    let values: number[] | null = null;
    let problem = outcome.problem ?? null;
    let text: string | null = null;
    if (response?.exception !== undefined) {
      problem = describeResponse(response);
    } else if (response?.registers || response?.bits) {
      values = response.registers ?? response.bits!.map(Number);
    } else if (response) {
      text = describeResponse(response);
    }
    this.results[index] = { at: Date.now(), ms: outcome.ms, values, text, problem };
  }

  /**
   * Keeps a read's values for the plot, named by their address: hr0, ir5,
   * c3, di1. Registers are read as Show says: signed, or two to a float.
   */
  private addSample(request: Request, values: number[], at: number): void {
    const kind = { 1: "c", 2: "di", 3: "hr", 4: "ir" }[request.fc as 1 | 2 | 3 | 4];
    if (!kind || at <= this.sampledAt) return;
    this.sampledAt = at;
    const prefix = request.unit === 1 ? kind : `u${request.unit}.${kind}`;
    const format = this.host.setup().format;
    const registers = request.fc === 3 || request.fc === 4;
    const shown = registers && format !== "hex" && format !== "unsigned" ? formatRegisters(values, format).map(Number) : values;
    this.samples.push({
      n: this.nextSample++,
      at,
      ok: true,
      values: shown
        .map((value, index): [string, number] => [`${prefix}${request.address + index}`, value])
        // A float's second register is part of the first.
        .filter((_, index) => !(registers && format.startsWith("float") && index % 2 === 1))
        .filter(([, value]) => Number.isFinite(value)),
    });
    if (this.samples.length > SAMPLES_MAX) this.samples.splice(0, SAMPLES_MAX / 10);
    this.version++;
  }

  /** Asks the requests marked to poll, again and again, `poll_ms` apart. */
  startPolling(): void {
    if (this.polling) return;
    this.polling = true;
    void this.pollLoop();
  }

  stopPolling(): void {
    this.polling = false;
    clearTimeout(this.pollTimer);
    this.wake?.();
  }

  private async pollLoop(): Promise<void> {
    while (this.polling) {
      const rows = this.host.setup().requests;
      const polled = rows.map((row, index) => (row.poll ? index : -1)).filter((index) => index >= 0);
      if (polled.length === 0) {
        this.addLog("problem", "Nothing to poll: tick Poll on a request.");
        this.polling = false;
        return;
      }
      for (const index of polled) {
        if (!this.polling) return;
        await this.sendRow(index);
      }
      await new Promise<void>((done) => {
        this.wake = done;
        this.pollTimer = setTimeout(done, this.host.setup().poll_ms);
      });
      this.wake = null;
    }
  }

  /** Asks every unit from `from` to `to` for one holding register; any answer, an exception too, means a device is there. */
  async startScan(from = 1, to = 247): Promise<void> {
    if (this.scan?.running) return;
    this.scan = { unit: from, found: [], running: true };
    for (let unit = from; unit <= to && this.scan.running; unit++) {
      this.scan.unit = unit;
      const outcome = await this.ask({ unit, fc: 3, address: 0, count: 1, values: [] }, SCAN_TIMEOUT_MS);
      if (outcome.response) this.scan.found.push(unit);
      if (outcome.problem === "Not connected.") break;
    }
    this.scan.running = false;
    this.addLog("problem", this.scan.found.length > 0 ? `Units that answered: ${this.scan.found.join(", ")}` : "No unit answered.");
  }

  stopScan(): void {
    if (this.scan) this.scan.running = false;
  }

  /** Answers a master from the tables, which writes change, on its own connection. */
  private onRequest(message: Message, setup: ModbusSetup, peer: number): void {
    if (!message.ok) {
      this.addLog("problem", message.problem ?? "a broken message", message.raw);
      return;
    }
    // For another slave on the bus; unit 0 here answers any.
    if (setup.unit !== 0 && message.unit !== setup.unit && message.unit !== 0) return;
    const request = parseRequest(message.unit, message.pdu);
    this.addLog("in", typeof request === "string" ? request : describeRequest(request), message.raw);
    const reply = answer(message.pdu, {
      start: setup.start,
      coils: setup.coils,
      discrete: setup.discrete,
      holding: setup.holding,
      input: setup.input,
    });
    const fc = message.pdu[0];
    if (fc === 5 || fc === 6 || fc === 15 || fc === 16) this.host.changed();
    // A broadcast is acted on, not answered.
    if (broadcast(message.unit, setup.mode)) return;
    const bytes = frame(setup.mode, message.unit, reply, message.tid ?? 0);
    this.host.send(bytes, peer);
    const response = parseResponse(message.unit, reply);
    if (typeof response !== "string" && response.exception !== undefined) this.stats.problems++;
    else this.stats.answered++;
    this.addLog("out", typeof response === "string" ? response : describeResponse(response), bytes);
  }

  setAnswering(on: boolean): void {
    this.answering = on;
    this.readers.clear();
  }

  /** Stops polling and scanning, as the tab disconnects. */
  stop(): void {
    this.stopPolling();
    this.stopScan();
  }

  /** Whether the tab is asking or answering, which keeps the line read whatever view is shown. */
  get busy(): boolean {
    return this.polling || this.answering;
  }

  /** Bytes sent or received on a peer's connection, for the Traffic view and the plot. */
  heard(sent: boolean, bytes: Uint8Array, at: number, peer = 0): void {
    const setup = this.host.setup();
    const mode = setup.mode;
    if (mode !== this.busMode) {
      this.buses.clear();
      this.busMode = mode;
    }
    // A master's requests and their answers are on its one connection, whatever the numbers say.
    const key = setup.role === "master" ? 0 : peer;
    let bus = this.buses.get(key);
    if (!bus) {
      bus = new BusReader(mode);
      this.buses.set(key, bus);
    }
    bus.answering = this.answering;
    const reading = bus;
    this.keep(() => reading.feed(bytes, at, sent));
    clearTimeout(this.quietTimer);
    this.quietTimer = setTimeout(() => {
      for (const quiet of this.buses.values()) this.keep(() => quiet.pause(Date.now()));
    }, QUIET_MS);
  }

  /** Keeps the frames read, with the bad ones counted: a request among those before can be found unanswered. */
  private keep(read: () => BusFrame[]): void {
    const before = this.lastRequest;
    const wasUnanswered = before?.unanswered ?? true;
    const frames = read();
    if (frames.length === 0) return;
    for (const found of frames) {
      const kept = Object.assign(found, { n: this.nextFrame++ });
      this.traffic.push(kept);
      if (isBad(kept)) this.badFrames++;
      if (kept.unit !== null) this.units.add(kept.unit);
      if (kept.fc !== null) this.functions.add(kept.fc);
      if (kept.kind === "request") this.lastRequest = kept;
      const values = kept.response?.registers ?? kept.response?.bits?.map(Number);
      if (kept.request && values) this.addSample(kept.request, values, kept.at);
    }
    // A request nothing answered is found so when the next one comes.
    if (before && !wasUnanswered && before.unanswered) this.badFrames++;
    if (this.traffic.length > TRAFFIC_MAX) {
      const gone = this.traffic.splice(0, this.traffic.length - TRAFFIC_MAX + TRAFFIC_MAX / 10);
      this.badFrames -= gone.filter(isBad).length;
    }
    this.trafficVersion++;
  }

  /** Reads the line again from what came and went lately: as the Traffic view opens, or the mode changes. */
  readAgain(chunks: { tx: boolean; at: number; bytes: Uint8Array; peer?: number }[]): void {
    this.clearTraffic();
    this.buses.clear();
    for (const chunk of chunks) this.heard(chunk.tx, chunk.bytes, chunk.at, chunk.peer ?? 0);
    for (const bus of this.buses.values()) this.keep(() => bus.pause(Date.now()));
    this.trafficVersion++;
  }

  /** Forgets the frames kept for the Traffic view. */
  clearTraffic(): void {
    this.traffic.length = 0;
    this.badFrames = 0;
    this.units.clear();
    this.functions.clear();
    this.lastRequest = null;
    this.trafficVersion++;
  }
}
