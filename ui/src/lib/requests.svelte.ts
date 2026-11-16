// CoAP and HTTP tabs' views: what their engines report, kept for the view
// to show, and what the views ask of the engines, as the lines a person
// would type. A client's requests in rows, each with the answer it got
// under it; a CoAP server's resources and an HTTP server's routes; and the
// requests a server heard.

import {
  DEFAULT_COAP_ROW,
  DEFAULT_HTTP_ROW,
  coapLine,
  headerLine,
  httpLine,
  parseLinks,
  routeLine,
  setLine,
  type CoapRow,
  type HttpRow,
  type Link,
  type RouteRow,
} from "./requests";

/** What the tab gives a view: its engine, as typed lines, and its saved rows. */
export type RequestsHost<Setup> = {
  /** Gives the engine a line, as if typed; rejects with the reason when it cannot. */
  command(line: string): Promise<void>;
  setup(): Setup;
  connected(): boolean;
};

const text = (value: unknown) => (typeof value === "string" ? value : "");
const number = (value: unknown) => (typeof value === "number" ? value : 0);

/** Bytes from the two hex digits a byte that the engines report them in. */
function bytesOf(hex: unknown): Uint8Array {
  const pairs = text(hex).match(/[0-9a-f]{2}/gi) ?? [];
  return Uint8Array.from(pairs, (pair) => parseInt(pair, 16));
}

/** A request a server heard, newest first in its list. */
export type Heard = { at: number; method: string; path: string; payload: Uint8Array; answer: string; ok: boolean };

/** How many requests a server's list keeps. */
const HEARD_MAX = 200;

// ----- CoAP -----

export type CoapSetup = { requests: CoapRow[]; format: "auto" | "text" | "hex" | "json" };

export const DEFAULT_COAP: CoapSetup = { requests: [{ ...DEFAULT_COAP_ROW }], format: "auto" };

/** What a CoAP request got last: an answer, each change while observed, or none in time. */
export type CoapResult = {
  at: number;
  code: string;
  ok: boolean;
  format: string | null;
  payload: Uint8Array;
  /** The Observe number of the last notification, and how many came. */
  observe: number | null;
  notifications: number;
  blocks: number | null;
  ms: number | null;
  problem: string | null;
};

/** A row that is being sent, waiting for the engine to say it went; -1 for Discover. */
const DISCOVER = -1;

export class CoapSession {
  results: (CoapResult | null)[] = $state([]);
  /** What Discover found on the server. */
  discovered: Link[] | null = $state(null);
  /** What the last ping got. */
  pinged: { at: number; text: string } | null = $state(null);
  /** A server's resources, as it last said. */
  resources: { path: string; value: Uint8Array; format: string; observers: number }[] = $state([]);
  /** The requests a server heard. */
  heard: Heard[] = $state([]);

  private readonly host: RequestsHost<CoapSetup>;
  private sending: number[] = [];
  /** The row each request is for, by its token. */
  private rows = new Map<string, number>();

  constructor(host: RequestsHost<CoapSetup>) {
    this.host = host;
  }

  report(report: Record<string, unknown>): void {
    const at = Date.now();
    switch (report.type) {
      case "request": {
        const row = this.sending.shift();
        if (row !== undefined) this.rows.set(text(report.token), row);
        return;
      }
      case "response": {
        const token = text(report.token);
        const row = this.rows.get(token);
        if (row === undefined) return;
        const payload = bytesOf(report.payload);
        const observe = typeof report.observe === "number" ? report.observe : null;
        if (row === DISCOVER) {
          this.discovered = parseLinks(new TextDecoder().decode(payload));
          this.rows.delete(token);
          return;
        }
        // While observed, each change counts; only the first answer has a round trip.
        const before = this.results[row];
        const notifications = observe === null ? 0 : (before && before.observe !== null ? before.notifications : 0) + 1;
        this.results[row] = {
          at,
          code: text(report.code),
          ok: number(report.class) === 2,
          format: typeof report.format === "string" ? report.format : null,
          payload,
          observe,
          notifications,
          blocks: typeof report.blocks === "number" ? report.blocks : null,
          ms: notifications > 1 ? null : number(report.ms),
          problem: null,
        };
        // An observation goes on with the same token; an answer ends a request.
        if (observe === null) this.rows.delete(token);
        return;
      }
      case "timeout": {
        const token = text(report.token);
        const row = this.rows.get(token);
        this.rows.delete(token);
        if (row === undefined || row === DISCOVER) return;
        this.results[row] = this.problem(`no answer after ${number(report.tries)} tries: is a CoAP server there?`);
        return;
      }
      case "rst":
        this.pinged = { at, text: "the server answered (RST)" };
        return;
      case "cancelled": {
        const path = text(report.path);
        this.host.setup().requests.forEach((row, index) => {
          const result = this.results[index];
          if (row.method === "OBSERVE" && row.path === path && result) this.results[index] = { ...result, observe: null };
        });
        return;
      }
      case "resources":
        this.resources = ((report.resources as Record<string, unknown>[] | undefined) ?? []).map((each) => ({
          path: text(each.path),
          value: bytesOf(each.value),
          format: text(each.format),
          observers: number(each.observers),
        }));
        return;
      case "heard": {
        const code = text(report.code);
        this.heard.unshift({
          at,
          method: `${text(report.method)}${typeof report.observe === "number" ? (report.observe === 0 ? " observe" : " cancel") : ""}`,
          path: text(report.path),
          payload: bytesOf(report.payload),
          answer: code,
          ok: number(report.class) === 2,
        });
        if (this.heard.length > HEARD_MAX) this.heard.length = HEARD_MAX;
        return;
      }
    }
  }

  private problem(problem: string): CoapResult {
    return { at: Date.now(), code: "", ok: false, format: null, payload: new Uint8Array(), observe: null, notifications: 0, blocks: null, ms: null, problem };
  }

  /** Gives the engine a line for a row, or for Discover; the answer comes as a report. */
  private async run(line: string, row: number): Promise<void> {
    if (!this.host.connected()) {
      if (row !== DISCOVER) this.results[row] = this.problem("Not connected.");
      return;
    }
    this.sending.push(row);
    try {
      await this.host.command(line);
    } catch (problem) {
      this.sending = this.sending.filter((each) => each !== row);
      if (row !== DISCOVER) this.results[row] = this.problem(String(problem));
    }
  }

  async send(index: number): Promise<void> {
    const row = this.host.setup().requests[index];
    if (!row) return;
    const { line, problem } = coapLine(row);
    if (problem) {
      this.results[index] = this.problem(problem);
      return;
    }
    await this.run(line, index);
  }

  /** Stops observing a row's path. */
  async cancel(index: number): Promise<void> {
    const row = this.host.setup().requests[index];
    if (row) await this.host.command(`cancel ${row.path.trim()}`).catch(() => {});
  }

  async discover(): Promise<void> {
    this.discovered = null;
    await this.run("discover", DISCOVER);
  }

  async ping(): Promise<void> {
    this.pinged = { at: Date.now(), text: "asked" };
    await this.host.command("ping").catch((problem) => (this.pinged = { at: Date.now(), text: String(problem) }));
  }

  /** A server's commands: set a resource, made if new, or remove one. */
  async set(path: string, value: string): Promise<void> {
    if (path.trim()) await this.host.command(setLine(path, value)).catch(() => {});
  }

  async remove(path: string): Promise<void> {
    await this.host.command(`remove ${path}`).catch(() => {});
  }

  /** The connection ended, or the tab stopped: what was asked is answered no more. */
  closed(): void {
    this.sending = [];
    this.rows.clear();
  }

  clearHeard(): void {
    this.heard = [];
  }
}

// ----- HTTP -----

export type HttpSetup = { requests: HttpRow[]; format: "auto" | "text" | "hex" | "json" };

export const DEFAULT_HTTP: HttpSetup = { requests: [{ ...DEFAULT_HTTP_ROW }], format: "auto" };

/** What an HTTP request got last. */
export type HttpResult = {
  at: number;
  status: number;
  /** Its first line, "HTTP/1.1 200 OK". */
  start: string;
  headers: [string, string][];
  body: Uint8Array;
  ms: number | null;
  problem: string | null;
};

export class HttpSession {
  results: (HttpResult | null)[] = $state([]);
  /** The headers every request has, beside the usual ones. */
  headers: [string, string][] = $state([]);
  /** A server's routes, as it last said. */
  routes: { method: string; path: string; status: number; type: string; body: Uint8Array }[] = $state([]);
  heard: Heard[] = $state([]);

  private readonly host: RequestsHost<HttpSetup>;
  /** Rows given to the engine and not yet said sent; and those sent, which answers come to in order. */
  private sending: number[] = [];
  private asked: number[] = [];

  constructor(host: RequestsHost<HttpSetup>) {
    this.host = host;
  }

  report(report: Record<string, unknown>): void {
    const at = Date.now();
    switch (report.type) {
      case "request": {
        const row = this.sending.shift();
        // A request typed in the send box has no row, but its answer still comes in its turn.
        this.asked.push(row ?? -1);
        return;
      }
      case "response": {
        const row = this.asked.shift();
        if (row === undefined || row < 0) return;
        this.results[row] = {
          at,
          status: number(report.status),
          start: text(report.start),
          headers: ((report.headers as [string, string][] | undefined) ?? []).map(([name, value]) => [name, value]),
          body: bytesOf(report.body),
          ms: typeof report.ms === "number" ? report.ms : null,
          problem: null,
        };
        return;
      }
      case "timeout": {
        const row = this.asked.shift();
        if (row !== undefined && row >= 0) this.results[row] = this.problem("no answer in 30 s");
        return;
      }
      case "headers":
        this.headers = ((report.headers as [string, string][] | undefined) ?? []).map(([name, value]) => [name, value]);
        return;
      case "routes":
        this.routes = ((report.routes as Record<string, unknown>[] | undefined) ?? []).map((each) => ({
          method: text(each.method),
          path: text(each.path),
          status: number(each.status),
          type: text(each.type),
          body: bytesOf(each.body),
        }));
        return;
      case "heard": {
        const status = number(report.status);
        this.heard.unshift({
          at,
          method: text(report.method),
          path: text(report.path),
          payload: bytesOf(report.body),
          answer: String(status),
          ok: status >= 200 && status < 400,
        });
        if (this.heard.length > HEARD_MAX) this.heard.length = HEARD_MAX;
        return;
      }
    }
  }

  private problem(problem: string): HttpResult {
    return { at: Date.now(), status: 0, start: "", headers: [], body: new Uint8Array(), ms: null, problem };
  }

  async send(index: number): Promise<void> {
    const row = this.host.setup().requests[index];
    if (!row) return;
    const { line, problem } = httpLine(row);
    if (problem) {
      this.results[index] = this.problem(problem);
      return;
    }
    if (!this.host.connected()) {
      this.results[index] = this.problem("Not connected.");
      return;
    }
    this.sending.push(index);
    try {
      await this.host.command(line);
    } catch (failed) {
      this.sending = this.sending.filter((each) => each !== index);
      this.results[index] = this.problem(String(failed));
    }
  }

  /** Sets a header every request has, or drops it with an empty value. */
  async header(name: string, value: string): Promise<void> {
    if (name.trim()) await this.host.command(headerLine(name, value)).catch(() => {});
  }

  /** A server's commands: make a route, or drop one. */
  async route(route: RouteRow): Promise<string> {
    const { line, problem } = routeLine(route);
    if (problem) return problem;
    try {
      await this.host.command(line);
      return "";
    } catch (failed) {
      return String(failed);
    }
  }

  async unroute(method: string, path: string): Promise<void> {
    await this.host.command(`unroute ${method} ${path}`).catch(() => {});
  }

  /** The connection ended, or the tab stopped: no answer comes to what was asked. */
  closed(): void {
    this.sending = [];
    this.asked = [];
  }

  clearHeard(): void {
    this.heard = [];
  }
}
