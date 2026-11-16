// An LwM2M tab's view: what its engine reports, kept for the view to show,
// and what the view asks of the engine, as the lines a person would type.
// A server's devices, what it read of each, what it observes, its
// requests and their answers, and the firmware it pushes; or a device's
// own state, its resources, and what its server asked of it.

import { askLine, setLine, type Ask } from "./lwm2m";

export type Lwm2mSetup = {
  /** The device chosen, by its endpoint name, so it stays chosen as it registers again. */
  selected: string;
  /** The format reads ask for; empty for the tab's own. */
  format: string;
  /** The request bar's path, value to write, and attributes. */
  path: string;
  value: string;
  attributes: string;
  /** The firmware to push, as a file, or the address the device fetches it from. */
  firmware: string;
  uri: string;
};

export const DEFAULT_LWM2M: Lwm2mSetup = {
  selected: "",
  format: "",
  path: "/3/0",
  value: "",
  attributes: "pmin=1&pmax=60",
  firmware: "",
  uri: "",
};

/** What the tab gives the view: its engine, as typed lines, and its saved settings. */
export type Lwm2mHost = {
  /** Gives the engine a line, as if typed; rejects with the reason when it cannot. */
  command(line: string): Promise<void>;
  setup(): Lwm2mSetup;
  connected(): boolean;
  /** Whether the tab is the server, rather than a device. */
  server(): boolean;
};

/** A device registered with the server, as the server said last. */
export type Lwm2mDevice = {
  location: string;
  endpoint: string;
  version: string;
  binding: string;
  lifetime: number;
  /** The seconds of its lifetime left when it was said, at `at`. */
  left: number;
  objects: string[];
  at: number;
};

/** What the server knows of one device: values read, paths observed, paths discovered. */
export type DeviceData = {
  values: Record<string, { value: string; at: number }>;
  /** Each path observed, with the token of its observation. */
  observed: Record<string, string>;
  /** Each path Discover listed, with its attributes. */
  links: Record<string, string>;
};

/** A request in the server's log: one it made of a device, or one a device made of it. */
export type LogEntry = {
  /** Its number, to key it by in the list. */
  id: number;
  at: number;
  kind: "asked" | "heard";
  endpoint: string;
  /** What it is: Read, Observe, Write, Register, and so on. */
  what: string;
  path: string;
  /** What went with it: a value written, a query. */
  detail: string;
  /** Its answer's code, such as 2.05 Content; null while it waits. */
  code: string | null;
  ok: boolean;
  ms: number | null;
  /** The answer's payload as people read it. */
  text: string;
  /** The changes that came while observed, after the first answer. */
  notifications: number;
  problem: string | null;
};

export type FirmwareProgress = { at: number; sent: number; total: number; done: boolean; problem: string | null };

/** A device's own state, as its engine said last. */
export type DeviceState = {
  endpoint: string;
  lifetime: number;
  /** Where its registration is, such as /rd/1; null while it is not registered. */
  location: string | null;
  registering: boolean;
  bootstrapping: boolean;
  resources: { path: string; value: string; kind: string }[];
  /** The paths its server observes. */
  observed: string[];
};

/** A request a device heard from its server, newest first. */
export type DeviceHeard = { id: number; at: number; what: string; path: string; detail: string; code: string; ok: boolean };

const text = (value: unknown) => (typeof value === "string" ? value : "");
const number = (value: unknown) => (typeof value === "number" ? value : 0);
const list = (value: unknown) => (Array.isArray(value) ? (value as Record<string, unknown>[]) : []);

/** How many entries the logs keep. */
const LOG_MAX = 300;

/** What a server's request was, by its method and options. */
function askedName(report: Record<string, unknown>): string {
  if (report.observe === 0) return "Observe";
  if (report.observe === 1) return "Cancel";
  switch (report.method) {
    case "GET":
      return report.accept === "link" ? "Discover" : "Read";
    case "PUT":
      return text(report.payload) === "" && text(report.query) !== "" ? "Attributes" : "Write";
    case "POST":
      return "Execute";
    case "DELETE":
      return "Delete";
    default:
      return text(report.method);
  }
}

/** What a device's request of the server was: Register, Update, Deregister or Bootstrap. */
function heardName(method: string, path: string): string {
  if (method === "POST" && path === "/rd") return "Register";
  if (method === "POST" && path.startsWith("/rd/")) return "Update";
  if (method === "DELETE" && path.startsWith("/rd/")) return "Deregister";
  if (method === "POST" && path === "/bs") return "Bootstrap";
  return method;
}

export class Lwm2mSession {
  /** A server's devices, as it said last. */
  devices: Lwm2mDevice[] = $state([]);
  /** What a server knows of each device, by its endpoint name. */
  data: Record<string, DeviceData> = $state({});
  log: LogEntry[] = $state([]);
  /** Each device's firmware upload, by its endpoint name. */
  firmware: Record<string, FirmwareProgress> = $state({});
  /** Why the view's last request could not go. */
  problem = $state("");
  /** A device tab's own state, and what its server asked of it. */
  device: DeviceState | null = $state(null);
  heard: DeviceHeard[] = $state([]);

  private readonly host: Lwm2mHost;
  /** The server's requests in the log, by token, while answers can come to them. */
  private tokens = new Map<string, LogEntry>();
  /** The number the next entry of a log gets. */
  private next = 0;

  constructor(host: Lwm2mHost) {
    this.host = host;
  }

  /** What the server knows of a device, made when it is first heard of. */
  dataOf(endpoint: string): DeviceData {
    if (!this.data[endpoint]) this.data[endpoint] = { values: {}, observed: {}, links: {} };
    return this.data[endpoint];
  }

  private endpointOf(location: string): string {
    return this.devices.find((device) => device.location === location)?.endpoint ?? `/rd/${location}`;
  }

  private add(entry: Omit<LogEntry, "id">): LogEntry {
    this.log.unshift({ id: ++this.next, ...entry });
    if (this.log.length > LOG_MAX) {
      for (const gone of this.log.splice(LOG_MAX)) {
        for (const [token, kept] of this.tokens) if (kept === gone) this.tokens.delete(token);
      }
    }
    // The log's own entry, which the view sees change.
    return this.log[0];
  }

  report(report: Record<string, unknown>): void {
    const at = Date.now();
    switch (report.type) {
      case "devices":
        this.devices = list(report.devices).map((device) => ({
          location: text(device.location),
          endpoint: text(device.endpoint),
          version: text(device.version),
          binding: text(device.binding),
          lifetime: number(device.lifetime),
          left: number(device.left),
          objects: Array.isArray(device.objects) ? device.objects.map(String) : [],
          at,
        }));
        return;
      case "asked": {
        const endpoint = text(report.endpoint);
        const path = text(report.path);
        const what = askedName(report);
        const entry = this.add({
          at,
          kind: "asked",
          endpoint,
          what,
          path,
          detail: what === "Attributes" ? text(report.query) : text(report.payload),
          code: null,
          ok: false,
          ms: null,
          text: "",
          notifications: 0,
          problem: null,
        });
        const token = text(report.token);
        this.tokens.set(token, entry);
        const data = this.dataOf(endpoint);
        if (report.observe === 0) data.observed[path] = token;
        if (report.observe === 1) delete data.observed[path];
        return;
      }
      case "answer": {
        const token = text(report.token);
        const entry = this.tokens.get(token);
        const endpoint = entry?.endpoint ?? this.endpointOf(text(report.location));
        const path = text(report.path);
        const data = this.dataOf(endpoint);
        for (const each of list(report.values)) data.values[text(each.path)] = { value: text(each.value), at };
        for (const each of list(report.links)) data.links[text(each.path)] = text(each.attributes);
        const ok = number(report.class) === 2;
        if (entry) {
          if (entry.code === null) {
            entry.code = text(report.code);
            entry.ok = ok;
            entry.ms = typeof report.ms === "number" ? report.ms : null;
          } else {
            entry.notifications += 1;
          }
          entry.text = text(report.text);
          // A value written is the resource's value now, as the device took it.
          if (entry.what === "Write" && ok) data.values[entry.path] = { value: entry.detail, at };
        }
        // An observation goes on while answers carry Observe; an answer without ends it.
        const observing = typeof report.observe === "number" && ok;
        if (!observing) {
          this.tokens.delete(token);
          if (data.observed[path] === token) delete data.observed[path];
        }
        return;
      }
      case "timeout": {
        const token = text(report.token);
        const entry = this.tokens.get(token);
        this.tokens.delete(token);
        if (!entry) return;
        entry.problem = "no answer: given up";
        const data = this.dataOf(entry.endpoint);
        if (data.observed[entry.path] === token) delete data.observed[entry.path];
        return;
      }
      case "firmware": {
        const endpoint = text(report.endpoint) || this.endpointOf(text(report.location));
        this.firmware[endpoint] = {
          at,
          sent: number(report.sent),
          total: number(report.total),
          done: report.done === true,
          problem: typeof report.problem === "string" ? report.problem : null,
        };
        return;
      }
      case "heard": {
        const method = text(report.method);
        const path = text(report.path);
        const code = text(report.code);
        const ok = number(report.class) === 2;
        const query = report.query && typeof report.query === "object" ? (report.query as Record<string, string>) : {};
        if (this.host.server()) {
          const words = Object.entries(query).map(([name, value]) => `${name}=${value}`);
          this.add({
            at,
            kind: "heard",
            endpoint: query.ep ?? this.devices.find((device) => path === `/rd/${device.location}`)?.endpoint ?? "",
            what: heardName(method, path),
            path,
            detail: [...words, text(report.payload)].filter(Boolean).join(" "),
            code,
            ok,
            ms: null,
            text: "",
            notifications: 0,
            problem: null,
          });
          return;
        }
        const what = report.observe === 0 ? "Observe" : report.observe === 1 ? "Cancel" : method;
        this.heard.unshift({ id: ++this.next, at, what, path, detail: text(report.payload), code, ok });
        if (this.heard.length > LOG_MAX) this.heard.length = LOG_MAX;
        return;
      }
      case "device":
        this.device = {
          endpoint: text(report.endpoint),
          lifetime: number(report.lifetime),
          location: typeof report.location === "string" ? report.location : null,
          registering: report.registering === true,
          bootstrapping: report.bootstrapping === true,
          resources: list(report.resources).map((each) => ({ path: text(each.path), value: text(each.value), kind: text(each.kind) })),
          observed: Array.isArray(report.observed) ? report.observed.map(String) : [],
        };
        return;
    }
  }

  private async run(line: string): Promise<void> {
    if (!this.host.connected()) {
      this.problem = "Not running: start the tab first.";
      return;
    }
    this.problem = "";
    try {
      await this.host.command(line);
    } catch (failed) {
      this.problem = String(failed);
    }
  }

  /** A server's request of a device, by its location. */
  async ask(location: string, ask: Ask): Promise<void> {
    const { line, problem } = askLine(location, ask);
    if (problem) {
      this.problem = problem;
      return;
    }
    await this.run(line);
  }

  /** A device's commands: set a resource, so its observers are told; register, update, deregister, bootstrap. */
  async set(path: string, value: string): Promise<void> {
    const { line, problem } = setLine(path, value);
    if (problem) {
      this.problem = problem;
      return;
    }
    await this.run(line);
  }

  async act(command: "register" | "update" | "deregister" | "bootstrap"): Promise<void> {
    await this.run(command);
  }

  /** The tab stopped: its devices, observations and requests ended with its engine. */
  closed(): void {
    this.tokens.clear();
    this.devices = [];
    for (const data of Object.values(this.data)) data.observed = {};
    for (const entry of this.log) if (entry.code === null && !entry.problem && entry.kind === "asked") entry.problem = "the tab stopped";
    this.device = null;
  }

  clearLog(): void {
    this.log = this.log.filter((entry) => [...this.tokens.values()].includes(entry));
  }

  clearHeard(): void {
    this.heard = [];
  }
}
