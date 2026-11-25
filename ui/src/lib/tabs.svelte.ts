// The open tabs, each with its session (UDP, a TCP or Telnet client or
// server, or a recording played back) and its log, and saving them to
// workspace.toml.

import { Channel, invoke } from "@tauri-apps/api/core";
import type { Terminal } from "@xterm/xterm";
import { echoed } from "./echo";
import { HexDump } from "./hexdump";
import {
  DEFAULT_DTLS,
  DEFAULT_TCP_CLIENT,
  DEFAULT_TCP_SERVER,
  DEFAULT_TLS_CLIENT,
  DEFAULT_TLS_SERVER,
  DEFAULT_UDP,
  agreedText,
  certText,
  clientText,
  hostAndPort,
  readFrame,
  serverText,
  targetOf,
  udpText,
  type Agreed,
  type DtlsOptions,
  type NetState,
  type Peer,
  type SessionEvent,
  type TcpClientConfig,
  type TcpServerConfig,
  type UdpConfig,
} from "./net";
import { DEFAULT_LWM2M, Lwm2mSession, type Lwm2mSetup } from "./lwm2m.svelte";
import { DEFAULT_MCUMGR, McumgrSession, type McumgrSetup } from "./mcumgr.svelte";
import { DEFAULT_MODBUS, ModbusSession, type ModbusSetup } from "./modbus.svelte";
import { DEFAULT_MQTT, MqttSession, type MqttSetup } from "./mqtt.svelte";
import {
  CoapSession,
  DEFAULT_COAP,
  DEFAULT_HTTP,
  HttpSession,
  type CoapSetup,
  type HttpSetup,
} from "./requests.svelte";
import { endOf, isReady } from "./new-tab";
import { optionsOf, setupOf } from "./protocols";
import { reopened } from "./reopen";
import { settings, type Macro, type Sequence } from "./settings.svelte";
import {
  DEFAULT_HEX_VIEW,
  DEFAULT_LINES_VIEW,
  DEFAULT_PLOT_VIEW,
  DEFAULT_REPLAY,
  DEFAULT_TERMINAL,
  type HexView,
  type LinesView,
  type LogLine,
  type PlayState,
  type PlotView,
  type ReplaySetup,
  type SentLine,
  type TerminalOptions,
  type View,
} from "./types";

/** Whether a log is being written, and where; or why it could not start. */
type LogStatus = { path: string | null; problem: string | null };

/** How a session's log file is written, for the Rust side. */
type LogSetup = { folder: string; name: string; format: string; timestamps: boolean };

/** What the Rust side learns of a recording it opens. */
type ReplayInfo = { name: string; length: number };

/** What a recording being played is asked to do. */
type ReplayCommand =
  | { kind: "play" }
  | { kind: "pause" }
  | { kind: "speed"; speed: number }
  | { kind: "seek"; position: number };

/** How sending a file goes, from the Rust side. */
type FileProgress = { sent: number; total: number; done: boolean; cancelled: boolean; problem: string | null };

/** What the UI keeps of a tab that Rust does not read: the same as `ui` in workspace.rs. */
type TabUi = {
  terminal?: TerminalOptions;
  hex_view?: HexView;
  lines_view?: LinesView;
  plot_view?: PlotView;
  history?: SentLine[];
  send_to?: string;
  /** Whether a protocol tab's send box shows the form for its commands, not the line to type them. */
  send_form?: boolean;
  /** How a Modbus tab's view asks or answers: its requests, or its tables. */
  modbus?: ModbusSetup;
  /** How an MQTT tab's view publishes, subscribes and shows. */
  mqtt?: MqttSetup;
  /** A CoAP or HTTP tab's view: its requests in rows. */
  coap?: CoapSetup;
  http?: HttpSetup;
  /** An LwM2M tab's view: the device chosen, and what its request bar and firmware hold. */
  lwm2m?: Lwm2mSetup;
  /** An MCUmgr tab's view: what Echo sends, and the image to upload. */
  mcumgr?: McumgrSetup;
};

/** One tab, as it is saved: the same fields as `TabSetup` in workspace.rs. */
export type TabSetup = {
  name: string;
  /** A kind from new-tab.ts, such as "mqtt_server", or "replay". */
  kind: string;
  /** Whether it was connected, or listening, when it was saved. */
  connected: boolean;
  view?: string;
  log?: boolean;
  udp?: UdpConfig | null;
  tcp_client?: TcpClientConfig | null;
  tcp_server?: TcpServerConfig | null;
  replay?: ReplaySetup | null;
  /** DTLS on a UDP tab's socket: a DTLS tab's, or a protocol's over DTLS. */
  dtls?: DtlsOptions | null;
  /** A protocol tab's own settings, as its engine reads them. */
  protocol?: Record<string, unknown>;
  ui?: TabUi;
};

/** What the UI saves of `Workspace` in workspace.rs; the window's place comes from the window. */
type Workspace = {
  active: number;
  tabs: TabSetup[];
};

/**
 * A line as the Lines view keeps it: numbered from the tab's first, with when
 * it came and from which peer. A note is one of the tab's own lines, such as
 * "connected to 192.168.1.50:23".
 */
export type StoredLine = LogLine & { n: number; at: number; note?: boolean; peer?: string; sent?: boolean };

/** What a tab's socket is, by the kind of tab. */
export type Socket = "udp" | "client" | "server" | "replay" | "none";

const encoder = new TextEncoder();
const ENTER = { cr: "\r", lf: "\n", crlf: "\r\n" };
/** The most sent lines a tab keeps. */
const HISTORY_MAX = 100;
/** About how many recent bytes a tab keeps, to fill its hex view when it opens. */
const RECENT_MAX = 256 * 1024;
/** The most lines a tab keeps for its Lines view; a tenth of them go when there are more. */
const LINES_MAX = 100_000;
/** The most time, in ms, that lines read at once are spread over. */
const SPREAD_MS = 200;
/** A datagram on a UDP tab is at most this big; a file goes in pieces of this size unless set. */
export const DATAGRAM_DEFAULT = 1024;

const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

/** The socket of a kind of tab, or null for a kind no phase has brought yet. */
export function socketOf(kind: string): Socket | null {
  switch (kind) {
    case "udp":
    case "dtls_client":
    case "dtls_server":
      return "udp";
    case "tcp_client":
    case "telnet_client":
    case "tls_client":
      return "client";
    case "tcp_server":
    case "telnet_server":
    case "tls_server":
      return "server";
    case "replay":
      return "replay";
    default:
      return setupOf(kind)?.socket ?? null;
  }
}

/** "14:02:11.204" */
export function clock(ms: number): string {
  const time = new Date(ms);
  const two = (n: number) => String(n).padStart(2, "0");
  return `${two(time.getHours())}:${two(time.getMinutes())}:${two(time.getSeconds())}.${String(time.getMilliseconds()).padStart(3, "0")}`;
}

/** "2.7 s", "4 min 10 s" */
export function duration(ms: number): string {
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${Math.round(seconds % 60)} s`;
}

/** The file's name, without its folder. */
export function fileName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

/** A recording's name for its tab: the file name without its time and extension. */
export function recordingName(path: string): string {
  return fileName(path)
    .replace(/\.(nrec|trec)$/i, "")
    .replace(/ \d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}( \(\d+\))?$/, "");
}

/** Bytes as people read them: "812 B", "4.1 KB". */
export function byteText(count: number): string {
  if (count < 1024) return `${count} B`;
  if (count < 1024 * 1024) return `${(count / 1024).toFixed(1)} KB`;
  return `${(count / 1024 / 1024).toFixed(1)} MB`;
}

let nextId = 1;

/** One tab: a kind of socket, its views, and the data it showed. */
export class Tab {
  /** Tells tabs apart while they are open, even with the same name; the Rust side knows the session by it. */
  readonly id = nextId++;
  readonly kind: string;
  readonly socket: Socket | null;
  name = $state("");
  view: View = $state("terminal");
  udp: UdpConfig = $state({ ...DEFAULT_UDP });
  client: TcpClientConfig = $state({ ...DEFAULT_TCP_CLIENT });
  server: TcpServerConfig = $state({ ...DEFAULT_TCP_SERVER });
  replay: ReplaySetup = $state({ ...DEFAULT_REPLAY });
  terminal: TerminalOptions = $state({ ...DEFAULT_TERMINAL });
  /** True while the session runs: connected or listening, or waiting to. */
  running = $state(false);
  /** What the session last said, while it runs. */
  status: NetState | null = $state(null);
  /** The other ends it talks to now. */
  peers: Peer[] = $state([]);
  /** Who the send box sends to: "default", "all" or "peer:3". */
  sendTo = $state("default");
  /** The last problem the session reported that did not end it, such as a datagram not sent. */
  problem: string | null = $state(null);
  rx = $state(0);
  tx = $state(0);
  /** When the session connected, or started listening. */
  connectedAt: number | null = $state(null);
  log = $state(false);
  logPath: string | null = $state(null);
  recordPath: string | null = $state(null);
  playback: PlayState | null = $state(null);
  hexView: HexView = $state({ ...DEFAULT_HEX_VIEW });
  linesView: LinesView = $state({ ...DEFAULT_LINES_VIEW });
  plotView: PlotView = $state({ ...DEFAULT_PLOT_VIEW });
  /** The number of the first line the plot reads: Clear in the Plot view moves it on. */
  plotFrom = $state(0);
  /** The lines lately, oldest first, for the Lines view and the plot: plain values, as there can be many. */
  readonly textLines: StoredLine[] = [];
  readonly levelCounts = new Map<string, number>();
  readonly moduleCounts = new Map<string, number>();
  readonly bookmarks = new Set<number>();
  linesVersion = $state(0);
  history: SentLine[] = $state([]);
  /** What is in the send box, kept while the tab is out of sight. */
  draft = $state({ text: "", hex: false, enter: true });
  /** Whether a protocol tab's send box shows the form for its commands, not the line to type them. */
  sendForm = $state(true);
  /** How a Modbus tab's view asks or answers. */
  modbusSetup: ModbusSetup = $state(structuredClone(DEFAULT_MODBUS));
  /** A Modbus tab's master or slave, on its connection, and the frames that went and came. */
  readonly modbus = new ModbusSession({
    send: (bytes, peer) => this.sendBytes(bytes, peer === undefined ? undefined : { to: "peer" as const, peer }),
    setup: () => this.modbusSetup,
    changed: () => changed(),
    connected: () => this.connected,
  });
  /** How an MQTT tab's view publishes, subscribes and shows. */
  mqttSetup: MqttSetup = $state(structuredClone(DEFAULT_MQTT));
  /** What an MQTT tab's engine reported, for its view, and what the view asks of the engine. */
  readonly mqtt = new MqttSession({
    command: (line) => this.sendLine(line, false, true),
    setup: () => this.mqttSetup,
    changed: () => changed(),
    connected: () => this.connected,
    broker: () => this.kind === "mqtt_server",
  });
  /** A CoAP tab's view: its requests, or its resources, and what its engine reported. */
  coapSetup: CoapSetup = $state(structuredClone(DEFAULT_COAP));
  readonly coap = new CoapSession({
    command: (line) => this.sendLine(line, false, true),
    setup: () => this.coapSetup,
    connected: () => this.connected,
  });
  /** An HTTP tab's view: its requests, or its routes, and what its engine reported. */
  httpSetup: HttpSetup = $state(structuredClone(DEFAULT_HTTP));
  readonly http = new HttpSession({
    command: (line) => this.sendLine(line, false, true),
    setup: () => this.httpSetup,
    connected: () => this.connected,
  });
  /** An LwM2M tab's view: a server's devices and requests, or a device's state, and what its engine reported. */
  lwm2mSetup: Lwm2mSetup = $state(structuredClone(DEFAULT_LWM2M));
  readonly lwm2m = new Lwm2mSession({
    command: (line) => this.sendLine(line, false, true),
    setup: () => this.lwm2mSetup,
    connected: () => this.connected,
    server: () => this.kind === "lwm2m_server",
  });
  /** An MCUmgr tab's view: a board's answers, images and upload, or a simulated board's, and what its engine reported. */
  mcumgrSetup: McumgrSetup = $state(structuredClone(DEFAULT_MCUMGR));
  readonly mcumgr = new McumgrSession({
    command: (line) => this.sendLine(line, false, true),
    setup: () => this.mcumgrSetup,
    connected: () => this.connected,
  });
  sending: { name: string; sent: number; total: number } | null = $state(null);
  scrollLock = $state(false);
  sequence: { name: string; round: number; rounds: number } | null = $state(null);
  /** What TLS agreed with each peer, while it is connected. */
  secure: Map<number, Agreed> = $state(new Map());
  /** A protocol tab's own settings, such as an MQTT client's id. */
  protocol: Record<string, unknown> = $state({});
  /** DTLS on the UDP socket: a DTLS tab's, or a protocol's over DTLS; null for none. */
  dtls: DtlsOptions | null = $state(null);

  /**
   * The session's closing, which a new start waits for: a tab started again
   * with new settings must not open its port while the old session holds it.
   */
  private closing: Promise<unknown> = Promise.resolve();
  private nextLine = 0;
  private linesAt = 0;
  private term: Terminal | null = null;
  private hexTerm: Terminal | null = null;
  private hexDump = new HexDump(DEFAULT_HEX_VIEW, 0);
  private hexTimer: ReturnType<typeof setTimeout> | undefined;
  private recent: { tx: boolean; at: number; bytes: Uint8Array; peer: number }[] = [];
  private recentBytes = 0;
  /** What came before the terminal was ready. */
  private early: (Uint8Array | string)[] = [];
  /** The peer whose bytes the terminal and the hex view showed last, to mark where another's start. */
  private shownPeer = 0;
  private hexPeer = 0;
  private lastReceived = 0;
  private sentSince = false;
  /** Whether what was written to the terminal last ended a line. */
  private atLineStart = true;
  /** The peer heard from last, which the send box's usual target answers on a server. */
  private lastHeard = 0;
  /** Every peer met, by number, also those gone, for the lines and the marks. */
  private known = new Map<number, string>();
  private stopping = false;
  private wake: (() => void) | null = null;
  private playWhenOpen = false;
  /** When the connection was lost, while it is waited for. */
  private lostAt: number | null = null;

  constructor(setup: TabSetup) {
    this.kind = setup.kind;
    this.socket = socketOf(setup.kind);
    this.name = setup.name;
    // A tab whose protocol has a view of its own, as Modbus and MQTT do, opens on it.
    const own = setupOf(setup.kind)?.view;
    const views = [...(own ? [own] : []), "terminal", "hex", "lines", "plot"];
    this.view = (views.includes(setup.view ?? "") ? setup.view : views[0]) as View;
    this.log = setup.log ?? false;
    this.udp = { ...DEFAULT_UDP, ...setup.udp };
    this.client = { ...DEFAULT_TCP_CLIENT, ...setup.tcp_client };
    this.server = { ...DEFAULT_TCP_SERVER, ...setup.tcp_server };
    this.replay = { ...DEFAULT_REPLAY, ...setup.replay };
    // A Telnet tab speaks Telnet, and a TLS tab TLS, whatever its settings say.
    if (this.kind === "telnet_client") this.client.telnet = true;
    if (this.kind === "telnet_server") this.server.telnet = true;
    this.client.tls = this.kind === "tls_client" ? { ...DEFAULT_TLS_CLIENT, ...setup.tcp_client?.tls } : null;
    this.server.tls = this.kind === "tls_server" ? { ...DEFAULT_TLS_SERVER, ...setup.tcp_server?.tls } : null;
    if (this.kind === "dtls_client" || this.kind === "dtls_server") {
      this.dtls = { ...DEFAULT_DTLS, ...setup.dtls };
      if (!setup.udp) {
        if (this.kind === "dtls_server") this.udp.local_port = 5684;
        else {
          this.udp.remote_host = "127.0.0.1";
          this.udp.remote_port = 5684;
        }
      }
    }
    const protocol = setupOf(this.kind);
    if (protocol) {
      if (protocol.dtlsPort && setup.dtls) this.dtls = { ...DEFAULT_DTLS, ...setup.dtls };
      this.protocol = optionsOf(this.kind, setup.protocol);
      // TLS where the protocol runs over it and the tab turned it on.
      if (protocol.tlsPort && setup.tcp_client?.tls) this.client.tls = { ...DEFAULT_TLS_CLIENT, ...setup.tcp_client.tls };
      if (protocol.tlsPort && setup.tcp_server?.tls) this.server.tls = { ...DEFAULT_TLS_SERVER, ...setup.tcp_server.tls };
      // A new tab starts on the protocol's own port, and shows what the engine shows as it is.
      if (!setup.tcp_client && !setup.tcp_server && !setup.udp) {
        this.client.port = protocol.port;
        this.server.port = protocol.port;
        if (protocol.socket === "udp") {
          if (this.kind.endsWith("_server")) this.udp.local_port = protocol.port;
          else {
            this.udp.remote_host = "127.0.0.1";
            this.udp.remote_port = protocol.port;
          }
          this.udp = { ...this.udp, ...protocol.udp };
        }
      }
      if (!setup.ui?.terminal) this.terminal = { ...this.terminal, local_echo: false, enter: "lf" };
    }
    const ui = setup.ui ?? {};
    this.terminal = { ...DEFAULT_TERMINAL, ...ui.terminal };
    this.hexView = { ...DEFAULT_HEX_VIEW, ...ui.hex_view };
    this.linesView = { ...DEFAULT_LINES_VIEW, ...ui.lines_view };
    this.plotView = { ...DEFAULT_PLOT_VIEW, ...ui.plot_view, trigger: { ...DEFAULT_PLOT_VIEW.trigger, ...ui.plot_view?.trigger } };
    this.history = ui.history ?? [];
    this.sendTo = ui.send_to ?? "default";
    this.sendForm = ui.send_form ?? true;
    if (this.isModbus) {
      // A tab from before the view had its unit and framing in its protocol settings.
      const before = setup.protocol ?? {};
      const earlier = ui.modbus ? {} : { mode: before.rtu ? "rtu" : "tcp", unit: Number(before.unit ?? 0) };
      this.modbusSetup = { ...structuredClone(DEFAULT_MODBUS), ...earlier, ...ui.modbus } as ModbusSetup;
      this.modbusSetup.role = this.kind === "modbus_server" ? "slave" : "master";
    }
    if (this.isMqtt) this.mqttSetup = { ...structuredClone(DEFAULT_MQTT), ...ui.mqtt };
    if (this.ownView === "coap") this.coapSetup = { ...structuredClone(DEFAULT_COAP), ...ui.coap };
    if (this.ownView === "http") this.httpSetup = { ...structuredClone(DEFAULT_HTTP), ...ui.http };
    if (this.ownView === "lwm2m") this.lwm2mSetup = { ...structuredClone(DEFAULT_LWM2M), ...ui.lwm2m };
    if (this.ownView === "mcumgr") this.mcumgrSetup = { ...structuredClone(DEFAULT_MCUMGR), ...ui.mcumgr };
  }

  /**
   * Whether the tab runs a protocol's engine, which reads typed commands. A
   * Modbus tab is a protocol tab whose view speaks Modbus instead, on a
   * plain socket.
   */
  get engine(): boolean {
    const setup = setupOf(this.kind);
    return setup !== undefined && !setup.plain;
  }

  /** Whether the tab is a Modbus master or slave, which its Modbus view drives. */
  get isModbus(): boolean {
    return setupOf(this.kind)?.view === "modbus";
  }

  /** Whether the tab is an MQTT client or broker, with its MQTT view. */
  get isMqtt(): boolean {
    return setupOf(this.kind)?.view === "mqtt";
  }

  /** The view of the tab's protocol's own, such as "coap", which it opens on. */
  get ownView(): View | undefined {
    return setupOf(this.kind)?.view;
  }

  /** Reads what went and came lately again as Modbus, as the view's mode changes. */
  readModbusAgain(): void {
    this.modbus.readAgain(this.recent);
  }

  /** Whether the tab runs a protocol's engine, which takes typed commands. */
  get isProtocol(): boolean {
    return setupOf(this.kind) !== undefined;
  }

  /** Whether the tab is of a kind built so far, so it can connect. */
  get built(): boolean {
    return this.socket !== null && (this.kind === "replay" || isReady(this.kind));
  }

  /** Connected, or listening: it can send and receive. */
  get connected(): boolean {
    return this.status?.state === "connected" || this.status?.state === "listening";
  }

  /** Whether it talks to many peers at once, so the send box asks which. */
  get manyPeers(): boolean {
    return this.socket === "udp" || this.socket === "server";
  }

  /** Whether what is typed and sent goes anywhere: not into a recording. */
  get takesInput(): boolean {
    return this.socket !== "replay";
  }

  /** What the tab is set to, in a few words: "UDP :5683 → 10.0.0.5:5683". */
  get target(): string {
    const protocol = this.isProtocol ? endOf(this.kind)?.protocol.name : undefined;
    if (protocol) {
      // "MQTT to 127.0.0.1:1883", "MQTT over TLS on :8883", "CoAP to 10.0.0.5:5683".
      if (this.socket === "none") return `${protocol} ${String(this.protocol.host ?? "")}`.trim();
      const tls = this.client.tls || this.server.tls ? " over TLS" : this.dtls ? " over DTLS" : "";
      const text = this.socket === "udp" ? udpText(this.udp) : this.socket === "client" ? clientText(this.client) : serverText(this.server);
      return text.replace(/^(TLS|TCP|UDP)( server)?/, `${protocol}${tls}`);
    }
    switch (this.socket) {
      case "udp":
        return this.dtls ? udpText(this.udp).replace(/^UDP/, "DTLS") : udpText(this.udp);
      case "client":
        return clientText(this.client);
      case "server":
        return serverText(this.server);
      case "replay":
        return this.replay.path ? fileName(this.replay.path) : "no recording";
      default:
        return "";
    }
  }

  /** The tab as it is saved. */
  setup(): TabSetup {
    const ui: TabUi = {
      terminal: this.terminal,
      hex_view: this.hexView,
      lines_view: this.linesView,
      plot_view: this.plotView,
      history: this.history,
      send_to: this.sendTo,
    };
    if (this.engine) ui.send_form = this.sendForm;
    if (this.isModbus) ui.modbus = this.modbusSetup;
    if (this.isMqtt) ui.mqtt = this.mqttSetup;
    if (this.ownView === "coap") ui.coap = this.coapSetup;
    if (this.ownView === "http") ui.http = this.httpSetup;
    if (this.ownView === "lwm2m") ui.lwm2m = this.lwm2mSetup;
    if (this.ownView === "mcumgr") ui.mcumgr = this.mcumgrSetup;
    const setup: TabSetup = {
      name: this.name,
      kind: this.kind,
      connected: this.running && this.socket !== "replay",
      view: this.view,
      log: this.log,
      ui,
    };
    if (this.socket === "udp") setup.udp = this.udp;
    if (this.socket === "client") setup.tcp_client = this.client;
    if (this.socket === "server") setup.tcp_server = this.server;
    if (this.socket === "replay") setup.replay = this.replay;
    if (this.isProtocol) setup.protocol = this.protocol;
    if (this.dtls) setup.dtls = this.dtls;
    return withoutNulls($state.snapshot(setup)) as TabSetup;
  }

  /** Called by the tab's terminal once it is on screen, and with null when it goes. */
  attach(term: Terminal | null): void {
    this.term = term;
    if (term) {
      for (const chunk of this.early) {
        term.write(chunk);
      }
      this.early = [];
    }
  }

  /** Called by the tab's hex view when it opens, which shows what came lately, and with null when it closes. */
  attachHex(term: Terminal | null): void {
    clearTimeout(this.hexTimer);
    this.hexTerm = term;
    if (term) {
      this.hexDump = new HexDump(this.hexView, this.terminal.pause_ms);
      this.hexPeer = 0;
      let text = "";
      for (const chunk of this.recent) {
        text += this.hexText(chunk.tx, chunk.at, chunk.bytes, chunk.peer);
      }
      term.write(text + this.hexDump.finish());
    }
  }

  /** A shell on a real terminal needs its size; sockets do not. */
  resized(_cols: number, _rows: number): void {}

  setView(view: View): void {
    this.view = view;
    changed();
  }

  setHexView(hexView: HexView): void {
    this.hexView = hexView;
    this.layOutHex();
    changed();
  }

  setLinesView(linesView: LinesView): void {
    this.linesView = linesView;
    changed();
  }

  setPlotView(plotView: PlotView): void {
    this.plotView = plotView;
    changed();
  }

  setSendForm(form: boolean): void {
    this.sendForm = form;
    changed();
  }

  /** Starts the plot again from the next line, leaving the lines kept as they are. */
  clearPlot(): void {
    this.plotFrom = this.nextLine;
  }

  toggleBookmark(n: number): void {
    if (!this.bookmarks.delete(n)) {
      this.bookmarks.add(n);
    }
    this.linesVersion++;
  }

  clearLines(): void {
    this.textLines.length = 0;
    this.levelCounts.clear();
    this.moduleCounts.clear();
    this.bookmarks.clear();
    this.linesVersion++;
  }

  setPause(ms: number): void {
    this.terminal.pause_ms = ms;
    this.layOutHex();
    changed();
  }

  setTerminal(options: TerminalOptions): void {
    this.terminal = options;
    changed();
  }

  setScrollLock(on: boolean): void {
    this.scrollLock = on;
  }

  /** Clears the terminal, or the hex view while it is shown. */
  clearScreen(): void {
    (this.view === "hex" ? this.hexTerm : this.term)?.clear();
  }

  /** Connects, starts listening, or opens the recording. */
  start(): void {
    if (this.running || !this.built) {
      return;
    }
    this.running = true;
    this.status = null;
    this.problem = null;
    this.peers = [];
    this.secure = new Map();
    this.lostAt = null;
    const data = new Channel<ArrayBuffer | number[]>();
    data.onmessage = (message) => {
      const frame = readFrame(message instanceof ArrayBuffer ? message : new Uint8Array(message));
      if (frame && this.running) this.receive(frame.sent, frame.peer, frame.at, frame.bytes);
    };
    const events = new Channel<SessionEvent>();
    events.onmessage = (event) => this.onEvent(event);
    if (this.socket === "replay") {
      this.openRecording(data, events);
      changed();
      return;
    }
    const common = { id: this.id, log: this.logSetup(), data, events };
    // Opened once the session before it has closed.
    const open = (command: string, args: Record<string, unknown>) =>
      this.closing.then(() => invoke<LogStatus>(command, args));
    let started: Promise<LogStatus>;
    // A Modbus slave answers the masters that connect as soon as it listens.
    if (this.isModbus) this.modbus.setAnswering(this.kind === "modbus_server");
    if (this.engine) {
      const socket =
        this.socket === "udp"
          ? { udp: $state.snapshot(this.udp), dtls: this.dtls ? $state.snapshot(this.dtls) : null }
          : this.socket === "client"
            ? { client: $state.snapshot(this.client) }
            : this.socket === "server"
              ? { server: $state.snapshot(this.server) }
              : {};
      // A client's engine learns where it connects, for headers such as HTTP's Host.
      const where = this.socket === "client" ? { host: this.client.host, port: this.client.port } : {};
      started = open("open_protocol_session", {
        ...common,
        kind: this.kind,
        options: { ...$state.snapshot(this.protocol), ...where },
        socket,
      });
      started.then((status) => this.onLogStatus(status)).catch((error) => this.note(`could not start: ${error}`));
      changed();
      return;
    }
    switch (this.socket) {
      case "udp":
        started = this.dtls
          ? open("open_dtls_session", {
              ...common,
              config: $state.snapshot(this.udp),
              dtls: $state.snapshot(this.dtls),
              client: this.kind === "dtls_client",
            })
          : open("open_udp_session", { ...common, config: $state.snapshot(this.udp) });
        break;
      // A Modbus tab times each answer: what comes is passed on at once, not gathered for the screen.
      case "client":
        started = open("open_tcp_client_session", { ...common, config: $state.snapshot(this.client), atOnce: this.isModbus });
        break;
      default:
        started = open("open_tcp_server_session", { ...common, config: $state.snapshot(this.server), atOnce: this.isModbus });
    }
    started.then((status) => this.onLogStatus(status)).catch((error) => this.note(`could not start: ${error}`));
    changed();
  }

  /** Disconnects, or stops listening. */
  stop(): void {
    if (!this.running) {
      return;
    }
    if (this.connected) {
      this.note(`closed at ${clock(Date.now())}`);
    }
    if (this.recordPath) {
      this.note(`recording saved: ${this.recordPath}`);
    }
    this.stopSequence();
    this.modbus.stop();
    this.mqtt.closed();
    this.coap.closed();
    this.http.closed();
    this.lwm2m.closed();
    this.mcumgr.closed();
    this.running = false;
    this.status = null;
    this.peers = [];
    this.secure = new Map();
    this.connectedAt = null;
    this.logPath = null;
    this.recordPath = null;
    this.playback = null;
    this.closing = invoke("close_session", { id: this.id }).catch(() => undefined);
    changed();
  }

  /** Changes a protocol tab's settings: its socket's and its engine's. A running tab starts again with them. */
  reconfigureProtocol(
    socket: { udp?: UdpConfig; client?: TcpClientConfig; server?: TcpServerConfig; dtls?: DtlsOptions | null },
    options: Record<string, unknown>,
  ): void {
    if (socket.udp) this.udp = socket.udp;
    if (socket.dtls !== undefined) this.dtls = socket.dtls;
    if (socket.client) this.client = socket.client;
    if (socket.server) this.server = socket.server;
    this.protocol = options;
    if (this.running) {
      this.stop();
      this.start();
    }
    changed();
  }

  /** Changes a DTLS tab's settings. A running tab starts again with them. */
  reconfigureDtls(config: UdpConfig, dtls: DtlsOptions): void {
    this.udp = config;
    this.dtls = dtls;
    if (this.running) {
      this.stop();
      this.start();
    }
    changed();
  }

  /** Changes a UDP tab's settings; an open socket opens again at once. */
  reconfigureUdp(config: UdpConfig): void {
    this.udp = config;
    if (this.running) void invoke("reconfigure_udp_session", { id: this.id, config: $state.snapshot(config) });
    changed();
  }

  /** Changes a client's settings; a running client connects again at once. */
  reconfigureClient(config: TcpClientConfig): void {
    this.client = {
      ...config,
      telnet: this.kind === "telnet_client" ? true : config.telnet,
      tls: this.kind === "tls_client" || (setupOf(this.kind)?.tlsPort && config.tls) ? { ...DEFAULT_TLS_CLIENT, ...config.tls } : null,
    };
    if (this.running) {
      void invoke("reconfigure_tcp_client_session", { id: this.id, config: $state.snapshot(this.client) });
    }
    changed();
  }

  /** Changes a server's settings; a running server listens again at once. */
  reconfigureServer(config: TcpServerConfig): void {
    this.server = {
      ...config,
      telnet: this.kind === "telnet_server" ? true : config.telnet,
      tls: this.kind === "tls_server" || (setupOf(this.kind)?.tlsPort && config.tls) ? { ...DEFAULT_TLS_SERVER, ...config.tls } : null,
    };
    if (this.running) {
      void invoke("reconfigure_tcp_server_session", { id: this.id, config: $state.snapshot(this.server) });
    }
    changed();
  }

  /** Ends one client's connection on a server, with a reset when `reset`. */
  dropPeer(peer: number, reset: boolean): void {
    void invoke("drop_peer", { id: this.id, peer, reset });
  }

  /** Ends a client's connection with a reset, to see how the other end takes it. */
  resetConnection(): void {
    if (this.socket === "client" && this.connected) {
      void invoke("drop_peer", { id: this.id, peer: null, reset: true });
    }
  }

  private openRecording(data: Channel<ArrayBuffer | number[]>, events: Channel<SessionEvent>): void {
    const { path, speed } = this.replay;
    invoke<ReplayInfo>("open_replay_session", { id: this.id, path, speed, data, events })
      .then((info) => {
        if (!this.running) {
          return;
        }
        this.connectedAt = Date.now();
        this.status = { state: "connected", address: fileName(path), local: "" };
        this.note(`playing ${fileName(path)}: ${duration(info.length * 1000)} recorded from ${info.name || "a tab"}`);
        if (this.playWhenOpen) {
          this.playWhenOpen = false;
          this.control({ kind: "play" });
        }
      })
      .catch((error) => {
        this.note(String(error));
        this.stop();
      });
  }

  /** Plays the recording of a replay tab, opening it first if it is not open. */
  play(): void {
    if (this.socket !== "replay") return;
    if (!this.running) {
      this.playWhenOpen = true;
      this.start();
      return;
    }
    this.control({ kind: "play" });
  }

  pause(): void {
    this.control({ kind: "pause" });
  }

  seek(position: number): void {
    this.control({ kind: "seek", position });
  }

  setSpeed(speed: number): void {
    this.replay.speed = speed;
    this.control({ kind: "speed", speed });
    changed();
  }

  private control(command: ReplayCommand): void {
    if (this.running) void invoke("control_replay", { id: this.id, command });
  }

  /** Clears what the tab shows, for a recording that starts again. */
  private clearViews(): void {
    this.write("\x1bc");
    this.recent = [];
    this.recentBytes = 0;
    this.shownPeer = 0;
    this.layOutHex();
    this.clearLines();
    this.rx = 0;
    this.tx = 0;
  }

  /** Starts or stops recording what the tab receives and sends, with its timing and peers. */
  setRecording(on: boolean): void {
    if (!this.running || this.socket === "replay") return;
    const before = this.recordPath;
    const folder = on ? settings.log.folder : null;
    invoke<LogStatus>("set_recording", { id: this.id, folder, name: this.name })
      .then((status) => {
        this.recordPath = status.path;
        if (status.path) this.note(`recording to ${status.path}`);
        else if (status.problem) this.note(status.problem);
        else if (before) this.note(`recording saved: ${before}`);
      })
      .catch((error) => this.note(`could not record: ${error}`));
  }

  /** Turns the tab's log on or off. A running session starts a new file at once. */
  setLog(on: boolean): void {
    this.log = on;
    changed();
    if (!this.running || this.socket === "replay") return;
    if (!on && this.logPath) this.note(`log closed: ${this.logPath}`);
    this.logPath = null;
    invoke<LogStatus>("set_log", { id: this.id, log: this.logSetup() })
      .then((status) => this.onLogStatus(status))
      .catch((error) => this.note(`could not start the log: ${error}`));
  }

  private logSetup(): LogSetup | null {
    if (!this.log) return null;
    const { folder, format, timestamps } = settings.log;
    return { folder, name: this.name, format, timestamps };
  }

  private onLogStatus(status: LogStatus): void {
    this.logPath = status.path;
    if (status.path) {
      this.note(`logging to ${status.path}`);
    } else if (status.problem) {
      this.log = false;
      this.note(status.problem);
      changed();
    }
  }

  /** Sends what was typed in the terminal, to the send box's target. */
  type(data: string): void {
    if (!this.connected || !this.takesInput) return;
    this.setScrollLock(false);
    this.sendBytes(encoder.encode(data.replace(/\r/g, ENTER[this.terminal.enter])));
    if (this.terminal.local_echo) this.write(echoed(data));
  }

  /**
   * Sends a line from the send box or a macro: hex digits, or text with
   * escapes such as \r, then the tab's Enter if `enter` is set. A protocol
   * tab's text goes as it was typed: its engine reads the escapes in a
   * payload itself, so \n stays in the payload and does not end the command.
   * Rejects with the reason when it cannot.
   */
  async sendLine(text: string, hex: boolean, enter: boolean): Promise<void> {
    if (this.socket === "replay") throw "A recording only plays back.";
    if (!this.connected) throw "Not connected.";
    const body =
      this.engine && !hex ? encoder.encode(text) : new Uint8Array(await invoke<number[]>("encode_input", { text, hex }));
    const end = enter ? encoder.encode(ENTER[this.terminal.enter]) : new Uint8Array();
    const bytes = new Uint8Array(body.length + end.length);
    bytes.set(body);
    bytes.set(end, body.length);
    if (bytes.length === 0) throw "Nothing to send.";
    this.sendBytes(bytes);
    if (this.terminal.local_echo) {
      this.write(hex ? `${DIM}${hexBytes(body)}${RESET}` : body);
      if (enter || this.socket === "udp") this.write("\r\n");
    }
  }

  /** Sends a macro from its key, and says in the terminal why when it cannot. */
  async sendMacro(macro: Macro): Promise<void> {
    this.setScrollLock(false);
    try {
      await this.sendLine(macro.text, macro.hex, macro.enter);
    } catch (problem) {
      this.note(`${macro.name}: ${problem}`);
    }
  }

  /** Sends a sequence's macros one after another, with its wait after each, then says how it ended. */
  async runSequence(sequence: Sequence): Promise<void> {
    if (this.sequence) return;
    const macros = sequence.steps.map((name) => settings.macros.find((macro) => macro.name === name));
    const missing = sequence.steps.find((_, index) => macros[index] === undefined);
    if (macros.length === 0 || missing !== undefined) {
      this.note(`${sequence.name}: ${missing === undefined ? "it has no macros" : `there is no macro called ${missing}`}`);
      return;
    }
    this.stopping = false;
    let done = 0;
    try {
      while (sequence.repeat === 0 || done < sequence.repeat) {
        this.sequence = { name: sequence.name, round: done + 1, rounds: sequence.repeat };
        for (const macro of macros as Macro[]) {
          if (this.stopping) {
            this.note(`${sequence.name}: stopped, after ${done} of ${sequence.repeat || "∞"} times`);
            return;
          }
          await this.sendLine(macro.text, macro.hex, macro.enter);
          await this.waitFor(sequence.delay_ms);
        }
        done++;
      }
      this.note(`${sequence.name}: sent ${done} ${done === 1 ? "time" : "times"}`);
    } catch (problem) {
      this.note(`${sequence.name}: ${problem}`);
    } finally {
      this.sequence = null;
      this.wake = null;
    }
  }

  stopSequence(): void {
    this.stopping = true;
    this.wake?.();
  }

  private waitFor(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, ms);
      this.wake = () => {
        clearTimeout(timer);
        resolve();
      };
    });
  }

  /** Keeps a line sent from the send box, so ↑ brings it back. */
  remember(text: string, hex: boolean): void {
    const last = this.history.at(-1);
    if (last && last.text === text && (last.hex ?? false) === hex) return;
    this.history.push(hex ? { text, hex } : { text });
    if (this.history.length > HISTORY_MAX) this.history.splice(0, this.history.length - HISTORY_MAX);
    changed();
  }

  /** Who the send box sends to now. */
  private sendTarget() {
    if (!this.manyPeers) return { to: "default" as const };
    const target = targetOf(this.sendTo);
    // A peer that went: back to the usual.
    if (target.to === "peer" && !this.peers.some((peer) => peer.id === target.peer)) return { to: "default" as const };
    return target;
  }

  /**
   * Sends bytes, to whom the send box sends unless told, and shows them in
   * the hex view and the Lines view.
   */
  private sendBytes(bytes: Uint8Array, to?: ReturnType<typeof targetOf>): void {
    if (bytes.length === 0) return;
    const target = to ?? this.sendTarget();
    void invoke<boolean>("write_session", { id: this.id, target, data: Array.from(bytes) });
    this.tx += bytes.length;
    this.sentSince = true;
    const at = Date.now();
    const peer = target.to === "peer" ? target.peer : 0;
    this.keepForHex(true, bytes, at, peer);
    if (this.isModbus) this.modbus.heard(true, bytes, at, peer);
    if (this.linesView.sent !== false) {
      const text = new TextDecoder().decode(bytes).replace(/[\r\n]+$/, "");
      if (text) {
        const to =
          target.to === "peer" ? this.known.get(target.peer) : target.to === "all" ? "all" : this.defaultDestination();
        this.addLines([{ text, time: null, level: null, module: null, message: text }], at, to, true);
      }
    }
  }

  /** Where the send box's usual target is now, for the Lines view: the remote address, or the peer heard last. */
  private defaultDestination(): string | undefined {
    if (this.socket === "client") return this.status?.state === "connected" ? this.status.address : undefined;
    if (this.socket === "udp" && this.udp.remote_host.trim()) return hostAndPort(this.udp.remote_host, this.udp.remote_port);
    return this.known.get(this.lastHeard);
  }

  /** Sends a file, paced for the link, with its progress in `sending`. */
  async sendFile(path: string, bytesPerSecond = 0, datagram = DATAGRAM_DEFAULT): Promise<void> {
    if (!this.connected || this.sending || !this.takesInput) return;
    const name = fileName(path);
    const started = Date.now();
    this.sending = { name, sent: 0, total: 0 };
    this.note(`sending ${name}`);
    const progress = new Channel<FileProgress>();
    progress.onmessage = (report) => this.onFileProgress(name, started, report);
    try {
      await invoke("send_file", { id: this.id, target: this.sendTarget(), path, bytesPerSecond, datagram, progress });
    } catch (error) {
      this.sending = null;
      this.note(String(error));
    }
  }

  cancelSend(): void {
    if (this.sending) void invoke("cancel_send", { id: this.id });
  }

  private onFileProgress(name: string, started: number, report: FileProgress): void {
    if (!this.sending) return;
    this.tx += report.sent - this.sending.sent;
    this.sending = { name, sent: report.sent, total: report.total };
    if (!report.done) return;
    this.sending = null;
    if (report.problem) this.note(report.problem);
    else if (report.cancelled) this.note(`stopped sending ${name} after ${byteText(report.sent)} of ${byteText(report.total)}`);
    else this.note(`sent ${name}, ${byteText(report.total)} in ${duration(Date.now() - started)}`);
  }

  /** Bytes a peer sent, or this end sent in a recording played back. */
  private receive(sent: boolean, peer: number, at: number, bytes: Uint8Array): void {
    if (sent) {
      this.tx += bytes.length;
      this.keepForHex(true, bytes, at, peer);
      this.write(`${DIM}`);
      this.write(bytes);
      this.write(RESET);
      return;
    }
    this.rx += bytes.length;
    this.lastHeard = peer;
    // Where another peer's bytes start, a line names it, on a tab that hears from many.
    // Peer 0 is the tab's own notes, such as a protocol's answer to help: no mark for it.
    if (this.manyPeers && peer !== 0 && peer !== this.shownPeer) {
      this.shownPeer = peer;
      this.lineBreak();
      this.write(`${DIM}── ${this.known.get(peer) ?? `peer ${peer}`} ──${RESET}\r\n`);
    } else {
      // After a pause, what comes starts on a new line, but not an echo of what was just typed.
      const pause = this.terminal.pause_ms;
      if (pause > 0 && at - this.lastReceived >= pause && !this.sentSince) this.lineBreak();
    }
    this.lastReceived = at;
    this.sentSince = false;
    this.write(bytes);
    // A datagram is a message of its own: the next one starts a line of its own.
    if (this.socket === "udp") this.lineBreak();
    this.keepForHex(false, bytes, at, peer);
    if (this.isModbus) {
      this.modbus.receive(bytes, at, peer);
      this.modbus.heard(false, bytes, at, peer);
    }
  }

  /** Ends the terminal's line, unless what was written last ended one already. */
  private lineBreak(): void {
    if (!this.atLineStart) this.write("\r\n");
  }

  private keepForHex(tx: boolean, bytes: Uint8Array, at: number, peer: number): void {
    this.recent.push({ tx, at, bytes, peer });
    this.recentBytes += bytes.length;
    if (this.recentBytes > 2 * RECENT_MAX) {
      let drop = 0;
      while (this.recentBytes > RECENT_MAX && drop < this.recent.length - 1) {
        this.recentBytes -= this.recent[drop].bytes.length;
        drop++;
      }
      this.recent.splice(0, drop);
    }
    if (this.hexTerm) {
      this.hexTerm.write(this.hexText(tx, at, bytes, peer));
      clearTimeout(this.hexTimer);
      const pause = this.terminal.pause_ms;
      if (pause > 0) this.hexTimer = setTimeout(() => this.hexTerm?.write(this.hexDump.finish()), pause);
    }
  }

  /** The hex view's text for a piece: a line naming the peer when it changes, and each datagram on lines of its own. */
  private hexText(tx: boolean, at: number, bytes: Uint8Array, peer: number): string {
    let out = "";
    if (this.manyPeers && !tx && peer !== 0 && peer !== this.hexPeer) {
      this.hexPeer = peer;
      out += `${this.hexDump.finish()}${DIM}── ${this.known.get(peer) ?? `peer ${peer}`} ──${RESET}\r\n`;
    }
    out += this.hexDump.feed(tx, at, bytes);
    if (this.socket === "udp") out += this.hexDump.finish();
    return out;
  }

  private layOutHex(): void {
    const term = this.hexTerm;
    if (term) {
      term.write("\x1bc");
      this.attachHex(term);
    }
  }

  private onEvent(event: SessionEvent): void {
    if (!this.running) return;
    switch (event.kind) {
      case "state": {
        const { kind: _, ...state } = event;
        this.onState(state as NetState);
        return;
      }
      case "peer_joined": {
        const peer = { id: event.id, address: event.address };
        this.known.set(peer.id, peer.address);
        if (!this.peers.some((known) => known.id === peer.id)) this.peers = [...this.peers, peer];
        if (this.socket === "server") this.note(`${peer.address} connected`);
        return;
      }
      case "peer_left": {
        const gone = this.peers.find((peer) => peer.id === event.peer);
        this.peers = this.peers.filter((peer) => peer.id !== event.peer);
        this.modbus.forget(event.peer);
        // A client's connection went: no answer comes to what it asked.
        if (this.socket === "client") this.http.closed();
        if (this.secure.has(event.peer)) {
          const secure = new Map(this.secure);
          secure.delete(event.peer);
          this.secure = secure;
        }
        if (gone && this.socket === "server") this.note(`${gone.address} went`);
        return;
      }
      case "problem":
        this.problem = event.problem;
        this.note(event.problem);
        return;
      case "report":
        if (this.isMqtt) this.mqtt.report(event.report);
        else if (this.ownView === "coap") this.coap.report(event.report);
        else if (this.ownView === "http") this.http.report(event.report);
        else if (this.ownView === "lwm2m") this.lwm2m.report(event.report);
        else if (this.ownView === "mcumgr") this.mcumgr.report(event.report);
        return;
      case "secure": {
        this.secure = new Map(this.secure).set(event.peer, event.agreed);
        const who = this.socket === "server" ? `${this.known.get(event.peer) ?? "a client"}: ` : "";
        this.note(`${who}${agreedText(event.agreed)}`);
        event.agreed.chain.forEach((cert, index) => {
          const which = index === 0 ? (this.socket === "server" ? "its certificate" : "certificate") : `signed by`;
          this.note(`  ${which}: ${certText(cert)}`);
        });
        // With a PSK, no certificate is the usual.
        if (event.agreed.chain.length === 0 && this.socket === "server" && !event.agreed.name.startsWith("PSK ")) {
          this.note("  it sent no certificate");
        }
        return;
      }
      case "text_lines":
        this.addLines(event.lines, event.at, this.known.get(event.peer), event.sent);
        return;
      case "restarted":
        this.clearViews();
        return;
      case "replay_state":
        this.playback = { position: event.position, length: event.length, playing: event.playing, speed: event.speed };
        return;
      case "recording_stopped":
        this.recordPath = null;
        this.note(event.problem);
        return;
      case "log_stopped":
        this.logPath = null;
        this.log = false;
        this.note(event.problem);
        changed();
        return;
    }
  }

  private onState(state: NetState): void {
    const before = this.status;
    this.status = state;
    if (state.state === "connected") {
      this.connectedAt = Date.now();
      this.problem = null;
      if (this.lostAt !== null) {
        const now = Date.now();
        this.note(`disconnected ${clock(this.lostAt)}, reconnected ${clock(now)} (${duration(now - this.lostAt)})`);
        this.lostAt = null;
      } else if (this.socket !== "replay") {
        this.note(`connected to ${state.address}, from ${state.local}`);
      }
    } else if (state.state === "listening") {
      this.connectedAt = Date.now();
      this.problem = null;
      this.note(this.socket === "none" ? "started" : `listening on ${state.local}`);
    } else {
      if (before?.state === "connected" || before?.state === "listening") {
        this.lostAt = Date.now();
        this.connectedAt = null;
        this.note(state.problem ? `disconnected: ${state.problem}` : "disconnected");
      } else if (state.problem && state.problem !== this.problem) {
        this.note(state.problem);
      }
      this.problem = state.problem;
    }
  }

  /** Keeps lines for the Lines view and the plot, spread over the time since the read before. */
  private addLines(lines: LogLine[], at: number, from: string | undefined, sent: boolean): void {
    const step = this.linesAt > 0 ? Math.min(Math.max(0, at - this.linesAt), SPREAD_MS) / lines.length : 0;
    this.linesAt = at;
    lines.forEach((line, index) => {
      const when = at - (lines.length - 1 - index) * step;
      this.textLines.push({ ...line, n: this.nextLine++, at: when, peer: from, sent: sent || undefined });
      if (!sent) this.count(line, 1);
    });
    this.trimLines();
  }

  private trimLines(): void {
    if (this.textLines.length > LINES_MAX) {
      const gone = this.textLines.splice(0, this.textLines.length - LINES_MAX + LINES_MAX / 10);
      for (const line of gone) {
        if (!line.sent) this.count(line, -1);
        this.bookmarks.delete(line.n);
      }
    }
    this.linesVersion++;
  }

  private count(line: LogLine & { note?: boolean }, step: number): void {
    if (line.note) return;
    const level = line.level ?? "other";
    this.levelCounts.set(level, (this.levelCounts.get(level) ?? 0) + step);
    if (line.module) {
      const left = (this.moduleCounts.get(line.module) ?? 0) + step;
      if (left > 0) this.moduleCounts.set(line.module, left);
      else this.moduleCounts.delete(line.module);
    }
  }

  /** A line of the tab's own, such as "connected to …": in the terminal, dim, and in the Lines view. */
  note(text: string): void {
    this.lineBreak();
    this.write(`${DIM}---- ${text} ----${RESET}\r\n`);
    this.textLines.push({ text, time: null, level: null, module: null, message: text, note: true, n: this.nextLine++, at: Date.now() });
    this.trimLines();
  }

  /** Writes to the terminal, or keeps it until the terminal is on screen. */
  private write(data: Uint8Array | string): void {
    // Colors change nothing of where the line is; a reset puts the cursor at the start.
    if (typeof data === "string" && /^\x1b\[[0-9;]*m$/.test(data)) {
      // nothing
    } else if (data === "\x1bc") {
      this.atLineStart = true;
    } else if (data.length > 0) {
      const last = typeof data === "string" ? data.charCodeAt(data.length - 1) : data[data.length - 1];
      this.atLineStart = last === 0x0a;
    }
    if (this.term) {
      this.term.write(data);
    } else {
      this.early.push(data);
      if (this.early.length > 2000) this.early.splice(0, 500);
    }
  }
}

/** "AA 55 01" */
function hexBytes(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
}

/** The same object without its null and undefined values, which TOML cannot hold. */
export function withoutNulls(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(withoutNulls);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value)) {
      if (inner !== null && inner !== undefined) out[key] = withoutNulls(inner);
    }
    return out;
  }
  return value;
}

/** The open tabs. */
export const tabs: Tab[] = $state([]);

/** What is on screen: `active` is the tab in front, with the keyboard. */
export const view: { active: number; welcome: boolean } = $state({ active: 0, welcome: false });

let loaded = false;
let saveTimer: ReturnType<typeof setTimeout> | undefined;

/** The tab in front, or none while the Welcome tab is. */
export function activeTab(): Tab | undefined {
  return view.welcome ? undefined : tabs[view.active];
}

/** Shows the Welcome tab, which stays first in the bar however many tabs there are. */
export function showWelcome(): void {
  view.welcome = true;
}


/** Opens the tabs saved last time, if the Startup settings say so. The settings must be loaded first. */
export async function loadWorkspace(): Promise<void> {
  // A reload of the page leaves no session holding its port.
  await invoke("close_all_sessions").catch(() => undefined);
  const workspace = await invoke<Workspace>("get_workspace");
  loaded = true;
  let active: Tab | undefined;
  const saved = settings.startup.restore_tabs ? workspace.tabs : [];
  for (const at of reopened(saved, (kind) => kind === "replay" || endOf(kind) !== undefined)) {
    const setup = saved[at];
    const tab = new Tab(setup);
    if (at === workspace.active) active = tab;
    tabs.push(tab);
    if (setup.connected && settings.startup.reconnect) tab.start();
  }
  view.active = active ? tabs.indexOf(active) : 0;
  // The tabs that do not come back are taken out of the file too.
  changed();
}

/** Opens a new tab of a kind from new-tab.ts, and brings it in front. */
export function newTab(kind: string): Tab {
  const tab = new Tab({ name: freeName(endOf(kind)?.end.title ?? kind), kind, connected: false, log: settings.log.new_tabs });
  tabs.push(tab);
  showTab(tabs.length - 1);
  return tab;
}

/** Opens a recording in a new replay tab, and plays it. */
export function openRecording(path: string): Tab {
  const tab = new Tab({ name: freeName(recordingName(path)), kind: "replay", connected: false, replay: { path, speed: 1 } });
  tabs.push(tab);
  showTab(tabs.length - 1);
  tab.play();
  return tab;
}

/** "MQTT broker", or "MQTT broker 2" when there is one already. */
export function freeName(label: string): string {
  const taken = new Set(tabs.map((tab) => tab.name));
  let name = label;
  for (let number = 2; taken.has(name); number++) {
    name = `${label} ${number}`;
  }
  return name;
}

export function closeTab(tab: Tab): void {
  const index = tabs.indexOf(tab);
  if (index < 0) return;
  tab.stop();
  tabs.splice(index, 1);
  const after = index < view.active ? view.active - 1 : view.active;
  view.active = Math.min(after, Math.max(0, tabs.length - 1));
  changed();
}

/** Brings a tab in front, going round past the ends. */
export function showTab(index: number): void {
  if (tabs.length === 0) return;
  view.welcome = false;
  view.active = (index + tabs.length) % tabs.length;
  changed();
}

/** Saves the workspace a moment after the last change. */
export function changed(): void {
  if (!loaded) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const workspace: Workspace = { active: view.active, tabs: tabs.map((tab) => tab.setup()) };
    invoke("set_workspace", { workspace }).catch((error) => console.error(error));
  }, 300);
}
