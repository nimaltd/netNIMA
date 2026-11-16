// An MQTT tab's view: what its engine reports, kept for the view to show,
// and what the view asks of the engine, as the lines a person would type.
// A client's messages to publish and its subscriptions, made again each
// time it connects; a broker's clients and retained messages; and every
// topic heard, with its last messages.

import {
  bytesOf,
  keep,
  publishLine,
  subscribeLine,
  unsubscribeLine,
  word,
  type PayloadFormat,
  type PublishRow,
  type TopicState,
} from "./mqtt";

/** A subscription a client makes each time it connects. */
export type SubscriptionRow = { filter: string; qos: number };

/** How an MQTT tab's view publishes, subscribes and shows, as workspace.toml keeps it. */
export type MqttSetup = {
  /** The messages to publish, each with its Send. */
  publishes: PublishRow[];
  /** A client's subscriptions, made again each time it connects. */
  subscriptions: SubscriptionRow[];
  format: PayloadFormat;
};

export const DEFAULT_MQTT: MqttSetup = {
  publishes: [{ topic: "sensors/temp", qos: 0, retain: false, payload: "21.5", hex: false }],
  subscriptions: [{ filter: "#", qos: 0 }],
  format: "auto",
};

/** What a publish or a subscription got last. */
export type Outcome = { at: number; ok: boolean; text: string };

/** A client of a broker, as the broker reported it. */
export type BrokerClient = {
  peer: number;
  clientId: string;
  address: string;
  version: string;
  keepAlive: number;
  will: string | null;
  /** Its subscriptions, filter to QoS. */
  filters: Record<string, number>;
};

/** What the tab gives its view. */
export type MqttHost = {
  /** Gives the engine a line, as if typed; rejects with the reason when it cannot. */
  command(line: string): Promise<void>;
  setup(): MqttSetup;
  changed(): void;
  connected(): boolean;
  /** A broker's tab rather than a client's. */
  broker(): boolean;
};

const text = (value: unknown) => (typeof value === "string" ? value : "");
const number = (value: unknown) => (typeof value === "number" ? value : 0);

export class MqttSession {
  /** Whether the broker took the client: null until it says. */
  accepted: boolean | null = $state(null);
  /** Why the broker said no. */
  reason = $state("");
  /** Each subscription's answer from the broker, by filter. */
  granted: Record<string, Outcome> = $state({});
  /** Each publish row's last outcome, by its place. */
  results: (Outcome | null)[] = $state([]);
  /** The topics heard, by name. Plain, as there can be many: `version` changes with them. */
  readonly topics = new Map<string, TopicState>();
  version = $state(0);
  /** How many messages came in all. */
  heard = $state(0);
  /** The topic whose messages are shown. */
  picked: string | null = $state(null);
  /** A broker's clients, by peer, and its retained messages, by topic. */
  clients: Record<number, BrokerClient> = $state({});
  retained: Record<string, { payload: Uint8Array; qos: number }> = $state({});

  private readonly host: MqttHost;
  /** The rows published and not yet reported sent, in order; and those waiting for their PUBACK or PUBCOMP, by packet id. */
  private sending: number[] = [];
  private delivering = new Map<number, number>();

  constructor(host: MqttHost) {
    this.host = host;
  }

  /** What the engine reported, as `{ type, ... }`. */
  report(report: Record<string, unknown>): void {
    const at = Date.now();
    switch (report.type) {
      case "connack":
        this.accepted = report.accepted === true;
        this.reason = text(report.reason);
        this.sending = [];
        this.delivering.clear();
        if (this.accepted) void this.subscribeAll();
        return;
      case "closed":
        this.closed();
        return;
      case "message": {
        keep(this.topics, {
          at,
          topic: text(report.topic),
          payload: bytesOf(text(report.payload)),
          qos: number(report.qos),
          retain: report.retain === true,
          from: typeof report.from === "string" ? report.from : undefined,
        });
        this.heard++;
        this.version++;
        return;
      }
      case "suback":
        for (const answer of (report.filters as Record<string, unknown>[] | undefined) ?? []) {
          const granted = answer.granted;
          // A broker may grant less than was asked.
          this.granted[text(answer.filter)] =
            typeof granted === "number"
              ? { at, ok: true, text: granted === number(answer.qos) ? "granted" : `granted QoS ${granted} only` }
              : { at, ok: false, text: `refused: ${text(answer.reason)}` };
        }
        return;
      case "unsuback":
        for (const filter of (report.filters as string[] | undefined) ?? []) delete this.granted[filter];
        return;
      case "sent": {
        const row = this.sending.shift();
        if (row === undefined) return;
        const qos = number(report.qos);
        if (qos === 0) {
          this.results[row] = { at, ok: true, text: "sent" };
        } else {
          this.results[row] = { at, ok: true, text: `sent, waiting for ${qos === 1 ? "PUBACK" : "PUBCOMP"}` };
          this.delivering.set(number(report.id), row);
        }
        return;
      }
      case "delivered": {
        const id = number(report.id);
        const row = this.delivering.get(id);
        if (row === undefined) return;
        this.delivering.delete(id);
        this.results[row] = { at, ok: true, text: `delivered in ${Number(number(report.ms).toFixed(1))} ms` };
        return;
      }
      case "client":
        this.clients[number(report.peer)] = {
          peer: number(report.peer),
          clientId: text(report.client_id),
          address: text(report.address),
          version: text(report.version),
          keepAlive: number(report.keep_alive),
          will: typeof report.will === "string" ? report.will : null,
          filters: {},
        };
        return;
      case "gone":
        delete this.clients[number(report.peer)];
        return;
      case "subscribed": {
        const client = this.clients[number(report.peer)];
        if (!client) return;
        for (const each of (report.filters as Record<string, unknown>[] | undefined) ?? []) {
          client.filters[text(each.filter)] = number(each.qos);
        }
        return;
      }
      case "unsubscribed": {
        const client = this.clients[number(report.peer)];
        if (!client) return;
        for (const filter of (report.filters as string[] | undefined) ?? []) delete client.filters[filter];
        return;
      }
      case "retained": {
        const topic = text(report.topic);
        if (typeof report.payload === "string") {
          this.retained[topic] = { payload: bytesOf(report.payload), qos: number(report.qos) };
        } else {
          delete this.retained[topic];
        }
        return;
      }
    }
  }

  /** The connection ended, or the tab stopped: what the broker said holds no more. */
  closed(): void {
    this.accepted = null;
    this.reason = "";
    this.granted = {};
    this.sending = [];
    this.delivering.clear();
    this.clients = {};
  }

  /** Gives the engine a line, and says why when it cannot. */
  private async run(line: string): Promise<string | null> {
    try {
      await this.host.command(line);
      return null;
    } catch (problem) {
      return String(problem);
    }
  }

  /** Publishes a row of the list. */
  async publish(index: number): Promise<void> {
    const row = this.host.setup().publishes[index];
    if (!row) return;
    const { line, problem } = publishLine(row);
    const at = Date.now();
    if (problem) {
      this.results[index] = { at, ok: false, text: problem };
      return;
    }
    if (!this.host.connected()) {
      this.results[index] = { at, ok: false, text: "Not connected." };
      return;
    }
    // A client hears back when it is sent; a broker publishes it at once.
    if (!this.host.broker()) this.sending.push(index);
    const failed = await this.run(line);
    if (failed) {
      this.sending = this.sending.filter((each) => each !== index);
      this.results[index] = { at, ok: false, text: failed };
    } else if (this.host.broker()) {
      this.results[index] = { at, ok: true, text: "published" };
    }
  }

  /** Subscribes to a filter: the broker's answer shows beside it. */
  async subscribe(filter: string, qos: number): Promise<void> {
    if (!filter.trim()) return;
    this.granted[filter.trim()] = { at: Date.now(), ok: true, text: "asked" };
    const failed = await this.run(subscribeLine(filter, qos));
    if (failed) this.granted[filter.trim()] = { at: Date.now(), ok: false, text: failed };
  }

  async unsubscribe(filter: string): Promise<void> {
    await this.run(unsubscribeLine(filter));
  }

  /** Makes the list's subscriptions, as the client connects. */
  private async subscribeAll(): Promise<void> {
    for (const { filter, qos } of this.host.setup().subscriptions) {
      if (filter.trim()) await this.subscribe(filter, qos);
    }
  }

  /** A broker's commands: forget a retained message, or close a client's connection. */
  async clearRetained(topic: string): Promise<void> {
    await this.run(`clear ${word(topic)}`);
  }

  async kick(peer: number): Promise<void> {
    await this.run(`kick ${peer}`);
  }

  /** Forgets the topics heard. */
  clearTopics(): void {
    this.topics.clear();
    this.heard = 0;
    this.picked = null;
    this.version++;
  }
}
