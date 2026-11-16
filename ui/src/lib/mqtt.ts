// MQTT as a tab's view sees it: payloads, which the engine reports in hex,
// shown as text, JSON or hex; the lines the view gives the engine, the same
// as typed ones; and the topics heard, each with its last messages. It has
// no imports, so its tests run in Node as they are.

/** How payloads are shown: as each is best, or all as text, as hex or as JSON. */
export type PayloadFormat = "auto" | "text" | "hex" | "json";

/** A message heard: on a client, from its broker; on a broker, from a client or itself. */
export type Heard = {
  /** When it came, in ms since 1970. */
  at: number;
  topic: string;
  payload: Uint8Array;
  qos: number;
  retain: boolean;
  /** On a broker, the client id that published it; empty for the broker itself. */
  from?: string;
};

/** A topic heard: how many came, and the last few, the newest first. */
export type TopicState = { topic: string; count: number; history: Heard[] };

/** How many messages each topic keeps. */
export const HISTORY = 50;

/** Bytes from the two hex digits a byte that the engine reports them in. */
export function bytesOf(hex: string): Uint8Array {
  const pairs = hex.match(/[0-9a-f]{2}/gi) ?? [];
  return Uint8Array.from(pairs, (pair) => parseInt(pair, 16));
}

const hexOf = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(" ");

/** The bytes as UTF-8 text, or null when they are not text a person reads: bad UTF-8, or control bytes but tabs and line ends. */
function textOf(bytes: Uint8Array): string | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  // eslint-disable-next-line no-control-regex
  return /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text) ? null : text;
}

/**
 * A payload as it is shown, and what it was shown as: JSON laid out when it
 * is JSON and `pretty`, text when it is text, and hex otherwise; or as the
 * format asks, falling back to hex when it cannot be that.
 */
export function showPayload(bytes: Uint8Array, format: PayloadFormat, pretty = false): { text: string; as: "text" | "json" | "hex" } {
  if (format === "hex") return { text: hexOf(bytes), as: "hex" };
  const text = textOf(bytes);
  if (text === null) return { text: hexOf(bytes), as: "hex" };
  if (format === "text") return { text, as: "text" };
  const trimmed = text.trim();
  if (/^[{[]/.test(trimmed)) {
    try {
      const json: unknown = JSON.parse(trimmed);
      return { text: pretty ? JSON.stringify(json, null, 2) : JSON.stringify(json), as: "json" };
    } catch {
      // Not JSON after all: text.
    }
  }
  return { text, as: "text" };
}

/** A topic or filter as one word of the engine's line: in double quotes when it has a space, as the engine reads one. */
export function word(text: string): string {
  return /[\s"]/.test(text) ? `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : text;
}

/** Hex digits, such as "01 02 ff" or "0x01,0x02", as \xHH escapes; null when they are not hex. */
export function hexEscapes(text: string): string | null {
  const digits = text.replace(/0x/gi, "").replace(/[\s:,-]/g, "");
  if (digits.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(digits)) return null;
  return (digits.match(/../g) ?? []).map((byte) => `\\x${byte.toLowerCase()}`).join("");
}

/** A message to publish, as a row of the view keeps it. */
export type PublishRow = {
  topic: string;
  qos: number;
  retain: boolean;
  /** Text, with \r \n \xHH for bytes; or hex digits when `hex`. */
  payload: string;
  hex: boolean;
};

/** The line that publishes a row, as `pub -q1 -r topic payload`; or why it cannot. */
export function publishLine(row: PublishRow): { line: string; problem: string } {
  const topic = row.topic.trim();
  if (topic === "") return { line: "", problem: "The topic is needed." };
  if (/[+#]/.test(topic)) return { line: "", problem: "A topic to publish to has no + or #: those are for filters." };
  let payload = row.payload;
  if (row.hex) {
    const escaped = hexEscapes(row.payload);
    if (escaped === null) return { line: "", problem: "The payload is not hex bytes, such as 01 02 ff." };
    payload = escaped;
  }
  const flags = `-q${Math.min(2, Math.max(0, row.qos))}${row.retain ? " -r" : ""}`;
  return { line: `pub ${flags} ${word(topic)}${payload ? ` ${payload}` : ""}`, problem: "" };
}

/** The line that subscribes to a filter with a QoS. */
export function subscribeLine(filter: string, qos: number): string {
  return `sub -q${Math.min(2, Math.max(0, qos))} ${word(filter.trim())}`;
}

/** The line that leaves a filter. */
export function unsubscribeLine(filter: string): string {
  return `unsub ${word(filter.trim())}`;
}

/** Whether a topic is one a filter takes in, with + for one level and # for the rest. */
export function matches(filter: string, topic: string): boolean {
  const wanted = filter.split("/");
  const levels = topic.split("/");
  for (let index = 0; index < wanted.length; index++) {
    if (wanted[index] === "#") return index > 0 || !topic.startsWith("$");
    if (index >= levels.length) return false;
    if (wanted[index] === "+") {
      if (index === 0 && topic.startsWith("$")) return false;
      continue;
    }
    if (wanted[index] !== levels[index]) return false;
  }
  return wanted.length === levels.length;
}

/** Keeps a message under its topic, the newest first, with at most `max` of each topic. */
export function keep(topics: Map<string, TopicState>, heard: Heard, max = HISTORY): void {
  const known = topics.get(heard.topic);
  if (known) {
    known.count++;
    known.history.unshift(heard);
    if (known.history.length > max) known.history.length = max;
  } else {
    topics.set(heard.topic, { topic: heard.topic, count: 1, history: [heard] });
  }
}

/** The topics in name order, those with every word of `find` in their name or their last payload. */
export function listed(topics: Map<string, TopicState>, find: string): TopicState[] {
  const words = find.toLowerCase().split(/\s+/).filter(Boolean);
  const all = [...topics.values()].sort((a, b) => a.topic.localeCompare(b.topic));
  if (words.length === 0) return all;
  return all.filter((state) => {
    const last = textOf(state.history[0].payload) ?? "";
    const text = `${state.topic} ${last}`.toLowerCase();
    return words.every((each) => text.includes(each));
  });
}
