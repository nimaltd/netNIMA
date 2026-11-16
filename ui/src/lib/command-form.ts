// A protocol's command as a form in the send box: its usage, such as
// "pub [-q0|-q1|-q2] [-r] <topic> <payload>", read into the fields the form
// shows, and the line those fields make. It has no imports, so its tests
// run in Node as they are.

/** A value to fill in, such as <topic>, [count] or [-a json]. */
export type ValuePart = {
  kind: "value";
  /** What it is: "topic". */
  name: string;
  /** Typed before the value, as -a in [-a json]; empty for none. */
  flag: string;
  /** Whether it may stay empty: it is in [ ]. */
  optional: boolean;
  /** Whether it takes several words, as <filter>... does. */
  many: boolean;
  /** Typed right after the value, as the colon of <Name>: in a header. */
  suffix: string;
  /** Data, which can be written as text or as hex: a payload, a message, a text or a body. */
  data: boolean;
};

/** A piece of a command's usage, as the form shows it. */
export type Part =
  /** Typed as it is: the command's word, such as "pub", or one after it, such as "uri". */
  | { kind: "word"; text: string }
  | ValuePart
  /** A flag that is there or not, such as [-r]. */
  | { kind: "switch"; flag: string }
  /** One of some words, such as on|off; or [-q0|-q1|-q2], where none is a choice too. */
  | { kind: "choice"; options: string[]; optional: boolean };

/** The names of values that are data, which can be written in hex. */
const DATA = new Set(["payload", "message", "text", "body"]);

const FLAG = /^-[A-Za-z][\w-]*$/;

/** A usage's pieces at the top: spaces inside < > and [ ] do not split them. */
function pieces(usage: string): string[] {
  const found: string[] = [];
  let depth = 0;
  let current = "";
  for (const char of usage.trim()) {
    if (char === "<" || char === "[") depth += 1;
    if (char === ">" || char === "]") depth = Math.max(0, depth - 1);
    if (depth === 0 && /\s/.test(char)) {
      if (current) found.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  if (current) found.push(current);
  return found;
}

/** Plain words, one of which is typed: on|off, 1|2c, -q0|-q1|-q2. */
function isChoice(piece: string): boolean {
  return piece.includes("|") && !/[<>[\]]/.test(piece);
}

function valueOf(name: string, optional: boolean): ValuePart {
  const many = name.endsWith("...");
  const bare = many ? name.slice(0, -3) : name;
  return { kind: "value", name: bare, flag: "", optional, many, suffix: "", data: DATA.has(bare) };
}

function partsOfPiece(piece: string, optional: boolean): Part[] {
  if (piece.startsWith("[")) {
    const inner = piece.slice(1, piece.lastIndexOf("]")).trim();
    const inside = pieces(inner);
    // [-r]: a flag that is there or not.
    if (inside.length === 1 && FLAG.test(inside[0])) return [{ kind: "switch", flag: inside[0] }];
    // [-q0|-q1|-q2]: one of some words, or none.
    if (inside.length === 1 && isChoice(inside[0])) {
      return [{ kind: "choice", options: inside[0].split("|"), optional: true }];
    }
    // [-a json], [-b 10M]: a flag with a value after it, such as the one shown.
    if (inside.length === 2 && FLAG.test(inside[0])) {
      const [after] = partsOfPiece(inside[1], true);
      const value = after?.kind === "value" ? after : valueOf(inside[1], true);
      return [{ ...value, flag: inside[0] }];
    }
    // [count], [saved as], [name...]: a value named in plain words.
    if (!inner.includes("<")) return [valueOf(inner, true)];
    // [<filter>...], [<oid> <type> <value>]: values that may stay empty.
    return inside.flatMap((each) => partsOfPiece(each, true));
  }
  if (piece.startsWith("<")) {
    const close = piece.indexOf(">");
    const name = piece.slice(1, close);
    const after = piece.slice(close + 1);
    // <code>|off: a value, or the word after the bar.
    if (after.startsWith("|")) return [valueOf(`${name}${after}`, optional)];
    const many = after.endsWith("...");
    return [{ ...valueOf(name, optional), many, suffix: many ? after.slice(0, -3) : after }];
  }
  if (isChoice(piece)) return [{ kind: "choice", options: piece.split("|"), optional }];
  return [{ kind: "word", text: piece }];
}

/** The parts of a command's usage, in the order they are typed. */
export function partsOf(usage: string): Part[] {
  return pieces(usage).flatMap((piece) => partsOfPiece(piece, false));
}

/** What the fields hold at first: nothing, but a choice that must be made takes its first word. */
export function startingValues(parts: Part[]): string[] {
  return parts.map((part) => (part.kind === "choice" && !part.optional ? part.options[0] : ""));
}

/** Hex bytes, such as "01 02 ff", "0x01,0x02" or "01:02:FF", as \xHH escapes; null when they are not hex. */
export function hexEscapes(text: string): string | null {
  const digits = text.replace(/0x/gi, "").replace(/[\s:,-]/g, "");
  if (digits.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(digits)) return null;
  return (digits.match(/../g) ?? []).map((byte) => `\\x${byte.toLowerCase()}`).join("");
}

/** A word with spaces in it, in double quotes, as the engine reads one. */
function quoted(text: string): string {
  return /\s/.test(text) ? `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : text;
}

/**
 * The line the form makes from what its fields hold, with `values[i]` for
 * `parts[i]`: "on" for a switch that is on. Data written in hex goes as
 * \xHH escapes, which the engine turns into its bytes. `problem` says why
 * there is no line yet.
 */
export function lineOf(parts: Part[], values: string[], hex: boolean): { line: string; problem: string } {
  const words: string[] = [];
  const last = parts.length - 1;
  for (const [index, part] of parts.entries()) {
    const value = (values[index] ?? "").trim();
    if (part.kind === "word") {
      words.push(part.text);
    } else if (part.kind === "switch") {
      if (value === "on") words.push(part.flag);
    } else if (part.kind === "choice") {
      if (value) words.push(value);
    } else if (value === "") {
      if (!part.optional) return { line: "", problem: `The ${part.name} is needed.` };
      // A value in its place, with none before it, would be read as this one.
      const later = parts.slice(index + 1).find(
        (other, at) => other.kind === "value" && !other.flag && (values[index + 1 + at] ?? "").trim() !== "",
      );
      if (!part.flag && later?.kind === "value") {
        return { line: "", problem: `Fill in the ${part.name} too, or leave the ${later.name} empty.` };
      }
    } else {
      let text = value;
      if (part.data && hex) {
        const escaped = hexEscapes(value);
        if (escaped === null) return { line: "", problem: `The ${part.name} is not hex bytes, such as 01 02 ff.` };
        text = escaped;
      } else if (!part.data && !part.many && index !== last) {
        text = quoted(value);
      }
      words.push(`${part.flag ? `${part.flag} ` : ""}${text}${part.suffix}`);
    }
  }
  return { line: words.join(" "), problem: "" };
}
