// What a protocol tab takes in its send box, from its engine's help, and
// what the send box offers from it while a line is typed. It has no
// imports, so its tests run in Node as they are.

/** One command, from a line of the engine's help. */
export type CommandHelp = {
  /** How it is typed: "pub [-q1] [-r] <topic> <payload>"; "<text>" stands for any line. */
  usage: string;
  /** What it does. */
  what: string;
};

/** What a kind of tab takes, as protocol_help gives it: none for a plain socket tab. */
export type ProtocolHelp = {
  commands: CommandHelp[];
  /** What help says besides, a sentence each. */
  notes: string[];
};

export const NO_HELP: ProtocolHelp = { commands: [], notes: [] };

/**
 * The word a command is typed with: "pub", "/close"; null for a line that
 * stands for any text, such as "<text>" or "[-e|-a] <message>".
 */
export function wordOf(command: CommandHelp): string | null {
  const word = command.usage.trim().split(/\s+/)[0] ?? "";
  return word === "" || /^[<[]/.test(word) ? null : word;
}

/** The first word of a line, and whether more comes after it. */
function firstWord(line: string): { word: string; more: boolean } {
  const start = line.trimStart();
  const space = start.search(/\s/);
  return space < 0 ? { word: start, more: false } : { word: start.slice(0, space), more: true };
}

/** While a line's first word is typed: the commands it is the start of. */
export function matching(commands: CommandHelp[], line: string): CommandHelp[] {
  const { word, more } = firstWord(line);
  if (more || word === "") return [];
  const typed = word.toLowerCase();
  return commands.filter((command) => wordOf(command)?.toLowerCase().startsWith(typed));
}

/** Once more is typed after a command's word: that command, to show how it goes on. */
export function typing(commands: CommandHelp[], line: string): CommandHelp[] {
  const { word, more } = firstWord(line);
  if (!more) return [];
  const typed = word.toLowerCase();
  return commands.filter((command) => wordOf(command)?.toLowerCase() === typed);
}

/**
 * What a command puts in the line when it is picked: the words it starts
 * with, and a space when it takes more: "pub ", "ping", "level all".
 */
export function completed(command: CommandHelp): string {
  const words = command.usage.trim().split(/\s+/);
  const fixed = words.findIndex((word) => /^[<[]/.test(word) || word.includes("|"));
  const head = (fixed < 0 ? words : words.slice(0, Math.max(fixed, 1))).join(" ");
  return fixed < 0 ? head : `${head} `;
}

/**
 * The line once a command is picked for it. A command being typed, or one
 * typed already, gives way to it, with what came after it kept; other text
 * stays, after the command.
 */
export function withCommand(line: string, command: CommandHelp, commands: CommandHelp[]): string {
  const head = completed(command);
  const start = line.trim();
  if (start === "") return head;
  const { word, more } = firstWord(start);
  const rest = more ? start.slice(word.length).trimStart() : "";
  const known = commands.some((each) => wordOf(each)?.toLowerCase() === word.toLowerCase());
  const kept = known || !more ? rest : start;
  return kept === "" ? head : `${head.trimEnd()} ${kept}`;
}
