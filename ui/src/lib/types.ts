// The types the views share, as terNIMA has them: how a terminal sends and
// shows, the lines the Lines view lists, and how the hex and plot views draw.
// It has no imports, so the modules the tests load can use it in Node.

export type LineEnding = "cr" | "lf" | "crlf";

export type TerminalOptions = {
  enter: LineEnding;
  local_echo: boolean;
  lf_is_newline: boolean;
  /** Starts a new line when data comes after a pause this long, in ms; 0 never does. */
  pause_ms: number;
};

export const DEFAULT_TERMINAL: TerminalOptions = { enter: "crlf", local_echo: true, lf_is_newline: true, pause_ms: 0 };

/** What a tab shows: the terminal, every byte in hex, every line in a list, the numbers in a chart, or its protocol's own view. */
export type View = "terminal" | "hex" | "lines" | "plot" | "modbus" | "mqtt" | "coap" | "http" | "lwm2m" | "mcumgr";

/** A Zephyr log level. */
export type Level = "err" | "wrn" | "inf" | "dbg";

/** A received line, with a Zephyr log line read into its parts: the same fields as `Line` in lines.rs. */
export type LogLine = {
  /** The whole line, without colors and control characters. */
  text: string;
  /** The time as the log wrote it, such as "00:00:01.234,567". */
  time: string | null;
  level: Level | null;
  module: string | null;
  /** What follows the module; the whole text for a line that is not a log line. */
  message: string;
};

/** What the Lines view leaves out. */
export type LinesView = {
  hidden_levels: Level[];
  hidden_modules: string[];
  /** Shows the lines that are not log lines. */
  others: boolean;
  /** Shows the lines this end sent too, not only the ones received. */
  sent?: boolean;
};

export const DEFAULT_LINES_VIEW: LinesView = { hidden_levels: [], hidden_modules: [], others: true, sent: true };

/** What the Plot view draws: values over time, one against the others, how often each comes, or their frequencies. */
export type Chart = "time" | "xy" | "histogram" | "fft";

/** A scope's trigger on the time chart: the time around the last crossing of a level, the crossing in the middle. */
export type Trigger = {
  on: boolean;
  /** The series it watches; empty for the first. */
  series: string;
  level: number;
  edge: "rising" | "falling" | "both";
  /** Stops at the first crossing, until it is armed again. */
  single: boolean;
};

/** How the Plot view reads and shows numbers. */
export type PlotView = {
  /** "auto" reads JSON, named values and plain numbers; "regex" uses `regex`. */
  mode: "auto" | "regex";
  regex: string;
  /** The time shown while it follows the newest values, in ms; 0 shows them all. */
  window_ms: number;
  /** The series left out of the chart. */
  hidden: string[];
  /** The series on the time chart's right axis, with a scale of their own. */
  right: string[];
  chart: Chart;
  /** The series along the XY chart's x axis; empty for the first. */
  x_series: string;
  /** The histogram's bins; 0 picks them from the values. */
  bins: number;
  /** The series the histogram counts; empty for the first. */
  hist_series: string;
  fft_window: "hann" | "hamming" | "blackman" | "rect";
  /** The FFT in dB rather than as amplitudes. */
  fft_db: boolean;
  /** Samples a second for the FFT; 0 measures it from when the lines came. */
  fft_rate: number;
  trigger: Trigger;
  /** Keeps the help over the chart while values come too; it shows on its own while there are none. */
  help: boolean;
  /** Marks each sample of the time chart with a dot, where there is room for it. */
  dots: boolean;
};

export const DEFAULT_TRIGGER: Trigger = { on: false, series: "", level: 0, edge: "rising", single: false };

export const DEFAULT_PLOT_VIEW: PlotView = {
  mode: "auto",
  regex: "",
  window_ms: 30_000,
  hidden: [],
  right: [],
  chart: "time",
  x_series: "",
  bins: 0,
  hist_series: "",
  fft_window: "hann",
  fft_db: true,
  fft_rate: 0,
  trigger: DEFAULT_TRIGGER,
  help: false,
  dots: true,
};

/** How the hex view breaks its lines, besides the tab's pause. It only changes what is shown. */
export type HexView = {
  /** Bytes on a full line: 8, 16 or 32. */
  width: number;
  /** A byte that ends its line, such as 0x0A for LF, or null for none. */
  end_byte?: number | null;
};

export const DEFAULT_HEX_VIEW: HexView = { width: 16, end_byte: null };

/** The recording a replay tab plays, and how fast. */
export type ReplaySetup = { path: string; speed: number };

export const DEFAULT_REPLAY: ReplaySetup = { path: "", speed: 1 };

/** Where a recording being played is, in seconds. */
export type PlayState = { position: number; length: number; playing: boolean; speed: number };

/** A line sent from the send box, kept so ↑ brings it back. */
export type SentLine = { text: string; hex?: boolean };
