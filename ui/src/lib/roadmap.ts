// Where netNIMA is going, phase by phase, as docs/PLAN.md lists it, and
// where to read about it. Menu items and tabs that a later phase brings say
// which one. It has no imports, so its tests run in Node as they are.

export type Phase = { number: number; name: string };

/** The phase being built now. Everything in a later one is greyed out or says when it comes. */
export const CURRENT_PHASE = 2;

export const PHASES: Phase[] = [
  { number: 0, name: "Skeleton" },
  { number: 1, name: "UDP, TCP and Telnet" },
  { number: 2, name: "TLS and DTLS in Rust" },
  { number: 3, name: "TLS for old and small devices" },
  { number: 4, name: "MQTT and CoAP" },
  { number: 5, name: "HTTP and WebSocket" },
  { number: 6, name: "Modbus TCP and MCUmgr" },
  { number: 7, name: "LwM2M" },
  { number: 8, name: "Services for boards" },
  { number: 9, name: "Finding and measuring" },
  { number: 10, name: "Sniffer" },
  { number: 11, name: "Reading the traffic" },
  { number: 12, name: "1.0" },
];

/** A phase's name, such as "MQTT and CoAP"; "" for a number that is not a phase. */
export function phaseName(number: number): string {
  return PHASES.find((phase) => phase.number === number)?.name ?? "";
}

/** Whether a phase is built, so what it brings can be used. */
export function isBuilt(number: number): boolean {
  return number <= CURRENT_PHASE;
}

/** The last phase, the one that brings 1.0. */
export const LAST_PHASE = PHASES[PHASES.length - 1].number;

export const GITHUB = "https://github.com/nimaltd/netNIMA";
export const PLAN = `${GITHUB}/blob/main/docs/PLAN.md`;
