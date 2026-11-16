// CoAP and HTTP as their tabs' views see them: a request in each row, the
// line that sends it, as a person would type it; a server's resources and
// routes, and the lines that change them; and the link format a CoAP
// server lists its resources in. It has no imports, so its tests run in
// Node as they are.

/** Hex digits, such as "01 02 ff", as \xHH escapes; null when they are not hex. */
export function hexEscapes(text: string): string | null {
  const digits = text.replace(/0x/gi, "").replace(/[\s:,-]/g, "");
  if (digits.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(digits)) return null;
  return (digits.match(/../g) ?? []).map((byte) => `\\x${byte.toLowerCase()}`).join("");
}

/** A word of the engine's line: in double quotes when it has a space. */
function word(text: string): string {
  return /[\s"]/.test(text) ? `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : text;
}

/** A payload as the engine takes it: text as written, hex digits as escapes; null when they are not hex. */
function payloadOf(text: string, hex: boolean): string | null {
  return hex ? hexEscapes(text) : text;
}

export const COAP_METHODS = ["GET", "OBSERVE", "POST", "PUT", "DELETE"] as const;
/** Content formats by the names the engine knows; empty for none. */
export const COAP_FORMATS = ["", "text", "json", "cbor", "link", "xml", "octet", "senml"] as const;

/** A CoAP request, as a row of the view keeps it. */
export type CoapRow = {
  method: (typeof COAP_METHODS)[number];
  path: string;
  /** The payload's format, for POST and PUT. */
  format: string;
  /** The format wanted back; empty for any. */
  accept: string;
  /** As NON, not sent again, rather than CON. */
  non: boolean;
  payload: string;
  hex: boolean;
};

export const DEFAULT_COAP_ROW: CoapRow = { method: "GET", path: "/sensors/temp", format: "", accept: "", non: false, payload: "", hex: false };

/** The line that sends a CoAP row, such as `put -f json /led {"on":true}`; or why it cannot. */
export function coapLine(row: CoapRow): { line: string; problem: string } {
  const path = row.path.trim();
  if (path === "") return { line: "", problem: "The path is needed, such as /sensors/temp." };
  const words = [row.method.toLowerCase()];
  if (row.non) words.push("-n");
  if (row.accept) words.push(`-a ${row.accept}`);
  const withBody = row.method === "POST" || row.method === "PUT";
  if (withBody && row.format) words.push(`-f ${row.format}`);
  words.push(word(path.startsWith("/") ? path : `/${path}`));
  if (withBody && row.payload !== "") {
    const payload = payloadOf(row.payload, row.hex);
    if (payload === null) return { line: "", problem: "The payload is not hex bytes, such as 01 02 ff." };
    words.push(payload);
  }
  return { line: words.join(" "), problem: "" };
}

/** The line that sets a CoAP server's resource, made if new, and tells its observers. */
export function setLine(path: string, value: string): string {
  return `set ${word(path.trim())} ${value}`.trimEnd();
}

/** A resource from a CoAP server's /.well-known/core: its path, and what is said of it. */
export type Link = { path: string; attributes: string };

/** The resources in link format, as `</sensors/temp>;ct=0;obs,</led>`. */
export function parseLinks(text: string): Link[] {
  const links: Link[] = [];
  for (const found of text.matchAll(/<([^>]*)>([^,]*)/g)) {
    links.push({ path: found[1], attributes: found[2].replace(/^;/, "") });
  }
  return links;
}

/** A CoAP code's class: 2 for success, 4 for the client's mistakes, 5 for the server's. */
export function codeClass(code: string): number {
  return Number(code.split(".")[0]) || 0;
}

export const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const;

/** An HTTP request, as a row of the view keeps it. */
export type HttpRow = { method: (typeof HTTP_METHODS)[number]; path: string; body: string };

export const DEFAULT_HTTP_ROW: HttpRow = { method: "GET", path: "/api/status", body: "" };

/** The line that sends an HTTP row, such as `post /api/led {"on":true}`; or why it cannot. */
export function httpLine(row: HttpRow): { line: string; problem: string } {
  const path = row.path.trim();
  if (path === "") return { line: "", problem: "The path is needed, such as /api/status." };
  const body = row.method === "GET" || row.method === "HEAD" ? "" : row.body;
  return { line: `${row.method.toLowerCase()} ${word(path)}${body ? ` ${body}` : ""}`, problem: "" };
}

/** The line that sets a header every request has, or drops it with an empty value. */
export function headerLine(name: string, value: string): string {
  return `header ${name.trim()}: ${value.trim()}`.trimEnd();
}

/** An HTTP server's route, as the view adds it. */
export type RouteRow = { method: string; path: string; status: number; body: string };

/** The line that makes a route, such as `route GET /api/temp 200 {"t":21.5}`. */
export function routeLine(route: RouteRow): { line: string; problem: string } {
  const path = route.path.trim();
  if (path === "") return { line: "", problem: "The path is needed, such as /api/temp." };
  if (!Number.isInteger(route.status) || route.status < 100 || route.status > 599) {
    return { line: "", problem: "The status is a number from 100 to 599." };
  }
  const where = path.startsWith("/") ? path : `/${path}`;
  return { line: `route ${route.method.toUpperCase()} ${word(where)} ${route.status}${route.body ? ` ${route.body}` : ""}`, problem: "" };
}

/** An HTTP status's class: 2 for success, 3 for elsewhere, 4 and 5 for mistakes. */
export function statusClass(status: number): number {
  return Math.floor(status / 100);
}
