// The sockets of netnima-core as the UI sees them: each kind's settings, what
// a session tells, and the frames its data comes in. It has no imports, so
// its tests run in Node as they are.

/** A multicast group a UDP tab joins: the same fields as `Multicast` in config.rs. */
export type Multicast = {
  group: string;
  /** For an IPv4 group, an address of the interface to join it on; empty for the OS's choice. */
  interface: string;
  /** For an IPv6 group, the number of the interface; 0 for the OS's choice. */
  interface_index: number;
  loopback: boolean;
};

/** The same fields as `UdpConfig` in config.rs. */
export type UdpConfig = {
  local_address: string;
  local_port: number;
  remote_host: string;
  remote_port: number;
  broadcast: boolean;
  multicast?: Multicast | null;
  ttl: number;
  reuse_address: boolean;
};

/** How a TLS client checks the server's certificate: the same as `Verify` in tls.rs. */
export type Verify = "system" | "file" | "none";
/** The TLS versions a tab speaks: the same as `Versions` in tls.rs. */
/** The TLS versions a tab speaks: 1.0 and 1.1 go through OpenSSL. The same as `Versions` in tls.rs. */
export type Versions = "both" | "tls12" | "tls13" | "all" | "tls10" | "tls11";
/** The TLS engine a tab uses: the same as `Engine` in tls.rs. */
export type Engine = "auto" | "rustls" | "openssl";
/** Whether a TLS server asks for client certificates: the same as `ClientAuth` in tls.rs. */
export type ClientAuth = "none" | "optional" | "required" | "any";

/** The same fields as `TlsClientOptions` in tls.rs. */
export type TlsClientOptions = {
  verify: Verify;
  ca_file: string;
  check_name: boolean;
  server_name: string;
  no_sni: boolean;
  cert_file: string;
  key_file: string;
  alpn: string;
  versions: Versions;
  key_log: string;
  engine: Engine;
  psk: boolean;
  psk_identity: string;
  psk_key: string;
  ciphers: string;
};

/** The same fields as `TlsServerOptions` in tls.rs. */
export type TlsServerOptions = {
  cert_file: string;
  key_file: string;
  client_auth: ClientAuth;
  ca_file: string;
  alpn: string;
  versions: Versions;
  key_log: string;
  engine: Engine;
  psk: boolean;
  psk_identity: string;
  psk_key: string;
  ciphers: string;
};

/** The DTLS versions a tab speaks: 1.0 goes through OpenSSL. The same as `DtlsVersion` in dtls.rs. */
export type DtlsVersion = "auto" | "dtls12" | "dtls13" | "dtls10" | "all";

/** The same fields as `DtlsOptions` in dtls.rs. */
export type DtlsOptions = {
  version: DtlsVersion;
  /** "rustls" stands for the Rust engine, dimpl, as in TLS tabs. */
  engine: Engine;
  ciphers: string;
  psk: boolean;
  psk_identity: string;
  psk_key: string;
  cert_file: string;
  key_file: string;
  verify: Verify;
  ca_file: string;
  check_name: boolean;
  server_name: string;
  client_auth: boolean;
  cookie: boolean;
};

/** Whether a DTLS tab's settings make it use OpenSSL: as `over_openssl` in dtls.rs. */
export function dtlsOverOpenssl(options: Pick<DtlsOptions, "engine" | "version" | "ciphers">): boolean {
  if (options.engine !== "auto") return options.engine === "openssl";
  return options.version === "dtls10" || options.version === "all" || options.ciphers.trim() !== "";
}

export const DEFAULT_DTLS: DtlsOptions = {
  version: "auto",
  engine: "auto",
  ciphers: "",
  psk: false,
  psk_identity: "netnima",
  psk_key: "000102030405060708090a0b0c0d0e0f",
  cert_file: "",
  key_file: "",
  verify: "none",
  ca_file: "",
  check_name: true,
  server_name: "",
  client_auth: false,
  cookie: true,
};

/** The same fields as `TcpClientConfig` in config.rs. */
export type TcpClientConfig = {
  host: string;
  port: number;
  local_port: number;
  telnet: boolean;
  no_delay: boolean;
  keep_alive: number;
  reconnect: boolean;
  tls?: TlsClientOptions | null;
};

/** The same fields as `TcpServerConfig` in config.rs. */
export type TcpServerConfig = {
  address: string;
  port: number;
  telnet: boolean;
  no_delay: boolean;
  keep_alive: number;
  max_clients: number;
  tls?: TlsServerOptions | null;
};

/** A certificate as people read it: the same as `CertInfo` in tls.rs. */
export type CertInfo = {
  subject: string;
  issuer: string;
  names: string[];
  not_before: string;
  not_after: string;
  key: string;
  sha256: string;
};

/** What the two ends of a TLS connection agreed: the same as `Agreed` in tls.rs. */
export type Agreed = {
  version: string;
  suite: string;
  group: string;
  alpn: string;
  name: string;
  resumed: boolean;
  chain: CertInfo[];
};

export const DEFAULT_TLS_CLIENT: TlsClientOptions = {
  verify: "system",
  ca_file: "",
  check_name: true,
  server_name: "",
  no_sni: false,
  cert_file: "",
  key_file: "",
  alpn: "",
  versions: "both",
  key_log: "",
  engine: "auto",
  psk: false,
  psk_identity: "netnima",
  psk_key: "000102030405060708090a0b0c0d0e0f",
  ciphers: "",
};

export const DEFAULT_TLS_SERVER: TlsServerOptions = {
  cert_file: "",
  key_file: "",
  client_auth: "none",
  ca_file: "",
  alpn: "",
  versions: "both",
  key_log: "",
  engine: "auto",
  psk: false,
  psk_identity: "netnima",
  psk_key: "000102030405060708090a0b0c0d0e0f",
  ciphers: "",
};

export const DEFAULT_UDP: UdpConfig = {
  local_address: "",
  local_port: 0,
  remote_host: "",
  remote_port: 0,
  broadcast: false,
  multicast: null,
  ttl: 64,
  reuse_address: false,
};

export const DEFAULT_TCP_CLIENT: TcpClientConfig = {
  host: "localhost",
  port: 0,
  local_port: 0,
  telnet: false,
  no_delay: true,
  keep_alive: 0,
  reconnect: true,
};

export const DEFAULT_TCP_SERVER: TcpServerConfig = {
  address: "",
  port: 0,
  telnet: false,
  no_delay: true,
  keep_alive: 0,
  max_clients: 0,
};

/** Where a session is: the same as `NetState` in net/mod.rs. */
export type NetState =
  | { state: "waiting"; problem: string | null }
  | { state: "connected"; address: string; local: string }
  | { state: "ended"; problem: string | null }
  | { state: "listening"; local: string };

/** Another end a session talks to. */
export type Peer = { id: number; address: string };

/** Who a write goes to: the same as `Target` in net/mod.rs. */
export type Target = { to: "default" } | { to: "all" } | { to: "peer"; peer: number };

/** What a session tells, apart from its data: the same as `SessionEvent` in sessions.rs. */
export type SessionEvent =
  | ({ kind: "state" } & NetState)
  | ({ kind: "peer_joined" } & Peer)
  | { kind: "peer_left"; peer: number }
  | { kind: "problem"; problem: string }
  | { kind: "secure"; peer: number; agreed: Agreed }
  | { kind: "text_lines"; peer: number; lines: import("./types").LogLine[]; at: number; sent: boolean }
  | { kind: "restarted" }
  | { kind: "replay_state"; position: number; length: number; playing: boolean; speed: number }
  | { kind: "recording_stopped"; problem: string }
  | { kind: "log_stopped"; problem: string }
  /** What a protocol's engine tells its view, such as an MQTT message that came. */
  | { kind: "report"; report: Record<string, unknown> };

/** One piece of data from a session's data channel. */
export type Frame = {
  /** Whether this end sent it, as a recording played back has. */
  sent: boolean;
  peer: number;
  /** When it came, in ms since 1970. */
  at: number;
  bytes: Uint8Array;
};

/** Reads a frame: a byte of flags, the peer as 4 bytes, the time as an 8-byte float, little-endian, then the bytes. */
export function readFrame(buffer: ArrayBuffer | Uint8Array): Frame | null {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (bytes.length < 13) {
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    sent: (bytes[0] & 1) === 1,
    peer: view.getUint32(1, true),
    at: view.getFloat64(5, true),
    bytes: bytes.subarray(13),
  };
}

/** "192.168.1.50:5683", or "[::1]:23" for an IPv6 address. */
export function hostAndPort(host: string, port: number): string {
  const trimmed = host.trim();
  return trimmed.includes(":") && !trimmed.startsWith("[") ? `[${trimmed}]:${port}` : `${trimmed}:${port}`;
}

/** Where a local address listens, for people: "all addresses" when it is left empty. */
export function localText(address: string, port: number): string {
  const where = address.trim() === "" ? "all addresses" : address.trim() === "::" ? "all IPv6 addresses" : address.trim();
  return port === 0 ? `${where}, any free port` : `${where}, port ${port}`;
}

/** What a UDP tab's settings say, in a few words. */
export function udpText(config: UdpConfig): string {
  const remote = config.remote_host.trim() ? ` → ${hostAndPort(config.remote_host, config.remote_port)}` : "";
  const group = config.multicast?.group ? `, group ${config.multicast.group}` : "";
  return `UDP ${config.local_port === 0 ? "any port" : `:${config.local_port}`}${remote}${group}`;
}

/** "TLS", "Telnet over TLS", "Telnet" or "TCP": what a stream tab speaks. */
function streamName(telnet: boolean, tls: boolean): string {
  if (tls) return telnet ? "Telnet over TLS" : "TLS";
  return telnet ? "Telnet" : "TCP";
}

/** What a client's settings say, in a few words. */
export function clientText(config: TcpClientConfig): string {
  return `${streamName(config.telnet, Boolean(config.tls))} to ${hostAndPort(config.host, config.port)}`;
}

/** What a server's settings say, in a few words. */
export function serverText(config: TcpServerConfig): string {
  const where = config.address.trim() ? `${config.address.trim()}:` : ":";
  return `${streamName(config.telnet, Boolean(config.tls))} server on ${where}${config.port === 0 ? "any port" : config.port}`;
}

/** What TLS agreed, in one line: "TLS 1.3, TLS13_AES_128_GCM_SHA256, X25519, ALPN mqtt". */
export function agreedText(agreed: Agreed): string {
  const parts = [agreed.version, agreed.suite];
  if (agreed.group) parts.push(agreed.group);
  if (agreed.alpn) parts.push(`ALPN ${agreed.alpn}`);
  // A PSK's identity is said as it is; a server's name is the one the client asked for.
  if (agreed.name) parts.push(agreed.name.startsWith("PSK ") ? agreed.name : `asked for ${agreed.name}`);
  if (agreed.resumed) parts.push("resumed");
  return parts.filter(Boolean).join(", ");
}

/** A certificate in one line: who it is for, who signed it, until when, and its fingerprint. */
export function certText(cert: CertInfo): string {
  const names = cert.names.length > 0 ? ` for ${cert.names.join(", ")}` : "";
  const signer = cert.issuer === cert.subject ? "self-signed" : `signed by ${cert.issuer}`;
  return `${cert.subject}${names}, ${signer}, ${cert.key}, valid ${cert.not_before} to ${cert.not_after}, SHA-256 ${cert.sha256}`;
}

/** Why settings cannot work, in words, before the Rust side is asked; null when they look right. */
export function portProblem(port: number, needed: boolean): string | null {
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    return "A port is a whole number from 1 to 65535.";
  }
  if (needed && port === 0) {
    return "Enter the port: a number from 1 to 65535.";
  }
  return null;
}

/** The target as the send box keeps it: "default", "all" or "peer:3". */
export function targetOf(key: string): Target {
  if (key === "all") return { to: "all" };
  if (key.startsWith("peer:")) {
    const peer = Number.parseInt(key.slice(5), 10);
    if (Number.isInteger(peer)) return { to: "peer", peer };
  }
  return { to: "default" };
}
