// The kinds of tab that File > New tab and the + button open: every protocol
// with its two ends, in its group, so both offer the same, in the same words
// and order, and the command palette too. It has no imports, so its tests
// run in Node as they are.

/** One end of a protocol, and the kind of tab it opens. */
export type End = {
  /** The tab's kind, as it is saved in workspace.toml: "mqtt_client", "mqtt_server", "udp". */
  kind: string;
  /** Its button in the New tab dialog: "Client", "Broker". */
  label: string;
  /** A new tab's name, with a number after it when it is taken: "MQTT broker". */
  title: string;
  /**
   * What it runs over, for a protocol with ends over more than one, such as
   * CoAP over UDP, TCP and WebSocket: the New tab dialog gives each a line.
   */
  transport?: string;
};

export type Protocol = {
  /** Such as "MQTT". */
  name: string;
  /** What it is for, beside its name in the New tab dialog. */
  detail: string;
  /** The roadmap phase that brings it. */
  phase: number;
  /** A client and a server, under their own names, for each transport; one end for UDP, ping and capture. */
  ends: End[];
};

export type Group = { name: string; protocols: Protocol[] };

/** A protocol with a client and a server, each named as the protocol names them. */
function both(id: string, name: string, client: string, server: string): End[] {
  return [
    { kind: `${id}_client`, label: client, title: `${name} ${client.toLowerCase()}` },
    { kind: `${id}_server`, label: server, title: `${name} ${server.toLowerCase()}` },
  ];
}

/** A protocol with one kind of tab, which does both or needs no other end. */
function one(kind: string, title: string): End[] {
  return [{ kind, label: "Open", title }];
}

/** A protocol's ends over one transport, when it has ends over more than one. */
function over(transport: string, ends: End[]): End[] {
  return ends.map((end) => ({ ...end, transport }));
}

/** In the order the roadmap brings them, grouped as the plan groups them. */
export const GROUPS: Group[] = [
  {
    name: "Sockets",
    protocols: [
      { name: "UDP", detail: "Send, listen, or both, each datagram kept whole", phase: 1, ends: one("udp", "UDP") },
      { name: "TCP", detail: "A stream: connect to a device, or let devices connect", phase: 1, ends: both("tcp", "TCP", "Client", "Server") },
      { name: "Telnet", detail: "TCP with Telnet's option talk", phase: 1, ends: both("telnet", "Telnet", "Client", "Server") },
    ],
  },
  {
    name: "Secure links",
    protocols: [
      { name: "TLS", detail: "TCP with TLS 1.0 to 1.3, certificates or a pre-shared key", phase: 2, ends: both("tls", "TLS", "Client", "Server") },
      { name: "DTLS", detail: "UDP with DTLS 1.0 to 1.3, a pre-shared key or certificates", phase: 2, ends: both("dtls", "DTLS", "Client", "Server") },
    ],
  },
  {
    name: "Messaging",
    protocols: [
      { name: "MQTT", detail: "Publish and subscribe, 3.1.1 and 5, over TCP, TLS or WebSocket", phase: 4, ends: both("mqtt", "MQTT", "Client", "Broker") },
      { name: "MQTT-SN", detail: "MQTT for sensor networks, over UDP, with a gateway that is its own broker", phase: 4, ends: both("mqttsn", "MQTT-SN", "Client", "Gateway") },
      {
        name: "CoAP",
        detail: "Requests, Observe and block-wise, over UDP or DTLS, TCP or TLS, and WebSocket",
        phase: 4,
        ends: [
          ...over("UDP", both("coap", "CoAP", "Client", "Server")),
          ...over("TCP", both("coap_tcp", "CoAP TCP", "Client", "Server")),
          ...over("WebSocket", both("coap_ws", "CoAP WebSocket", "Client", "Server")),
        ],
      },
    ],
  },
  {
    name: "Web",
    protocols: [
      { name: "HTTP", detail: "Requests to a device's web API, or a server with routes made by hand", phase: 5, ends: both("http", "HTTP", "Client", "Server") },
      { name: "WebSocket", detail: "Text and binary messages, ws and wss", phase: 5, ends: both("websocket", "WebSocket", "Client", "Server") },
    ],
  },
  {
    name: "Devices",
    protocols: [
      { name: "Modbus TCP", detail: "Coils and registers with terNIMA's tester, over TCP or TLS", phase: 6, ends: both("modbus", "Modbus TCP", "Master", "Slave") },
      { name: "MCUmgr", detail: "Firmware update over UDP, as Zephyr serves it", phase: 6, ends: both("mcumgr", "MCUmgr", "Client", "Device") },
      { name: "LwM2M", detail: "Device management over CoAP, bootstrap and firmware update", phase: 7, ends: both("lwm2m", "LwM2M", "Client", "Server") },
    ],
  },
  {
    name: "Services for boards",
    protocols: [
      { name: "TFTP", detail: "Files for bootloaders such as U-Boot", phase: 8, ends: both("tftp", "TFTP", "Client", "Server") },
      { name: "FTP", detail: "Files, plain or with FTPS", phase: 8, ends: both("ftp", "FTP", "Client", "Server") },
      {
        name: "Syslog",
        detail: "Log messages over UDP, TCP or TLS",
        phase: 8,
        ends: [
          ...over("UDP", both("syslog", "Syslog", "Sender", "Receiver")),
          ...over("TCP", both("syslog_tcp", "Syslog TCP", "Sender", "Receiver")),
        ],
      },
      { name: "NTP", detail: "The time, asked for or served", phase: 8, ends: both("ntp", "NTP", "Client", "Server") },
      {
        name: "DNS",
        detail: "Names, any record, over UDP, TCP or TLS",
        phase: 8,
        ends: [
          ...over("UDP", both("dns", "DNS", "Client", "Server")),
          ...over("TCP", both("dns_tcp", "DNS TCP", "Client", "Server")),
        ],
      },
      { name: "DHCP", detail: "Addresses, for a board wired straight to the PC", phase: 8, ends: both("dhcp", "DHCP", "Client", "Server") },
      { name: "SNMP", detail: "v1 and v2c: get, walk, bulk, set and traps", phase: 8, ends: both("snmp", "SNMP", "Manager", "Agent") },
    ],
  },
  {
    name: "Finding and measuring",
    protocols: [
      { name: "mDNS / DNS-SD", detail: "The services on the network, and one of our own", phase: 9, ends: both("mdns", "mDNS", "Browse", "Advertise") },
      { name: "SSDP", detail: "Who is there, by UPnP's search", phase: 9, ends: both("ssdp", "SSDP", "Search", "Answer") },
      {
        name: "iperf2 / zperf",
        detail: "Throughput over TCP or UDP, as Zephyr's zperf and ESP-IDF's iperf measure it",
        phase: 9,
        ends: [
          ...over("TCP", both("iperf", "iperf2 TCP", "Client", "Server")),
          ...over("UDP", both("iperf_udp", "iperf2 UDP", "Client", "Server")),
        ],
      },
      { name: "Ping", detail: "Times and losses, IPv4 and IPv6", phase: 9, ends: one("ping", "Ping") },
      { name: "STUN", detail: "The address and port a NAT gives this end, as a server sees it", phase: 9, ends: both("stun", "STUN", "Client", "Server") },
      {
        name: "Echo",
        detail: "What is sent comes back, checked and timed, over TCP or UDP, as Zephyr's echo samples do",
        phase: 9,
        ends: [
          ...over("TCP", both("echo", "Echo TCP", "Client", "Server")),
          ...over("UDP", both("echo_udp", "Echo UDP", "Client", "Server")),
        ],
      },
      { name: "Wake-on-LAN", detail: "The magic packet, sent or heard", phase: 9, ends: both("wol", "Wake-on-LAN", "Send", "Listen") },
    ],
  },
  {
    name: "Capture",
    protocols: [
      { name: "Capture", detail: "The packets on an interface, read layer by layer", phase: 10, ends: one("capture", "Capture") },
    ],
  },
];

/**
 * The kinds of tab built so far. The roadmap's phases bring the others, not
 * always in their order: a kind is listed here once it works.
 */
export const READY = new Set<string>([
  "udp",
  "tcp_client",
  "tcp_server",
  "telnet_client",
  "telnet_server",
  "tls_client",
  "tls_server",
  "dtls_client",
  "dtls_server",
  "mqtt_client",
  "mqtt_server",
  "coap_client",
  "coap_server",
  "modbus_client",
  "modbus_server",
  "http_client",
  "http_server",
  "websocket_client",
  "websocket_server",
  "syslog_client",
  "syslog_server",
  "syslog_tcp_client",
  "syslog_tcp_server",
  "ntp_client",
  "ntp_server",
  "wol_client",
  "wol_server",
  "dns_client",
  "dns_server",
  "dns_tcp_client",
  "dns_tcp_server",
  "tftp_client",
  "tftp_server",
  "mcumgr_client",
  "mcumgr_server",
  "lwm2m_client",
  "lwm2m_server",
  "dhcp_client",
  "dhcp_server",
  "ping",
  "ftp_client",
  "ftp_server",
  "iperf_client",
  "iperf_server",
  "iperf_udp_client",
  "iperf_udp_server",
  "mdns_client",
  "mdns_server",
  "ssdp_client",
  "ssdp_server",
  "snmp_client",
  "snmp_server",
  "mqttsn_client",
  "mqttsn_server",
  "coap_tcp_client",
  "coap_tcp_server",
  "echo_client",
  "echo_server",
  "echo_udp_client",
  "echo_udp_server",
  "stun_client",
  "stun_server",
  "coap_ws_client",
  "coap_ws_server",
]);

/** Whether a kind of tab is built, so it can connect. */
export function isReady(kind: string): boolean {
  return READY.has(kind);
}

/** Whether any end of a protocol is built. */
export function protocolReady(protocol: Protocol): boolean {
  return protocol.ends.some((end) => READY.has(end.kind));
}

/** Every end of every protocol, in the order of the groups, each with its protocol. */
export const ENDS: { end: End; protocol: Protocol }[] = GROUPS.flatMap((group) =>
  group.protocols.flatMap((protocol) => protocol.ends.map((end) => ({ end, protocol }))),
);

/** A line of buttons in the New tab dialog: a protocol's ends over one transport. */
export type Line = { transport?: string; ends: End[] };

/**
 * A protocol's ends as the New tab dialog shows them: a line for each
 * transport, in their order. A client and a server a line keep the
 * protocol's name in view beside them, however many ends it has.
 */
export function linesOf(protocol: Protocol): Line[] {
  const lines: Line[] = [];
  for (const end of protocol.ends) {
    const line = lines.find((each) => each.transport === end.transport);
    if (line) line.ends.push(end);
    else lines.push({ transport: end.transport, ends: [end] });
  }
  return lines;
}

/** A kind of tab's end and protocol; undefined for a kind this netNIMA does not know. */
export function endOf(kind: string): { end: End; protocol: Protocol } | undefined {
  return ENDS.find(({ end }) => end.kind === kind);
}

/** The protocols whose name, words or ends have all of these words in them, in their groups; all of them for none. */
export function findProtocols(query: string): Group[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const matches = (protocol: Protocol) => {
    const text = [protocol.name, protocol.detail, ...protocol.ends.map((end) => end.title)].join(" ").toLowerCase();
    return words.every((word) => text.includes(word));
  };
  return GROUPS.map((group) => ({ ...group, protocols: group.protocols.filter(matches) })).filter(
    (group) => group.protocols.length > 0,
  );
}
