// The protocol tabs: which socket each runs on, its usual port, and the
// settings its engine in netnima-core/src/proto takes, as fields the tab's
// settings dialog shows. Typed commands drive them; `help` lists them. It has
// no imports, so its tests run in Node as they are.

/** One setting of a protocol, as a field in the tab's settings. */
export type Field = {
  /** The name the engine's options have in Rust, such as "client_id". */
  key: string;
  label: string;
  type: "text" | "password" | "number" | "check" | "select";
  placeholder?: string;
  /** Takes two of the dialog's three columns. */
  wide?: boolean;
  min?: number;
  max?: number;
  /** For a select: each value and its words. */
  choices?: [string | number, string][];
  /** Says what it does when the mouse is on it. */
  title?: string;
  /** For a text field: "address" offers this PC's IPv4 addresses as it is typed in. */
  suggest?: "address";
};

export type ProtocolSetup = {
  /** The socket under it; "none" for one, such as ping, that does its own work. */
  socket: "client" | "server" | "udp" | "none";
  /** The port it usually has: a client connects to it, a server listens on it. */
  port: number;
  /** The usual port with TLS, when it can run over TLS. */
  tlsPort?: number;
  /** The usual port with DTLS, when it can run over DTLS. */
  dtlsPort?: number;
  fields: Field[];
  /** Each field's value in a new tab. */
  defaults: Record<string, unknown>;
  /** A line under the fields. */
  hint?: string;
  /** A view of the protocol's own, first among the tab's views: Modbus's, as terNIMA has it, MQTT's, CoAP's, HTTP's, LwM2M's or MCUmgr's. */
  view?: "modbus" | "mqtt" | "coap" | "http" | "lwm2m" | "mcumgr";
  /**
   * Whether its view speaks the protocol itself, on a plain socket, with no
   * engine and no typed commands, as the Modbus view does. MQTT's view asks
   * the engine instead.
   */
  plain?: boolean;
  /** What a new tab's UDP socket starts with, such as broadcast for Wake-on-LAN. */
  udp?: {
    local_port?: number;
    remote_host?: string;
    remote_port?: number;
    broadcast?: boolean;
    reuse_address?: boolean;
    multicast?: { group: string; interface: string; interface_index: number; loopback: boolean };
  };
};

const QOS: [number, string][] = [
  [0, "0: at most once"],
  [1, "1: at least once"],
  [2, "2: exactly once"],
];

export const PROTOCOL_SETUPS: Record<string, ProtocolSetup> = {
  mqtt_client: {
    socket: "client",
    port: 1883,
    tlsPort: 8883,
    fields: [
      { key: "version", label: "Version", type: "select", choices: [[4, "3.1.1"], [5, "5.0"], [3, "3.1"]] },
      { key: "client_id", label: "Client id", type: "text", placeholder: "Empty: one made up", wide: true },
      { key: "username", label: "User name", type: "text" },
      { key: "password", label: "Password", type: "password" },
      { key: "keep_alive", label: "Keep-alive, s", type: "number", min: 0, max: 65535 },
      { key: "subscribe", label: "Subscribe at once to", type: "text", placeholder: "sensors/#, cmd/+", wide: true },
      { key: "qos", label: "QoS unless told", type: "select", choices: QOS },
      { key: "will_topic", label: "Will topic", type: "text", placeholder: "Empty: no will", wide: true },
      { key: "will_qos", label: "Will QoS", type: "select", choices: QOS },
      { key: "will_payload", label: "Will message", type: "text", wide: true },
      { key: "session_expiry", label: "Session expiry, s (5.0)", type: "number", min: 0 },
      { key: "path", label: "WebSocket path", type: "text", placeholder: "/mqtt", title: "The path asked for over WebSocket" },
      { key: "clean", label: "Clean session", type: "check", title: "Starts a new session rather than taking up the last one" },
      { key: "will_retain", label: "Retain the will", type: "check" },
      { key: "websocket", label: "Over WebSocket", type: "check", title: "ws://, or wss:// with TLS on, as brokers offer on ports 8080, 8083 or 443" },
    ],
    defaults: {
      websocket: false,
      path: "/mqtt",
      version: 4,
      client_id: "",
      username: "",
      password: "",
      keep_alive: 60,
      clean: true,
      session_expiry: 0,
      will_topic: "",
      will_payload: "",
      will_qos: 0,
      will_retain: false,
      subscribe: "#",
      qos: 0,
    },
    hint: "Its MQTT view publishes and subscribes, and lists the messages by topic; the send box takes its commands too.",
    view: "mqtt",
  },
  mqtt_server: {
    socket: "server",
    port: 1883,
    tlsPort: 8883,
    fields: [
      { key: "username", label: "User name", type: "text", placeholder: "Empty: anyone" },
      { key: "password", label: "Password", type: "password" },
      { key: "websocket", label: "Takes WebSocket clients too", type: "check", title: "ws://, or wss:// with TLS on, on any path: plain MQTT clients still connect on the same port" },
    ],
    defaults: { username: "", password: "", websocket: false },
    hint: "It speaks 3.1, 3.1.1 and 5.0, keeps retained messages and publishes wills. Its MQTT view lists its clients, what is retained, and every message.",
    view: "mqtt",
  },
  coap_client: {
    view: "coap",
    socket: "udp",
    port: 5683,
    dtlsPort: 5684,
    fields: [
      { key: "token_length", label: "Token bytes", type: "number", min: 0, max: 8 },
      { key: "non", label: "Send requests as NON", type: "check", title: "NON requests are not sent again when no answer comes" },
    ],
    defaults: { non: false, token_length: 4 },
    hint: "Set the server's address as the remote host above. Type help for the commands, such as get /sensors/temp and observe /led.",
  },
  coap_server: {
    view: "coap",
    socket: "udp",
    port: 5683,
    dtlsPort: 5684,
    fields: [
      { key: "resources", label: "Resources to start with", type: "text", wide: true, placeholder: "sensors/temp=21.5, led=off" },
    ],
    defaults: { resources: "sensors/temp=21.5, sensors/hum=48, led=off" },
    hint: "It answers GET, PUT, POST and DELETE, Observe and block-wise, and lists its resources at /.well-known/core.",
  },
  modbus_client: {
    socket: "client",
    port: 502,
    tlsPort: 802,
    fields: [],
    defaults: {},
    hint: "Its Modbus view asks the slave: a request in each row, each with its Send, Poll for the ones ticked, and the values under each.",
    view: "modbus",
    plain: true,
  },
  modbus_server: {
    socket: "server",
    port: 502,
    tlsPort: 802,
    fields: [],
    defaults: {},
    hint: "Its Modbus view answers the masters that connect from its four tables, which their writes change.",
    view: "modbus",
    plain: true,
  },
  http_client: {
    view: "http",
    socket: "client",
    port: 80,
    tlsPort: 443,
    fields: [
      { key: "headers", label: "Headers on every request", type: "text", wide: true, placeholder: "Authorization: Bearer abc; Accept: application/json" },
    ],
    defaults: { headers: "" },
    hint: "Type help for the commands, such as get /api/status and post /api/led {\"on\":true}.",
  },
  http_server: {
    view: "http",
    socket: "server",
    port: 8080,
    tlsPort: 8443,
    fields: [{ key: "folder", label: "Folder of files to serve", type: "text", wide: true, placeholder: "Empty: none" }],
    defaults: { folder: "" },
    hint: "It answers its routes, GET / with a list of them, and POST /echo. Type help: route GET /api/temp 200 {\"t\":21.5}.",
  },
  websocket_client: {
    socket: "client",
    port: 80,
    tlsPort: 443,
    fields: [
      { key: "path", label: "Path", type: "text", placeholder: "/" },
      { key: "protocols", label: "Subprotocols", type: "text", placeholder: "mqtt, chat" },
      { key: "origin", label: "Origin", type: "text", placeholder: "Empty: none" },
    ],
    defaults: { path: "/", protocols: "", origin: "" },
    hint: "What is typed goes as a text message. Commands start with a slash: /binary 01 02, /ping, /close.",
  },
  websocket_server: {
    socket: "server",
    port: 8080,
    tlsPort: 8443,
    fields: [{ key: "echo", label: "Send each message back", type: "check" }],
    defaults: { echo: false },
    hint: "What is typed goes to every client as text. Type help for /to, /binary, /ping and /close.",
  },
  syslog_client: {
    socket: "udp",
    port: 514,
    fields: [
      { key: "format", label: "Form", type: "select", choices: [[5424, "RFC 5424"], [3164, "RFC 3164 (BSD)"]] },
      { key: "hostname", label: "Host name", type: "text" },
      { key: "app", label: "App name", type: "text" },
      {
        key: "facility",
        label: "Facility",
        type: "select",
        choices: ["user", "daemon", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7", "kern", "auth"].map(
          (name) => [name, name] as [string, string],
        ),
      },
    ],
    defaults: { format: 5424, hostname: "netnima", app: "netnima", facility: "user" },
    hint: "What is typed goes as a message at the info level; -w, -r, -e and the others set the level. Type help.",
  },
  syslog_server: {
    socket: "udp",
    port: 514,
    fields: [],
    defaults: {},
    hint: "It shows each message with its facility and level, in RFC 3164's form or RFC 5424's. Type level warning or module net_dhcpv4 to filter Zephyr's logs.",
  },
  syslog_tcp_client: {
    socket: "client",
    port: 601,
    tlsPort: 6514,
    fields: [
      { key: "format", label: "Form", type: "select", choices: [[5424, "RFC 5424"], [3164, "RFC 3164 (BSD)"]] },
      { key: "hostname", label: "Host name", type: "text" },
      { key: "app", label: "App name", type: "text" },
      {
        key: "facility",
        label: "Facility",
        type: "select",
        choices: ["user", "daemon", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7", "kern", "auth"].map(
          (name) => [name, name] as [string, string],
        ),
      },
      {
        key: "lines",
        label: "A line end after each message",
        type: "check",
        title: "Non-transparent framing, as many devices send: otherwise each message has its length in front (octet counting), as RFC 5425 has over TLS",
      },
    ],
    defaults: { format: 5424, hostname: "netnima", app: "netnima", facility: "user", lines: false },
    hint: "What is typed goes as a message at the info level; -w, -r, -e and the others set the level. 601 is syslog over TCP, 6514 over TLS.",
  },
  syslog_tcp_server: {
    socket: "server",
    port: 601,
    tlsPort: 6514,
    fields: [],
    defaults: {},
    hint: "It takes each message with its length in front or one a line, and shows its facility and level. Type level warning or module main to filter.",
  },
  ntp_client: {
    socket: "udp",
    port: 123,
    fields: [],
    defaults: {},
    hint: "Type ask for the time once, or every 10 to ask again and again: it shows how far this PC's clock is off.",
  },
  ntp_server: {
    socket: "udp",
    port: 123,
    fields: [],
    defaults: {},
    hint: "It answers with this PC's clock, for a board that sets its time from the network.",
  },
  wol_client: {
    socket: "udp",
    port: 9,
    fields: [],
    defaults: {},
    hint: "Type wake and a MAC address, such as wake 00:11:22:33:44:55.",
    udp: { remote_host: "255.255.255.255", broadcast: true },
  },
  wol_server: {
    socket: "udp",
    port: 9,
    fields: [],
    defaults: {},
    hint: "It shows the magic packets that come, and the MAC address each wakes.",
  },
  dns_client: {
    socket: "udp",
    port: 53,
    fields: [],
    defaults: {},
    hint: "Set the DNS server as the remote host above. Type a example.com, aaaa, mx, txt, srv, ptr 192.168.1.1...",
  },
  dns_server: {
    socket: "udp",
    port: 53,
    fields: [{ key: "records", label: "Records", type: "text", wide: true, placeholder: "board.local=192.168.1.50, sensor.local=fe80::1" }],
    defaults: { records: "board.local=192.168.1.50, netnima.local=127.0.0.1" },
    hint: "It answers A, AAAA, TXT and CNAME from its records. Type help: add, remove, records.",
  },
  dns_tcp_client: {
    socket: "client",
    port: 53,
    tlsPort: 853,
    fields: [],
    defaults: {},
    hint: "Each question goes with its length in front, as DNS over TCP and DNS over TLS (853) have it. Type a example.com, aaaa, mx, txt...",
  },
  dns_tcp_server: {
    socket: "server",
    port: 53,
    tlsPort: 853,
    fields: [{ key: "records", label: "Records", type: "text", wide: true, placeholder: "board.local=192.168.1.50, sensor.local=fe80::1" }],
    defaults: { records: "board.local=192.168.1.50, netnima.local=127.0.0.1" },
    hint: "DNS over TCP, or over TLS on 853: it answers A, AAAA, TXT and CNAME from its records. Type help: add, remove, records.",
  },
  tftp_client: {
    socket: "udp",
    port: 69,
    fields: [{ key: "folder", label: "Folder", type: "text", wide: true, placeholder: "Empty: Downloads" }],
    defaults: { folder: "" },
    hint: "Type get firmware.bin or put config.txt: files are read from and saved to the folder.",
  },
  tftp_server: {
    socket: "udp",
    port: 69,
    fields: [{ key: "folder", label: "Folder served", type: "text", wide: true, placeholder: "Empty: Downloads" }],
    defaults: { folder: "" },
    hint: "For bootloaders such as U-Boot: it serves the folder's files and keeps what clients put, with blksize and tsize.",
  },
  iperf_client: {
    socket: "client",
    port: 5001,
    fields: [
      { key: "seconds", label: "Seconds", type: "number", min: 1, max: 86400 },
      { key: "bandwidth", label: "Rate", type: "text", placeholder: "10M" },
      { key: "length", label: "Bytes each", type: "number", min: 12, max: 65000 },
    ],
    defaults: { seconds: 10, bandwidth: "10M", length: 1470 },
    hint: "Type run, or run 30 -b 50M: it sends at that rate, and the server says what came each second.",
  },
  iperf_server: {
    socket: "server",
    port: 5001,
    fields: [],
    defaults: {},
    hint: "It counts what each client sends, each second and in all, as iperf2 -s does.",
  },
  iperf_udp_client: {
    socket: "udp",
    port: 5001,
    fields: [
      { key: "seconds", label: "Seconds", type: "number", min: 1, max: 86400 },
      { key: "bandwidth", label: "Rate", type: "text", placeholder: "1M" },
      { key: "length", label: "Bytes each", type: "number", min: 12, max: 65000 },
    ],
    defaults: { seconds: 10, bandwidth: "1M", length: 1470 },
    hint: "Type run, or run 10 -b 5M -l 1200: datagrams numbered and timed, and the server's report at the end.",
  },
  iperf_udp_server: {
    socket: "udp",
    port: 5001,
    fields: [],
    defaults: {},
    hint: "It counts each client's datagrams, the ones lost or out of order, and the jitter, and sends its report.",
  },
  ftp_client: {
    socket: "client",
    port: 21,
    // FTPS: explicit FTPS stays on 21, with AUTH TLS; implicit is usually on 990.
    tlsPort: 21,
    fields: [
      { key: "username", label: "User name", type: "text" },
      { key: "password", label: "Password", type: "password" },
      { key: "folder", label: "Folder for files", type: "text", wide: true, placeholder: "Empty: Downloads" },
      {
        key: "implicit",
        label: "TLS from the start (implicit, port 990)",
        type: "check",
        title: "With Over TLS on: TLS from the first byte, as on port 990. Otherwise the connection starts plain and AUTH TLS turns TLS on (explicit FTPS)",
      },
    ],
    defaults: { username: "anonymous", password: "netnima@", folder: "", implicit: false },
    hint: "It logs in as it connects; over TLS it asks for AUTH TLS and PROT P first, so files go in TLS too. Type ls, cd, get <file>, put <file>, or quote.",
  },
  ftp_server: {
    socket: "server",
    port: 21,
    tlsPort: 21,
    fields: [
      { key: "folder", label: "Folder served", type: "text", wide: true, placeholder: "Empty: Downloads" },
      { key: "username", label: "User name", type: "text", placeholder: "Empty: anyone" },
      { key: "password", label: "Password", type: "password" },
      {
        key: "implicit",
        label: "TLS from the start (implicit, port 990)",
        type: "check",
        title: "With Over TLS on: TLS from the first byte, as on port 990. Otherwise clients connect plain and send AUTH TLS (explicit FTPS)",
      },
    ],
    defaults: { folder: "", username: "", password: "", implicit: false },
    hint: "Passive mode (PASV and EPSV): listings, files to get and put, folders made and removed. Over TLS: AUTH TLS, PBSZ and PROT P.",
  },
  ping: {
    socket: "none",
    port: 0,
    fields: [
      { key: "host", label: "Host", type: "text", wide: true, placeholder: "192.168.1.1 or a name" },
      { key: "interval", label: "Every, ms", type: "number", min: 100 },
      { key: "count", label: "How many", type: "number", min: 0, title: "0 pings until stopped" },
      { key: "size", label: "Bytes of data", type: "number", min: 0, max: 65000 },
      { key: "timeout", label: "Wait, ms", type: "number", min: 10 },
    ],
    defaults: { host: "127.0.0.1", interval: 1000, count: 0, size: 32, timeout: 1000 },
    hint: "It starts at once. Type ping to start over, ping <host> for another, stop for how it went.",
  },
  echo_client: {
    socket: "none",
    port: 0,
    fields: [
      { key: "host", label: "Echo server", type: "text", wide: true, placeholder: "192.168.1.50 or a name" },
      { key: "port", label: "Port", type: "number", min: 1, max: 65535 },
      { key: "count", label: "Messages in a test", type: "number", min: 1 },
      { key: "size", label: "Bytes each", type: "number", min: 1, max: 60000 },
      { key: "interval", label: "Between, ms", type: "number", min: 0 },
    ],
    defaults: { host: "192.168.1.50", port: 4242, count: 100, size: 64, interval: 0 },
    hint: "Type a line to send it and time its echo, or test [count] [size] [ms]. 4242 is Zephyr's echo_server; RFC 862's port is 7.",
  },
  echo_udp_client: {
    socket: "none",
    port: 0,
    fields: [
      { key: "host", label: "Echo server", type: "text", wide: true, placeholder: "192.168.1.50 or a name" },
      { key: "port", label: "Port", type: "number", min: 1, max: 65535 },
      { key: "count", label: "Messages in a test", type: "number", min: 1 },
      { key: "size", label: "Bytes each", type: "number", min: 1, max: 60000 },
      { key: "interval", label: "Between, ms", type: "number", min: 0 },
    ],
    defaults: { host: "192.168.1.50", port: 4242, count: 100, size: 64, interval: 0 },
    hint: "Each message is a datagram: one that does not come back in 2 s is counted lost. Type a line, or test [count] [size] [ms].",
  },
  stun_client: {
    socket: "udp",
    port: 3478,
    fields: [],
    defaults: {},
    hint: "Set the STUN server as the remote host above, then type bind: it shows the address and port the server sees this end at.",
  },
  stun_server: {
    socket: "udp",
    port: 3478,
    fields: [],
    defaults: {},
    hint: "It answers each Binding Request with the address and port it came from (XOR-MAPPED-ADDRESS). Type stats.",
  },
  echo_server: {
    socket: "server",
    port: 4242,
    fields: [{ key: "quiet", label: "Only count what comes", type: "check" }],
    defaults: { quiet: false },
    hint: "It sends back what comes, as Zephyr's echo_server does, for its echo_client sample. Type stats, or quiet.",
  },
  echo_udp_server: {
    socket: "udp",
    port: 4242,
    fields: [{ key: "quiet", label: "Only count what comes", type: "check" }],
    defaults: { quiet: false },
    hint: "It sends each datagram back to its sender. Type stats, or quiet.",
  },
  dhcp_client: {
    socket: "udp",
    port: 67,
    fields: [
      { key: "mac", label: "MAC address", type: "text", placeholder: "Empty: one made up" },
      { key: "host", label: "Host name", type: "text" },
    ],
    defaults: { mac: "", host: "netnima" },
    hint: "Type discover: it shows what servers offer, and takes the first. The PC's own address does not change. Port 68 may be held by the OS's DHCP client.",
    udp: { local_port: 68, remote_host: "255.255.255.255", broadcast: true },
  },
  dhcp_server: {
    socket: "udp",
    port: 67,
    fields: [
      {
        key: "server",
        label: "This PC's address there",
        type: "text",
        suggest: "address",
        title: "The address of the card the board is wired to: it lists this PC's addresses as you type; Tools > The PC's interfaces shows them all",
      },
      { key: "first", label: "First address given", type: "text" },
      { key: "count", label: "How many", type: "number", min: 1, max: 1000 },
      { key: "mask", label: "Mask", type: "text" },
      { key: "router", label: "Router", type: "text", placeholder: "Empty: none" },
      { key: "dns", label: "DNS server", type: "text", placeholder: "Empty: none" },
      { key: "lease", label: "Lease, s", type: "number", min: 60 },
    ],
    defaults: { server: "192.168.137.1", first: "192.168.137.100", count: 50, mask: "255.255.255.0", router: "", dns: "", lease: 3600 },
    hint: "For a board wired straight to the PC: give that network card a fixed address, and listen on it above. Type help.",
    udp: { remote_host: "255.255.255.255", remote_port: 68, broadcast: true },
  },
  lwm2m_client: {
    view: "lwm2m",
    socket: "udp",
    port: 5683,
    dtlsPort: 5684,
    fields: [
      { key: "endpoint", label: "Endpoint name", type: "text", wide: true },
      { key: "lifetime", label: "Lifetime, s", type: "number", min: 10 },
      { key: "manufacturer", label: "Manufacturer", type: "text" },
      { key: "model", label: "Model", type: "text" },
      { key: "serial", label: "Serial number", type: "text" },
      { key: "firmware", label: "Firmware version", type: "text" },
      {
        key: "bootstrap",
        label: "Bootstrap first",
        type: "check",
        title: "Asks the server above for bootstrap (POST /bs), then registers at the server it is given",
      },
    ],
    defaults: {
      endpoint: "netnima-device",
      lifetime: 300,
      manufacturer: "netNIMA",
      model: "Simulated board",
      serial: "0001",
      firmware: "1.0.0",
      bootstrap: false,
    },
    hint: "A device with the Server, Device, Firmware Update, Temperature and Light Control objects. It registers at once, or bootstraps first; type help.",
  },
  lwm2m_server: {
    view: "lwm2m",
    socket: "udp",
    port: 5683,
    dtlsPort: 5684,
    fields: [
      {
        key: "format",
        label: "Reads ask for",
        type: "select",
        choices: [
          ["tlv", "TLV"],
          ["senml", "SenML JSON"],
          ["senml-cbor", "SenML CBOR"],
          ["text", "Plain text"],
        ],
      },
      {
        key: "bootstrap",
        label: "As a bootstrap server, it gives",
        type: "text",
        wide: true,
        placeholder: "Empty: none; coap://192.168.1.10:5683",
        title: "The LwM2M server's address given to devices that ask for bootstrap, such as this tab's own",
      },
      {
        key: "bootstrap_key",
        label: "With the PSK, for coaps://",
        type: "text",
        placeholder: "Hex, or \"text\"",
        title: "The key given with a coaps:// address; a device's PSK identity is its name",
      },
    ],
    defaults: { format: "tlv", bootstrap: "", bootstrap_key: "" },
    hint: "Devices register with it. Type help: clients, read 1 /3/0, write, execute, observe, discover, firmware 1 app.bin.",
  },
  mcumgr_client: {
    view: "mcumgr",
    socket: "udp",
    port: 1337,
    fields: [
      { key: "folder", label: "Folder of firmware files", type: "text", wide: true, placeholder: "Empty: Downloads" },
      { key: "version2", label: "SMP version 2 (Zephyr 3.5 and later)", type: "check" },
    ],
    defaults: { version2: true, folder: "" },
    hint: "Type help: echo, info, taskstat, images, upload zephyr.signed.bin, test <hash>, confirm, reset.",
  },
  mcumgr_server: {
    view: "mcumgr",
    socket: "udp",
    port: 1337,
    fields: [],
    defaults: {},
    hint: "A simulated Zephyr board: it answers os and image commands, and takes firmware uploads.",
  },
  mdns_client: {
    socket: "udp",
    port: 5353,
    fields: [],
    defaults: {},
    hint: "Type browse for the kinds of service there are, browse _http._tcp for one kind, resolve and found.",
    udp: { remote_host: "224.0.0.251" },
  },
  mdns_server: {
    socket: "udp",
    port: 5353,
    fields: [
      { key: "instance", label: "Name", type: "text" },
      { key: "service", label: "Service", type: "text", placeholder: "_http._tcp" },
      { key: "port", label: "Its port", type: "number", min: 1, max: 65535 },
      { key: "host", label: "Host, .local", type: "text" },
      { key: "txt", label: "Text", type: "text", wide: true, placeholder: "version=1; model=board" },
    ],
    defaults: { instance: "netNIMA", service: "_netnima._udp", port: 5683, txt: "version=1", host: "netnima" },
    hint: "It shares port 5353 with the OS's own responder, and answers the questions about its service.",
    udp: {
      remote_host: "224.0.0.251",
      remote_port: 5353,
      reuse_address: true,
      multicast: { group: "224.0.0.251", interface: "", interface_index: 0, loopback: true },
    },
  },
  ssdp_client: {
    socket: "udp",
    port: 1900,
    fields: [],
    defaults: {},
    hint: "Type search for every device, or search upnp:rootdevice; found lists what answered.",
    udp: { remote_host: "239.255.255.250" },
  },
  ssdp_server: {
    socket: "udp",
    port: 1900,
    fields: [
      { key: "target", label: "It is", type: "text", wide: true, placeholder: "upnp:rootdevice" },
      { key: "location", label: "Its description", type: "text", wide: true, placeholder: "Empty: on this PC, port 8080" },
    ],
    defaults: { target: "upnp:rootdevice", location: "" },
    hint: "It answers searches for its target or ssdp:all; notify and byebye say it comes and goes.",
    udp: {
      remote_host: "239.255.255.250",
      remote_port: 1900,
      reuse_address: true,
      multicast: { group: "239.255.255.250", interface: "", interface_index: 0, loopback: true },
    },
  },
  coap_tcp_client: {
    view: "coap",
    socket: "client",
    port: 5683,
    tlsPort: 5684,
    fields: [{ key: "token_length", label: "Token bytes", type: "number", min: 0, max: 8 }],
    defaults: { token_length: 4 },
    hint: "CoAP over TCP (RFC 8323), or TLS with ALPN coap: each end sends its CSM first. Type help: get /sensors/temp, observe /led, ping.",
  },
  coap_tcp_server: {
    view: "coap",
    socket: "server",
    port: 5683,
    tlsPort: 5684,
    fields: [
      { key: "resources", label: "Resources to start with", type: "text", wide: true, placeholder: "sensors/temp=21.5, led=off" },
    ],
    defaults: { resources: "sensors/temp=21.5, sensors/hum=48, led=off" },
    hint: "CoAP over TCP (RFC 8323): its resources take GET, PUT, POST, DELETE and Observe. Lines show messages as UDP would carry them.",
  },
  coap_ws_client: {
    view: "coap",
    socket: "client",
    port: 80,
    tlsPort: 443,
    fields: [
      { key: "path", label: "WebSocket path", type: "text", placeholder: "/.well-known/coap" },
      { key: "token_length", label: "Token bytes", type: "number", min: 0, max: 8 },
    ],
    defaults: { path: "/.well-known/coap", token_length: 4 },
    hint: "CoAP over WebSocket (RFC 8323): ws://, or wss:// with TLS on, subprotocol coap. Type help: get /sensors/temp, observe /led.",
  },
  coap_ws_server: {
    view: "coap",
    socket: "server",
    port: 8080,
    tlsPort: 8443,
    fields: [
      { key: "resources", label: "Resources to start with", type: "text", wide: true, placeholder: "sensors/temp=21.5, led=off" },
    ],
    defaults: { resources: "sensors/temp=21.5, sensors/hum=48, led=off" },
    hint: "CoAP over WebSocket (RFC 8323) on any path: its resources take GET, PUT, POST, DELETE and Observe.",
  },
  mqttsn_client: {
    socket: "udp",
    port: 10000,
    fields: [
      { key: "client_id", label: "Client id", type: "text", wide: true },
      { key: "keep_alive", label: "Keep-alive, s", type: "number", min: 0, max: 65535 },
      { key: "subscribe", label: "Subscribe at once to", type: "text", placeholder: "sensors/#, cmd", wide: true },
      { key: "qos", label: "QoS unless told", type: "select", choices: QOS },
      { key: "clean", label: "Clean session", type: "check" },
    ],
    defaults: { client_id: "netnima-sn", keep_alive: 60, subscribe: "sensors/#", qos: 0, clean: true },
    hint: "Set the gateway as the remote host above. Type pub -q1 sensors/temp 21.5, sub cmd, or pub -q-1 t1 hi to a two-letter topic.",
  },
  mqttsn_server: {
    socket: "udp",
    port: 10000,
    fields: [{ key: "gateway_id", label: "Gateway id", type: "number", min: 0, max: 255 }],
    defaults: { gateway_id: 1 },
    hint: "A gateway with a broker inside: its clients publish to each other through it. Type help: pub, clients, topics.",
  },
  snmp_client: {
    socket: "udp",
    port: 161,
    fields: [
      { key: "community", label: "Community", type: "text" },
      { key: "version", label: "Version", type: "select", choices: [["2c", "v2c"], ["1", "v1"]] },
    ],
    defaults: { community: "public", version: "2c" },
    hint: "Set the agent's address as the remote host above. Type get sysDescr.0, walk system, bulk, set sysName.0 s board; traps that come are shown.",
  },
  snmp_server: {
    socket: "udp",
    port: 161,
    fields: [
      { key: "community", label: "Community that reads", type: "text" },
      { key: "write_community", label: "Community that sets", type: "text" },
      { key: "name", label: "sysName", type: "text" },
      { key: "location", label: "sysLocation", type: "text" },
    ],
    defaults: { community: "public", write_community: "private", name: "netnima", location: "bench" },
    hint: "It answers the system group and a board's values under 1.3.6.1.4.1.32473. Type mib, set, or trap; traps go to the remote host above, or the manager heard last.",
  },
};

/** The setup of a protocol tab's kind; undefined for socket tabs such as TCP. */
export function setupOf(kind: string): ProtocolSetup | undefined {
  return PROTOCOL_SETUPS[kind];
}

/** A protocol tab's options: what was saved, with each missing one at its default. */
export function optionsOf(kind: string, saved: Record<string, unknown> | undefined): Record<string, unknown> {
  return { ...(setupOf(kind)?.defaults ?? {}), ...(saved ?? {}) };
}
