# netNIMA plan

netNIMA is a desktop app for testing devices on the network. It speaks UDP, TCP, TLS
and DTLS, and the protocols embedded devices use on top of them, each one as a client
and as a server, so one PC can try both ends with no device at all. It also sniffs
packets. It looks and works like terNIMA, the same on Windows, Linux and macOS.

The name is "net" with my name, Nima, in it: net-NIMA.

This file is the plan: what we build, what we build it with, and in which order. It
will change as we learn. The question still open comes before the roadmap, and the
checklists at the bottom show where we are.

---

## Decisions

| Topic | Decision |
|---|---|
| Kind of app | Desktop GUI app with its own window |
| Platforms | Windows 10/11, Linux x86_64, macOS 11+ (Apple Silicon and Intel) |
| Look | terNIMA's: the same UI on all three, its colors, fonts, menus, tabs and status bar |
| Menus | Our own menu bar inside the window (File, Edit, View, Connection, Capture, Tools, Help), the same on every OS |
| Both ends | Every protocol has a client and a server in netNIMA, so each one can be tried on one PC with no device. Decided in November 2026 |
| Order | The protocols first, then the sniffer. Decided in November 2026 |
| Nothing outside | No device, no firmware, and nothing else to install for the protocols: what can be done in Rust is done in Rust |
| Wi-Fi monitor mode | Not in this plan: this PC's adapter cannot do it, and the other ways need a device outside the PC. Decided in November 2026 |
| Language | Rust for everything that touches the network, TypeScript for the UI |
| App framework | Tauri 2 |
| Sockets | tokio |
| TLS | All of it: TLS 1.0 to 1.3, PSK, AES-CCM. rustls for TLS 1.2 and 1.3; OpenSSL, built into netNIMA, for the rest (see the open question) |
| DTLS | All of it: DTLS 1.0 to 1.3, PSK, AES-CCM, the Connection ID. dimpl, with what it lacks added by us; OpenSSL for DTLS 1.0 |
| Modbus TCP | In netNIMA and in terNIMA, with the same code. Decided in November 2026 |
| Packet capture | libpcap's API: Npcap on Windows, the OS's own libpcap on Linux and macOS |
| Rights | A small helper program, `netnima-helper`, holds them. The app itself never runs as administrator or root |
| Capture files | pcapng, read and written; pcap read |
| Terminal engine | xterm.js |
| Charts | uPlot |
| License | Apache 2.0, like the other NimaLTD projects |
| Config format | TOML, in the OS's normal config folder |

---

## Why Rust and Tauri

The same reasons as terNIMA and bleNIMA: Tauri 2 makes a small, fast app with the same
UI on all three OSes, and Rust is where network code is safe and fast. Using the same
stack also means netNIMA starts from terNIMA's window, menus, tabs, themes, settings,
send box and views, and the apps look like one family.

Rust also has what netNIMA needs most: tokio for sockets, rustls for TLS with no C
library to build, a DTLS library, and bindings to libpcap, which every OS has in one
form or another.

---

## What it does

- **Sockets:** UDP, TCP, TLS and DTLS, each as a client and as a server, over IPv4 and
  IPv6, with terNIMA's views, send box, macros, log, record and replay
- **TLS of every kind:** TLS 1.0 to 1.3 and DTLS 1.0 to 1.3, with certificates or
  pre-shared keys, AES-GCM, AES-CCM and the rest, and DTLS's Connection ID, so old and
  small devices can be tested too
- **Protocols, both ends:** Telnet, MQTT, CoAP, LwM2M, HTTP, WebSocket, Modbus TCP,
  MCUmgr, TFTP, FTP, syslog, NTP, DNS, DHCP, mDNS, SSDP and iperf2 / zperf, each as a
  client and as a server, and in its secure form where it has one
- **Sniffer:** the packets on any interface, filtered, read layer by layer by the same
  code that speaks each protocol, and saved as pcapng for Wireshark

---

## Both ends on one PC

Each protocol has both ends in netNIMA. A client tab and a server tab on the same PC
talk to each other through the loopback, so every protocol can be tried, shown and
learned with no device. A device can be tested from either side: netNIMA as the broker
for a board's MQTT client, or as the client of a board's CoAP server.

- A server tab shows every peer, every request and every answer, as a client tab does
- A server answers from what you set: a table of Modbus registers, CoAP resources, HTTP
  routes, MQTT retained messages, DNS records, a folder for TFTP and FTP
- A server can also answer late, or not at all, to see how a device copes. It is a
  tester's server, not one for production

---

## The main window

terNIMA's window, with network tabs. File > New tab and the + button open a client, a
server or a capture tab.

```
+-------------------------------------------------------------------------+
| File  Edit  View  Connection  Capture  Tools  Help                      |  menu bar
+-------------------------------------------------------------------------+
| [+]  CoAP client *  |  MQTT broker *  |  Modbus slave *  |  Ethernet    |  tabs
+-------------------------------------------------------------------------+
| UDP to 192.168.1.50:5684, DTLS with PSK | Terminal Hex Lines Plot CoAP  |  toolbar
+-------------------------------------------------------------------------+
|                                                                         |
|   the view: terminal, hex, lines, plot or the protocol's own            |
|   (split into two panes if you like)                                    |
|                                                                         |
+-------------------------------------------------------------------------+
| > send box                [hex v] [Send]      macros: [reboot] [ver]    |
+-------------------------------------------------------------------------+
| Connected 00:03:12 | RX 4.1 KB, 37 datagrams | TX 812 B, 9 datagrams    |  status bar
+-------------------------------------------------------------------------+
```

A capture tab, below the same menu bar and tabs:

```
+-------------------------------------------------------------------------+
| Ethernet 2, promiscuous                                 Packets  Plot   |  toolbar
| filter: udp port 5683                                                   |
+-------------------------------------------------------------------------+
| No.   Time      Source        Destination   Proto Len  Info             |  packets
| 1042  3.201554  192.168.1.10  192.168.1.50  CoAP  61   CON GET /temp    |
| 1043  3.204120  192.168.1.50  192.168.1.10  CoAP  64   ACK 2.05 Content |
+-------------------------------------------------------------------------+
| > Ethernet II: Espressif_bb:cc -> 00:1c:3b:12:34:56                     |  layers
| > IPv4 192.168.1.50 -> 192.168.1.10, UDP 5683 -> 5683                   |
| v CoAP: ACK, 2.05 Content, MID 4711, token 3a, payload "21.5"           |
+-------------------------------------------------------------------------+
| 0000  00 1c 3b 12 34 56 24 6f  28 aa bb cc 08 00 45 00  ..;.4V$o(.....E.|  bytes
+-------------------------------------------------------------------------+
| Capturing 00:01:04 | 12,431 packets, 0 dropped | 1.2 MB to eth.pcapng   |  status bar
+-------------------------------------------------------------------------+
```

- The menu bar, its keys, the command palette (Ctrl+Shift+P), the two text sizes and
  split view are terNIMA's
- A server tab's status bar shows where it listens and how many peers it has
- Items that a later phase brings are listed already, greyed out with their phase

---

## Sockets

### UDP

- Send to an address and port, listen on a port, or both at once, over IPv4 or IPv6
- Each datagram is kept whole: one row in the Lines view with its time, peer and length,
  and its bytes in the hex view
- A listening tab hears from many peers. Each one is in the peer list, and the send box
  sends to the last one heard, to a chosen one, or to all
- Broadcast, and multicast: join a group on a chosen interface, with the TTL and whether
  our own datagrams come back
- Bind to an interface or a local address and choose the local port, for a device that
  only answers a fixed port
- "Port unreachable" shows as a marker line where the OS tells it. On Windows it makes
  the next read fail unless turned off, so netNIMA turns that off (`SIO_UDP_CONNRESET`)

### TCP

- Client: connects, waits for the other end, and connects again when it comes back, as
  terNIMA's TCP tabs do, with the same marker lines
- Server: listens and takes many clients at once, each in the peer list; send to one or
  to all, drop one
- Options: Nagle off (`TCP_NODELAY`), keep-alive, and closing with a reset instead of a
  FIN, to see how a device's stack takes it

### Telnet

- Client and server, with the option talk as terNIMA's Telnet does it (echo and no
  go-ahead yes, the rest no), kept out of the terminal

---

## TLS and DTLS

### What netNIMA speaks

| | TLS | DTLS |
|---|---|---|
| Versions | 1.0, 1.1, 1.2, 1.3 | 1.0, 1.2, 1.3 |
| Keys | certificates (RSA, ECDSA, Ed25519) or a pre-shared key (PSK) | certificates (ECDSA, and RSA through OpenSSL) or a PSK |
| Suites | AES-GCM, ChaCha20-Poly1305, AES-CCM and CCM_8, and for TLS 1.0 to 1.2 the old CBC and RSA ones | AES-GCM, ChaCha20-Poly1305, AES-CCM and CCM_8, and CBC through OpenSSL |
| Also | SNI, ALPN, mutual TLS, key logs | the Connection ID (RFC 9146), retransmissions shown, key logs |

### Engines

No one library speaks all of this, so a tab picks its engine:

- **rustls**, pure Rust, for TLS 1.2 and 1.3 with certificates. It is the default: it
  builds the same everywhere, and it is the most careful
- **dimpl**, pure Rust, for DTLS 1.2 and 1.3, with a PSK or certificates. We add what
  devices need and it lacks: the Connection ID (RFC 9146), which LwM2M devices on
  cellular links use, and `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8`, CoAP's suite for
  certificates. Upstream if its authors take them, in our own copy if not
- **OpenSSL 3**, built from its source into netNIMA, for what no Rust library speaks:
  TLS 1.0 and 1.1 and DTLS 1.0, PSK over TLS, AES-CCM over TLS, and the old CBC and RSA
  key exchange suites
- **Auto**, on every tab, picks the Rust engine when it can and OpenSSL when the version
  or the suites need it. The tab shows which engine it uses
- Writing our own TLS 1.0 to 1.2 in Rust in place of OpenSSL can be done. It is months
  of work, and it is the open question below

### On a tab

- The server's certificate checked against the OS's own roots, against a CA file of
  your own, or not at all for a test board's self-signed certificate, with a warning
  on the tab
- A client certificate and key for mutual TLS, PEM or DER; SNI and ALPN
- What was agreed, shown on the tab: engine, version, cipher suite, key exchange, ALPN,
  and the certificate chain with names, dates and fingerprints
- Choose the versions and suites a tab offers or accepts, old and weak ones included,
  to see what a device agrees to. TLS 1.0, 1.1 and DTLS 1.0 work in OpenSSL 3 only at
  its security level 0: netNIMA sets it on the one tab that asks, and says so there
- DTLS: the handshake shown step by step, with each flight's time and retransmissions,
  which is where DTLS goes wrong on a lossy link; the Connection ID, and whether the
  other end took it
- A key log (the `SSLKEYLOGFILE` format) per tab when asked, so the sniffer and
  Wireshark can read that tab's traffic
- Test certificates: Tools > Certificates makes a test CA, a server certificate for a
  board's name or IP address, and client certificates, as PEM files to put in firmware

A pre-shared key, a key file's passphrase or a password is asked each time and never
kept, as terNIMA does with SSH passwords.

---

## Protocols

Each protocol is a tab kind of its own, client or server, with the protocol's own view
beside terNIMA's Terminal, Hex, Lines and Plot.

| Protocol | Client | Server | Plain | Secure |
|---|---|---|---|---|
| Telnet | client | server | TCP 23 | |
| MQTT 3.1.1 and 5 | client | broker | TCP 1883, WebSocket | TLS 8883, WebSocket over TLS |
| CoAP | client | server | UDP 5683 | DTLS 5684 |
| LwM2M | client (a device) | server and bootstrap server | CoAP over UDP | CoAP over DTLS, with the Connection ID |
| HTTP/1.1 | client | server | TCP 80 | TLS 443 |
| WebSocket | client | server | over HTTP | over HTTPS |
| Modbus TCP | master | slave | TCP 502 | Modbus/TCP Security, TLS 802 |
| MCUmgr / SMP | client | a device | UDP 1337 | |
| TFTP | client | server | UDP 69 | |
| FTP | client | server | TCP 21 | FTPS: TLS asked for (AUTH TLS), or from the start on 990 |
| Syslog | sender | receiver | UDP 514, TCP | TLS 6514 |
| NTP / SNTP | client | server | UDP 123 | |
| DNS | client | server | UDP and TCP 53 | DNS over TLS 853 |
| DHCP | client | server | UDP 67 and 68 | |
| mDNS / DNS-SD | browse | advertise | UDP 5353 | |
| SSDP | search | answer | UDP 1900 | |
| iperf2 / zperf | client | server | TCP and UDP 5001 | |
| Wake-on-LAN | send | listen | UDP 9 | |
| Ping | ping | (the OS answers) | ICMP | |

### MQTT

- **Client:** MQTT 3.1.1 and 5, over TCP, TLS and WebSocket. Connect with a client ID,
  clean start, keep-alive, a user and password (asked each time), a will message, and
  MQTT 5's properties. Subscribe with wildcards and a QoS; publish with QoS 0, 1 or 2,
  retain, and MQTT 5's content type, response topic and user properties
- Messages in a list (time, topic, QoS, retain, size, payload) and in a topic tree with
  each topic's last value. Payloads as text, JSON, hex or CBOR; numbers in JSON payloads
  plotted by terNIMA's plot. Publish buttons, like terNIMA's macros, with a repeat time
- **Broker:** many clients at once, sessions, retained messages and wills, QoS 0, 1 and
  2, MQTT 5's topic aliases and session expiry, anonymous or with users, and client
  certificates over TLS. Every packet of every client in the list; a client can be
  dropped by hand
- One codec of our own, MQTT 3.1.1 and 5, for both ends

### CoAP

- **Client:** over UDP and DTLS. GET, POST, PUT, DELETE and FETCH, confirmable or not,
  with retransmission as RFC 7252 says. Observe (RFC 7641), each new value in the list
  and the plot. Block-wise transfers (RFC 7959) both ways. Discovery:
  `/.well-known/core` as a tree of the device's resources. Payloads as text, JSON, CBOR
  (in diagnostic notation) and SenML
- **Server:** resources made by hand (a path, a content format, a value or a file, and
  which methods it takes), Observe with new values on a timer or by hand, block-wise
  both ways, and `/.well-known/core` made from the resources

### LwM2M

- **Server:** a device registers, and its objects and instances show as a tree. Read,
  Write, Execute, Discover, Observe and attributes; a firmware update through object 5;
  SenML JSON and CBOR, and TLV. A bootstrap server too
- **Client:** netNIMA as a device with the objects you pick (Device, Connectivity,
  Firmware Update, IPSO sensors with made-up values), registering with a server,
  netNIMA's own or another
- Built on our CoAP, over UDP or DTLS with a PSK and the Connection ID. The objects come
  from OMA's registry, its licence checked first

### HTTP and WebSocket

- **HTTP client:** method, URL, headers and body, and the answer with its headers and
  how long each step took (DNS, connect, TLS, first byte)
- **HTTP server:** serves a folder, or routes made by hand (method, path, status,
  headers, body, a delay). Every request in the list with its headers and body. HTTPS
  with a certificate from Tools > Certificates
- **WebSocket client and server:** `ws://` and `wss://`, text and binary messages in the
  terminal, Lines and hex views, ping and pong, close codes, subprotocols. The server
  takes many clients and sends to one or to all

### Modbus TCP

- terNIMA's Modbus tester and its traffic view, on Modbus TCP tabs: a master and a
  slave. The frames are the same, with the MBAP header in front instead of RTU's
  address and CRC. Modbus RTU over TCP too, as many gateways send it
- Modbus/TCP Security: TLS on port 802, with client certificates and the role they
  carry, as the Modbus organization's security spec says
- In terNIMA too, with the same code

### MCUmgr / SMP

- **Client:** bleNIMA's MCUmgr view over UDP, as Zephyr's UDP transport serves it:
  image slots, upload with progress, test, confirm, reset, echo, and the update in one
  go
- **A device:** netNIMA answers SMP as a Zephyr device would (echo, the image list, an
  upload kept in a file, reset), to try the client, or other MCUmgr tools, with no board

### Services for boards

- **TFTP:** a server that serves a folder, read and write, with the block size,
  transfer size and window size options U-Boot uses, every transfer with its progress;
  and a client that gets and puts with the same options
- **FTP:** a server for a folder, anonymous or with users, passive and active, FTPS; a
  client that lists, gets, puts, renames and deletes. Every command and reply shown
- **Syslog:** a receiver on UDP, TCP and TLS that reads RFC 3164 and RFC 5424 into the
  Lines view, with filters by severity, facility, host and program; Zephyr's network
  log backend sends here, and its lines are filtered by level and module as terNIMA does
  with Zephyr logs. A sender with a chosen facility, severity, host and program, once
  or on a timer
- **NTP / SNTP:** a server that answers with the PC's time, or with a time set by hand
  (a year ahead, say, to test a device's clock), with a chosen stratum and leap flags;
  a client that shows the offset, delay, stratum and reference
- **DNS:** a client for any record type, to a chosen server, over UDP, TCP or TLS, with
  every section of the answer; a server that answers from a table of records and shows
  every query
- **DHCP:** a server that hands out addresses from a range, with the router, DNS and
  other options, to a board wired straight to the PC, with its leases and every message;
  a client that sends a DISCOVER on an interface and shows each server's offer

### Finding and measuring

- **mDNS / DNS-SD:** browse the services on the network (`_http._tcp`, `_mqtt._tcp`,
  `_coap._udp`, `_arduino._tcp` and others) with their addresses, ports and TXT records,
  one click opening a tab to one; and advertise a service of our own, so a device that
  looks for one finds it
- **SSDP:** search with M-SEARCH and see who answers; answer searches with a
  description made by hand
- **iperf2 / zperf:** a client and a server, UDP and TCP, the protocol Zephyr's zperf
  and ESP-IDF's iperf example speak: Mbit/s second by second in a chart, lost and out of
  order datagrams, and jitter
- **Ping**, IPv4 and IPv6, with the times and the losses; **Wake-on-LAN**, sent, and
  heard when another sends one
- **The PC's interfaces:** addresses, MAC address, MTU, up or down, and which are Wi-Fi

---

## Sniffer

- A capture tab listens on one interface or several. The interface list shows the names
  the OS shows ("Wi-Fi", "Ethernet 2", `en0`, `eth0`) and their addresses
- A capture filter in libpcap's own language (`udp port 5683`, `host 192.168.1.50`),
  checked as you type by libpcap itself
- Promiscuous mode, snap length and buffer size; the packets the OS dropped, counted and
  shown
- The Packets view, in three panes as in Wireshark: the list (number, time, source,
  destination, protocol, length, a line of what it is, and color rules), the selected
  packet's layers as a tree, and its bytes in terNIMA's hex view, with the selected
  field's bytes lit
- Millions of packets: they stay in the capture file and in Rust, and the UI asks for
  the rows it shows, as terNIMA's Lines view does
- A display filter with Wireshark's field names, so people already know it:
  `ip.addr == 10.0.0.5 && udp.port == 5683`, `mqtt`, `coap.code == 69`,
  `frame contains "ERR"`. A part of Wireshark's language first, more later
- Decoders: Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, ICMPv6 with neighbour discovery,
  UDP, TCP, TLS and DTLS (records, and the handshake: SNI, versions, suites,
  certificates), LLDP, IGMP and MLD, and every protocol above, read by the same code
  that speaks it
- Follow a TCP stream or a UDP flow: it opens in the terminal and hex views, each
  direction in its own color, as terNIMA shows sent and received bytes
- Statistics: conversations, endpoints and protocols; packets and bytes per second in
  the Plot view
- Files: save as pcapng, with comments; open pcapng and pcap files from Wireshark or
  tcpdump; save only the packets shown; Open in Wireshark when Wireshark is installed
- A long capture goes to pcapng files in the capture folder ("netNIMA captures" in
  Documents unless set), a new file by size, the oldest taken away past a limit
- Names: the maker of a MAC address (an ESP32 shows as Espressif), and the service on a
  port
- The TLS key logs of netNIMA's own tabs go into the pcapng file (its Decryption Secrets
  Block), so Wireshark shows that traffic decrypted

### Seeing a board's traffic

On a switched network a PC sees its own traffic, broadcasts and multicasts, but not a
board's traffic with others. To see all of it, the PC must be on the way: the board on
the PC's own hotspot or on a second network port, or a switch with a mirror port. The
help says how, as it is the first thing people trip over. Traffic between two netNIMA
tabs on one PC is seen on the loopback.

---

## Wi-Fi's low layers: not in this plan

Sniffing Wi-Fi itself (every 802.11 frame on a channel, with radiotap's channel, rate,
MCS, signal and noise) needs an adapter in monitor mode. The PC this plan was written on
cannot: for its Qualcomm Atheros QCA61x4A (driver 12.0.0.1257, from 2022), Windows says
"Network monitor mode: Not supported". The ways around it, a USB adapter on Linux, a
Raspberry Pi over SSH or an ESP32 as a sniffer, all need a device outside the PC, so
Wi-Fi sniffing is out of the plan. What was found, in case it comes back one day:

| | Windows | Linux | macOS |
|---|---|---|---|
| Monitor mode | Npcap installed with "Support raw 802.11 traffic (and monitor mode)", and an adapter whose driver offers it; many built-in ones do not | most mac80211 drivers (Atheros, MediaTek, Intel, some Realtek); not the Raspberry Pi's built-in Wi-Fi | the built-in Wi-Fi through libpcap, as `tcpdump -I`; reported unreliable on the newest Wi-Fi 7 Macs in macOS 26.3 |
| The channel | as Npcap's WlanHelper sets it | nl80211 | CoreWLAN |
| Radiotap | a few fields, no noise | signal; noise only per channel, from nl80211's survey | signal, noise, rate |
| Rights | administrator to switch | `CAP_NET_ADMIN` and `CAP_NET_RAW` | `/dev/bpf*` |

Capturing on a Wi-Fi interface as it is, not in monitor mode, works like any other
interface: the sniffer shows the PC's own Wi-Fi traffic as Ethernet frames.

---

## The hard parts

### TLS of every kind

- No one library speaks it all. rustls and dimpl are pure Rust and careful, but have no
  TLS 1.0 or 1.1, no PSK over TLS, no AES-CCM in TLS and no Connection ID. OpenSSL has
  all of these but the Connection ID (as far as we know: checked again when Phase 3
  starts), and it is C
- OpenSSL is built from its source into netNIMA (the `openssl` crate's vendored build),
  so nobody installs it. That needs Perl to build on Windows (GitHub's runners have it),
  two builds for the one macOS file, and a few MB more in the app
- The Connection ID and the CCM_8 certificate suite are ours to add to dimpl. If its
  authors do not take them, we keep our own copy of dimpl and follow theirs by hand
- Two engines behind one tab: both give the same events and the same details on screen,
  so a tab reads the same whichever engine it uses

### Capture: Npcap on Windows, libpcap on Linux and macOS

All three give libpcap's API: Linux and macOS have libpcap, and Windows has it through
Npcap's `wpcap.dll`. The `pcap` crate wraps it the same way on all three. The
differences are around it:

- **Npcap is not ours to ship.** Its free licence allows it on up to 5 systems and does
  not allow redistributing it, and its free installer cannot run silently. Putting it in
  our installer needs Npcap's paid OEM licence. So the user installs Npcap from
  npcap.com, as Wireshark's users do. netNIMA looks for it at start. Without it, every
  protocol works, and capture tabs say what to install, with the link
- **`wpcap.dll` must not be linked into the app.** A Windows program linked to it does
  not start at all on a PC without Npcap. Capture lives in the helper, which loads
  `wpcap.dll` from `System32\Npcap` only when it captures. The app always starts
- **Npcap's install options change what works.** "Restrict Npcap driver's access to
  Administrators only" makes every capture ask for administrator. netNIMA reads which
  options were chosen and says what to change
- **Names:** Npcap names an interface `\Device\NPF_{GUID}`. netNIMA shows Windows' own
  names ("Wi-Fi", "Ethernet 2"). Traffic to 127.0.0.1 is seen only through Npcap's
  loopback adapter
- **Building** on Windows needs the Npcap SDK for its `wpcap.lib`: CI downloads it.
  Linux needs `libpcap-dev`; macOS has libpcap in its SDK
- **Speed:** a busy link gives hundreds of thousands of packets a second. The helper
  writes every packet to the capture file first, and the UI only asks for what it
  shows. A slow UI never loses packets; when the OS's buffer overflows, the dropped
  count says so

### Permissions and elevated rights

| What | Windows | Linux | macOS |
|---|---|---|---|
| Clients | nothing | nothing | nothing, but macOS 15 and later ask once for Local Network access |
| A server on a port below 1024 (Telnet 23, DNS 53, DHCP 67, TFTP 69, HTTP 80, NTP 123, Modbus 502, syslog 514) | nothing | root or `CAP_NET_BIND_SERVICE`: the helper opens the port and hands it to the app | nothing (since macOS 10.14) |
| Taking connections in | Windows' firewall asks the first time | the firewall, if one is on | the macOS firewall, if it is on, asks |
| Capture | Npcap installed; administrator only if Npcap was installed for administrators only | `CAP_NET_RAW`, for the helper | read access to `/dev/bpf*`, which only root has out of the box |
| Ping | nothing (`IcmpSendEcho2`) | nothing on most distributions (ICMP datagram sockets), else `CAP_NET_RAW` | nothing |

The app never runs as administrator or root: a web view with those rights is a bad
idea. The rights go to the helper alone:

- **`netnima-helper`** is a small program with no window, the only part of netNIMA that
  needs rights, as Wireshark's `dumpcap` is for Wireshark. On Linux it opens server
  ports below 1024 and passes each open socket to the app over a Unix socket. On every
  OS it captures packets, writing pcapng to the app through a pipe and taking commands
  (stop) the other way
- **Linux:** the `.deb` and `.rpm` give the helper `cap_net_bind_service` and
  `cap_net_raw`, and let only the `netnima` group run it, as Wireshark's packages do
  with `dumpcap`; you join the group once and log in again. An AppImage cannot carry
  rights, so Tools > Set up rights asks for your password once (pkexec) and installs the
  helper with its rights under `/usr/local`; the app checks the helper's version and
  asks again after an update. Who would rather not have the helper can lower
  `net.ipv4.ip_unprivileged_port_start` themselves; the help says how
- **macOS:** low ports need nothing. For capture, `/dev/bpf*` belongs to root.
  Wireshark's ChmodBPF is a small launch daemon that gives the `access_bpf` group access
  each time the Mac starts. netNIMA does the same with the same group, so one setup
  serves both apps: Tools > Set up rights asks for the administrator's password once.
  With Wireshark's ChmodBPF installed there is nothing to do. Apple's newer way for
  helpers (`SMAppService`) needs a signed app
- **Windows:** low ports need nothing, and Npcap does the capture. The helper asks for
  administrator (UAC) only when Npcap was installed for administrators only
- **macOS's Local Network access:** macOS 15 and later ask once before an app reaches
  devices on the local network; until it is allowed, connecting to a board fails with
  "No route to host". The app says why it asks in its `Info.plist`
  (`NSLocalNetworkUsageDescription`). How this goes for an app that is not signed is to
  be tried on a Mac. terNIMA's TCP and SSH tabs meet the same

### Ports the OS holds

Some ports may already be taken by the OS's own services: on Windows, UDP 123 by Windows
Time and UDP 1900 by SSDP Discovery; on Linux, 127.0.0.53:53 by systemd-resolved; on
every OS, UDP 68 by the OS's own DHCP client, and UDP 5353 by its mDNS responder, which
can be shared. netNIMA names the program that holds a port where the OS tells it, and
offers to listen on one interface's address instead, or on another port. How a DHCP
client tab shares port 68 is tried on each OS.

---

## Views

Every tab can switch view at any time. A split shows two views side by side, of one tab
or of two, as in terNIMA, so a client and its server can be watched together.

- **Client and server tabs:** Terminal, Hex, Lines (one row per datagram or message, or
  per line on a stream) and Plot, as terNIMA's; and the protocol's own view (MQTT,
  CoAP, LwM2M, HTTP, Modbus, MCUmgr and the others)
- **Capture tabs:** Packets (the list, the layers and the bytes) and Plot (packets and
  bytes per second)

---

## Input

As terNIMA:

- Type into the terminal view, or use the send box: history, text or hex (`AA 55 01`),
  escapes such as `\r` and `\x03`, and the line ending
- Macros on Alt+1 to Alt+9, and sequences of them
- Send a file, paced. On UDP each send is one datagram, so a file goes in datagrams of a
  chosen size, with a pause between them

---

## Logging, record and replay

- Log to a file as terNIMA does: raw or text, with times, and markers for connect and
  disconnect
- Record and replay client and server tabs in terNIMA's recording format, with each
  message's peer added
- Capture tabs save pcapng, which is their recording

---

## Saving and restoring

As terNIMA: `settings.toml` (preferences) and `workspace.toml` (the tabs, each with its
settings, views, splits, macros and history, and the window's place and size), saved on
every change through a temporary file.

| OS | Folder |
|---|---|
| Windows | `%APPDATA%\com.nimaltd.netnima\` |
| Linux | `~/.config/com.nimaltd.netnima/` |
| macOS | `~/Library/Application Support/com.nimaltd.netnima/` |

Portable mode as terNIMA's: with a `netnima.portable` file next to the program, the
config goes into a `config` folder beside it.

```toml
[[session]]
name = "CoAP client"
kind = "coap-client"
view = "coap"

[session.coap]
transport = "dtls"
remote = "192.168.1.50:5684"
engine = "auto"
psk_identity = "esp32"   # the key itself is asked each time

[[session]]
name = "MQTT broker"
kind = "mqtt-broker"
view = "mqtt"

[session.mqtt_broker]
listen = ["0.0.0.0:1883"]
listen_tls = ["0.0.0.0:8883"]
certificate = "certs/broker.pem"
key = "certs/broker.key"
anonymous = true
```

### Finding the same interface again

A USB network adapter can come back under another name. A tab that listens on one
interface remembers its name and its MAC address, finds it by name and then by MAC, and
otherwise shows "Waiting for eth1..." and starts as soon as it is back, as terNIMA does
with serial ports.

---

## How it is built

### Layout

```
netNIMA/
  Cargo.toml              Rust workspace
  package.json            UI build (Vite)
  crates/
    netnima-core/         no UI: sockets, TLS, DTLS, every protocol's both ends,
                          decoders, the display filter, capture files, settings and
                          workspace. Tested on its own
    netnima-helper/       the only part with rights: low ports on Linux, and capture
                          with libpcap or Npcap, pcapng out through a pipe
  src-tauri/              the Tauri app: connects netnima-core and the helper to the UI
  ui/                     Svelte 5 + TypeScript + xterm.js + uPlot
  docs/                   this plan
  .github/workflows/      CI and releases
```

### How data flows

```
client and server tabs
  network -> socket -> TLS or DTLS -> session task -+-> log file, recording
                                                    +-> the protocol's codec and logic
                                                    +-> UI, about 60 times a second
  send box, macros, protocol views -> session task -> TLS or DTLS -> socket -> network

capture tabs
  adapter -> libpcap or Npcap -> netnima-helper -> pcapng through a pipe -> capture task
  capture task -+-> capture file (every packet, always)
                +-> index: each packet's time, place in the file and one-line summary
                +-> statistics -> UI, every 250 ms
  UI asks for rows -> index -> decoders -> rows; the selected packet decoded in full
```

- Each tab runs on its own task. Its read loop never waits for the UI or the disk
- A server tab runs one task that listens and one for each peer, and every message
  carries its peer's address
- Each protocol's codec is written once and used by its client, its server and the
  sniffer
- Packets stay in the capture file, with an index in Rust. A row's summary is decoded
  once; the selected packet's layers are decoded in full when it is selected
- The SMP protocol, the Modbus frames and the CBOR and value formats are TypeScript
  modules with no imports, taken from bleNIMA and terNIMA and tested by Node as they are

### Libraries

| Need | Library | Why |
|---|---|---|
| Async, sockets | `tokio` 1.54, `socket2` 0.6 | as terNIMA; `socket2` for what tokio does not reach: multicast on one interface, address reuse, TTL, `SIO_UDP_CONNRESET` |
| TLS 1.2 and 1.3 | `rustls` 0.23 and `tokio-rustls` 0.26, with `ring` | pure Rust, so the same on all three OSes; client and server, client certificates, key logs. `ring` and not its default `aws-lc-rs`, for the reason terNIMA has with russh: no NASM on Windows |
| TLS 1.0 and 1.1, PSK, AES-CCM; DTLS 1.0 | `openssl` 0.10, with OpenSSL 3 built in (`vendored`) | the one library with all of them together, and the best known for talking to odd devices; Apache-2.0 since OpenSSL 3.0 |
| DTLS 1.2 and 1.3 | `dimpl` 0.9, with its `rust-crypto` backend and our additions | PSK and ECDSA certificates, sans-IO so it runs inside our own session task, MIT or Apache-2.0, active (0.9.0 in October 2026) |
| The OS's roots | `rustls-platform-verifier` 0.7 | checks a server's certificate as the OS itself does |
| Certificates | `rcgen` 0.14, `x509-parser` 0.18 | makes the test CA and certificates; reads certificates for their details |
| MQTT | our own codec, client and broker | one codec for both ends, MQTT 3.1.1 and 5, so the client and the broker show every packet the same way |
| CoAP | `coap-lite` 0.13 | CoAP messages and options with no I/O of its own; the client's and the server's logic (retransmission, Observe, block-wise) are ours |
| LwM2M | our own, on our CoAP | no Rust library does both ends |
| HTTP | `hyper` 1.12, `hyper-util` 0.1 | client and server over our own TCP and TLS, so they use a tab's TLS settings and each step is timed |
| WebSocket | `tokio-tungstenite` 0.30 | client and server, `ws` and `wss` |
| DNS | `hickory-proto` 0.26 | DNS messages with every record type, for the client, the server and the sniffer |
| DHCP | `dhcproto` 0.15 | DHCP messages and options, pure Rust; the client and the server are ours |
| mDNS / DNS-SD | `mdns-sd` 0.21 | browse and advertise, pure Rust |
| Modbus TCP | terNIMA's Modbus code | the same frames and tests in both apps, with the MBAP header added |
| SMP and CBOR | bleNIMA's SMP code | the same MCUmgr view and tests, over UDP |
| Telnet | terNIMA's Telnet code | the option talk, for both ends |
| TFTP, FTP, syslog, NTP, SSDP, iperf2, ping, Wake-on-LAN | our own | small or text protocols; owning them means every message is shown, and a server answers as we want |
| Capture | `pcap` 2.5, in the helper | a thin wrapper of libpcap's API, which Npcap gives on Windows: BPF filters, timestamps; MIT or Apache-2.0 |
| Capture files | `pcap-file` 3 | reads and writes pcap and pcapng, also as a stream from the helper's pipe |
| Ethernet to TCP and UDP | `etherparse` 0.21 | fast, reads in place without copying, IPv6 extension headers; MIT or Apache-2.0 |
| TLS in captures | `tls-parser` 0.12 | the handshake, SNI, suites and certificates, from captured bytes |
| Windows | `windows` 0.62 | the adapters' names, `IcmpSendEcho2` |
| Interfaces | `netdev` 0.47 | interfaces, addresses, MAC, MTU, gateway and which are Wi-Fi, on all three |
| MAC makers, port names | the IEEE's OUI list and IANA's port list, built in | an ESP32 shows as Espressif, port 5683 as CoAP; their terms are checked before they go in |
| Config | `serde`, `toml` | as terNIMA |
| UI | Svelte 5, Vite, TypeScript, `@xterm/xterm`, `uplot` | as terNIMA |

Other options we looked at:

| Option | Why not |
|---|---|
| `rumqttc` 0.25 and `rumqttd` 0.20 | a client and a broker, each with its own codec; rumqttd is made for production setups. One codec of ours serves both ends and shows every packet the same way |
| mbedTLS (`mbedtls` 0.13) | what many devices run, with the Connection ID; but no TLS 1.0 or 1.1 since mbedTLS 3, and CMake and clang to build. Its test programs check our Connection ID on CI |
| wolfSSL | speaks all of it, but its GPL licence would make netNIMA GPL too |
| `webrtc-dtls` 0.12 | DTLS 1.2 only, async and tied to tokio; dimpl with our additions covers it |
| `libunftp` 0.25, `suppaftp` 12 | an FTP server and an FTP client with their own ways; FTP is a text protocol small enough to own, every line shown |
| `hickory-server` 0.26 | a full DNS server; ours answers from a table and shows every query |
| `sntpc` 0.11 | an SNTP client only |
| `tokio-modbus` 0.17 | good, but terNIMA's own Modbus code already does both ends, with tests |
| `async-tftp` 0.4 | runs on smol's executor, not tokio |
| `pnet` 0.35 | packets and capture in one, but on Windows it needs Npcap too, and it has no BPF compiler; `pcap` with `etherparse` covers more |
| Wireshark's decoders (tshark, sharkd) | GPL, and Wireshark would have to be installed; netNIMA writes pcapng and opens Wireshark for the rest |
| Wireshark's `dumpcap` as the helper | where Wireshark is installed, its rights are set up already; but netNIMA could not capture without Wireshark |

---

## Platform notes

- **Windows:** Windows' firewall asks the first time a tab listens. Some ports belong to
  Windows' own services. Npcap from npcap.com for capture. WebView2 is part of Windows
  10 and 11; the installer adds it if it is missing
- **Linux:** the `.deb` and `.rpm` set up the helper's rights and the `netnima` group;
  the AppImage asks once. Servers on ports below 1024 and capture go through the helper
- **macOS:** macOS 15 and later ask for Local Network access. Capture needs the BPF
  setup once (or Wireshark's ChmodBPF). Until we sign and notarize the app, the first
  start needs the `xattr` step that terNIMA's README gives

---

## Builds and releases

As terNIMA:

- **CI on every push and pull request:** `cargo fmt --check`, `cargo clippy` with
  warnings as errors, the tests on Windows, Linux and macOS, `npm run check`,
  `npm test`, and a build of the app. OpenSSL is built from its source every time
  (cached); Linux installs `libpcap-dev`, and Windows downloads the Npcap SDK, once the
  sniffer comes
- **Release on a tag** `vX.Y.Z`: GitHub Actions builds the installers and leaves them on
  a draft GitHub Release. A release after each phase or two, from 0.1.0, as bleNIMA did

| OS | Files |
|---|---|
| Windows | `.msi` and setup `.exe` |
| macOS | `.dmg` (one file for Apple Silicon and Intel) |
| Linux | `.AppImage`, `.deb`, `.rpm` |

The helper is in every installer, as a Tauri sidecar. For the macOS `.dmg` it is built
for both chips and joined into one file. The `.deb` and `.rpm` give it its rights as
they install. The release text says to install Npcap for capture on Windows.

No package is called `netnima` on crates.io, npm or the AUR (checked in November 2026),
so it can keep its name there.

---

## Testing

No device is needed for any test.

- Unit tests in `netnima-core`: every codec against the examples in its RFC or spec and
  against captured bytes; each client's and server's steps; the display filter; pcapng
  written and read back; settings and workspace
- **Both ends:** each protocol's client against its server, on the loopback, in CI on
  all three OSes, plain and secure
- **Against well-known others,** on Linux CI: Mosquitto (MQTT), libcoap (CoAP over UDP
  and DTLS), curl (HTTP and HTTPS), OpenSSL's `s_server` and `s_client` (TLS 1.0 to 1.3,
  PSK, AES-CCM, DTLS), mbedTLS's `ssl_server2` and `ssl_client2` (the Connection ID),
  dnsmasq (DNS, DHCP and TFTP), iperf 2, Avahi (mDNS), and small Python servers where
  they fit
- **Capture:** on Linux and macOS CI, whose runners allow `sudo`, the helper captures
  the traffic between two netNIMA tabs on the loopback. Windows CI has no Npcap (its
  free installer cannot run silently), so there only the decoders and files are tested,
  and capture is tried by hand
- A real board is welcome when there is one, and never needed

---

## Risks

- **Many protocols, both ends:** each one counts as done only when its two ends work
  together and each end works with a well-known other implementation
- **OpenSSL** is C inside the app, built from its source: Perl on Windows, two builds on
  macOS. Its old versions are there on purpose, at security level 0, on one tab at a
  time
- **DTLS in Rust is young,** and dimpl is made for WebRTC first. Our additions to it are
  checked against OpenSSL and mbedTLS before anything is built on them
- **Ports:** servers below 1024 on Linux need the helper, and the OS's own services hold
  some ports on every OS
- **Npcap** is the user's to install, its options decide what works, and its licence
  stops us from shipping it. netNIMA has to explain this well
- **macOS** asks for Local Network access, and helpers want a signed app
- **The Linux AppImage** cannot carry rights, so its servers on low ports and its
  capture need a one-time setup
- **Decoders:** Wireshark has thousands. netNIMA reads the protocols it speaks, well,
  and opens Wireshark for the rest
- **WebKitGTK on Linux** is slower than WebView2 and Safari; the packet list only ever
  holds the rows on screen
- **The law:** capturing other people's traffic is not allowed in many countries.
  netNIMA is for your own networks and devices, and the README and the help say so
- **Four apps with the same window code:** terNIMA, bleNIMA, libNIMA and netNIMA each
  have a copy, and a change such as the menu text size is made in each by hand. A shared
  package could come later

---

## Open question

1. **TLS 1.0 and 1.1, PSK over TLS and AES-CCM over TLS:** OpenSSL built into netNIMA
   (C, but ready, and the best known for odd devices), or our own TLS 1.0 to 1.2 engine
   in Rust (months of work, and ours to keep correct)? (OpenSSL, built in)

Answered in November 2026: Wi-Fi monitor mode is out, as nothing outside the PC is
used; the protocols come first, each with both ends; Rust wherever it can be; all of
TLS and DTLS, old versions, PSK, AES-CCM and the Connection ID included; Modbus TCP in
both apps; our own helper rather than Wireshark's `dumpcap`.

---

## Roadmap

The protocols come first, each with its client and its server. The sniffer comes after
them, and reads every protocol with the protocols' own code.

### Phase 0: skeleton

- [x] Plan
- [x] README, LICENSE.md, NOTICE, CHANGELOG, CONTRIBUTING
- [x] Rust workspace with `netnima-core`, `netnima-helper` and the Tauri app
- [x] terNIMA's window, menus, tabs, status bar, command palette, themes, fonts and the
  two text sizes, from bleNIMA's copy of them
- [x] New tab: every protocol in its group with its two ends; until its phase is built,
  a tab says what it will do and when it comes
- [x] A welcome page with the logo, the phase, and the helper the app found
- [x] `settings.toml` and `workspace.toml`, saved on every change
- [x] The helper beside the app in the installers (`npm run package`), found and run by
  the app. Tried on Windows
- [ ] CI on Windows, Linux and macOS, and the release workflow with the helper in every
  installer: written, not run on GitHub yet
- [x] The name checked: nothing called netnima on crates.io, npm or the AUR
  (November 2026)

Done when the installers from CI open the same window on all three OSes.

### Phase 1: UDP, TCP and Telnet

- [x] UDP tabs: send, listen or both; IPv4 and IPv6; peers; broadcast and multicast;
  a chosen interface and port
- [x] TCP clients that connect again by themselves, with marker lines, and servers with
  many clients
- [x] Telnet client and server
- [ ] Terminal, Hex, Lines and Plot views (done), and split view (not yet)
- [x] Send box, macros, sequences, sending a file
- [x] Log, record and replay
- [ ] Ports below 1024 on Linux, through the helper; the ports the OS holds, named
- [ ] Clear messages: a port in use, refused, unreachable, blocked by the firewall

Done when a UDP and a TCP client and server talk to each other on one PC, and it
replaces Packet Sender or Hercules for everyday work.

### Phase 2: TLS and DTLS in Rust

- [x] TLS clients and servers with rustls: the OS's roots, a CA of your own, or no
  check; client certificates, SNI, ALPN; what was agreed, and the chain
- [x] DTLS clients and servers with dimpl, with a PSK or certificates (the handshake
  step by step: not yet)
- [x] Key logs
- [x] Tools > Certificates

Done when netNIMA's TLS and DTLS clients and servers talk to each other and to
OpenSSL's, with certificates and, for DTLS, with a PSK.

### Phase 3: TLS for old and small devices

- [x] OpenSSL built in, and Auto choosing the engine on each tab, TLS and DTLS
- [x] TLS 1.0 and 1.1 and the old CBC and RSA suites; DTLS 1.0, through OpenSSL
- [x] PSK over TLS, TLS 1.2 and 1.3; over DTLS 1.0 and 1.2 with any PSK suite
- [x] AES-CCM and CCM_8 in TLS, and in DTLS: with a PSK through dimpl or OpenSSL, with
  ECDSA through OpenSSL (`ECDHE-ECDSA-AES128-CCM8` in the cipher list)
- [ ] The Connection ID (RFC 9146): neither dimpl nor OpenSSL 3.6 has it, so it is ours
  to add to dimpl, and to offer upstream

Done when TLS 1.0, PSK over TLS, an AES-CCM suite and DTLS with the Connection ID each
work between netNIMA's two ends, and against OpenSSL's or mbedTLS's.

### Phase 4: MQTT and CoAP

- [x] MQTT codec, 3.1.1 and 5
- [ ] MQTT client: TCP, TLS and WebSocket (done); the list and the topic tree (not yet); the plot (done, from the lines)
- [x] MQTT broker: sessions, retained messages, wills, QoS 0, 1 and 2, users, TLS, WebSocket
- [x] CoAP client: confirmable, Observe, block-wise, discovery, over UDP and DTLS, and
  over TCP, TLS and WebSocket (RFC 8323)
- [x] CoAP server: resources made by hand, Observe, block-wise, over UDP and DTLS, and
  over TCP, TLS and WebSocket
- [x] MQTT-SN 1.2: a client, and a gateway with a broker inside

Done when netNIMA's MQTT client and broker, and its CoAP client and server, work with
each other and with Mosquitto and libcoap, plain and secure.

### Phase 5: HTTP and WebSocket

- [x] HTTP client, with each answer timed
- [x] HTTP server: a folder, or routes made by hand
- [x] WebSocket client and server
- [x] All of them over TLS too

Done when netNIMA's HTTP and WebSocket clients and servers work with each other, with
curl and with a browser on the same PC, plain and over TLS.

### Phase 6: Modbus TCP and MCUmgr

- [x] Modbus TCP master and slave (written here: terNIMA was not to be changed); Modbus RTU over TCP
- [x] Modbus/TCP Security on port 802: Modbus over TLS, with client certificates
- [x] MCUmgr client over UDP (written here: bleNIMA has no SMP code)
- [x] An SMP device that answers as Zephyr would

Done when the Modbus master and slave poll each other over TCP and TLS, and the MCUmgr
client updates netNIMA's own SMP device.

### Phase 7: LwM2M

- [ ] LwM2M server (done: registration, Read, Write, Execute, Discover, Observe,
  attributes, bootstrap server, firmware pushed in blocks); the object tree (not yet)
- [ ] LwM2M client: a device with the Server, Device, Firmware Update, Temperature and
  Light Control objects, that can bootstrap first (done); objects picked (not yet)
- [ ] TLV, SenML JSON, SenML CBOR and CBOR over UDP and DTLS with a PSK (done); the Connection ID (not yet)

Done when netNIMA's LwM2M client registers with its LwM2M server over DTLS with a PSK
and the Connection ID, and the server reads, writes, observes and updates its firmware.

### Phase 8: services for boards

- [x] TFTP client and server
- [x] FTP client and server, passive mode, and FTPS: explicit (AUTH TLS) and implicit,
  with PROT P
- [x] Syslog sender and receiver over UDP, TCP and TLS, and Zephyr's logs filtered by
  level and module
- [x] NTP / SNTP client and server
- [x] DNS client and server over UDP, TCP and TLS
- [x] DHCP client and server
- [x] SNMP v1 and v2c: a manager that gets, walks, bulks and sets and shows traps, and an
  agent with the system group that sends traps

Done when each service's client and server work with each other, and with dnsmasq's DNS,
DHCP and TFTP.

### Phase 9: finding and measuring

- [x] mDNS / DNS-SD: browse and advertise
- [x] SSDP: search and answer
- [x] iperf2 / zperf client and server, over TCP and UDP
- [x] Ping (IPv4) and Wake-on-LAN
- [x] Echo (RFC 862) over TCP and UDP, client and server, as Zephyr's echo samples
- [x] STUN (RFC 8489) client and server
- [x] The PC's interfaces: Tools > The PC's interfaces

Done when netNIMA finds the service it advertises itself and its own SSDP answer, and
its iperf2 client and server measure each other and iperf 2.

### Phase 10: sniffer

- [ ] Capture in the helper: interfaces, capture filter, pcapng through a pipe, drops,
  stop
- [ ] Npcap found and its options read; the rights for capture on each OS
- [ ] The Packets view: list, layers and bytes, for millions of packets
- [ ] Decoders: Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, ICMPv6, UDP, TCP
- [ ] pcapng and pcap saved and opened, capture files by size, Open in Wireshark
- [ ] The loopback on every OS

Done when the traffic between two netNIMA tabs is captured on all three OSes, with the
app running as a normal user.

### Phase 11: reading the traffic

- [ ] Every protocol above decoded with its own codec; TLS, DTLS, LLDP, IGMP and MLD
- [ ] Display filter
- [ ] Follow a stream or a flow in the terminal and hex views
- [ ] Conversations, endpoints and protocols; packets and bytes per second in the plot
- [ ] Our own TLS tabs' key logs in the pcapng file
- [ ] MAC makers and port names

Done when one MQTT session can be found and read in a busy capture in seconds.

### Phase 12: 1.0

- [ ] 1.0.0 for Windows, macOS and Linux, not signed yet
- [ ] Help pages on the website, linked from the Help menu, the About box and the README
- [ ] Code signing on Windows and macOS (later)

### Later

- [x] MQTT-SN, client and gateway (brought into Phase 4)
- [x] CoAP over TCP and WebSocket (RFC 8323), brought into Phase 4
- [ ] HTTP/2
- [x] SNMP v1 and v2c, manager and agent (brought into Phase 8); SNMPv3 (not yet)
- [ ] NTS, NTP's secure form
- [ ] Sending crafted Ethernet frames
- [ ] winget, Homebrew and Flathub
- [ ] Scripting (Rhai or Lua) for tests
