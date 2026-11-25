# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The Welcome tab stays first in the tab bar while tabs are open, and a click
  brings it to the front again. It has no close button.

## [0.1.2] - 2026-11-25

### Added

- The welcome page has a Donate card at the right: PayPal and Ko-fi, each
  with a QR code for a phone and a link that opens in the browser.

## [0.1.1] - 2026-11-17

### Changed

- The menu text size starts at 13 pixels, where nothing is zoomed, and
  View > Normal menu text size goes to 13; in 0.1.0 both were 16. A size
  chosen in Settings stays as it is.

## [0.1.0] - 2026-11-16

### Added

- The plan, in docs/PLAN.md: what netNIMA will do, what it is built with, the
  hard parts, and the roadmap, phase by phase.
- The window, as terNIMA's: its own menu bar (File, Edit, View, Connection,
  Capture, Tools, Help) with Alt+letter and the arrow keys, tabs with Ctrl+Tab,
  a status bar, the command palette (Ctrl+Shift+P), dark and light themes that
  can follow the OS, the Inter and JetBrains Mono fonts built in, and the two
  text sizes: one for the menus, tabs, buttons and dialogs, and one for the
  views. Menu items that a later phase brings are there already, greyed out
  with their phase.
- A welcome page with the logo, where netNIMA is going, and the helper it
  found.
- New tab (Ctrl+Shift+N, Cmd+N on macOS, or the + button): every protocol in
  its group, with its two ends, such as an MQTT client and an MQTT broker, on
  a line for each transport when it has more than one, as CoAP has for UDP,
  TCP and WebSocket. Until its phase is built, a tab says what it will do and
  when it comes. The command palette opens every kind of tab too.
- `settings.toml` and `workspace.toml` in the OS's config folder, saved on every
  change. The tabs, and the window's place and size, come back when netNIMA
  starts again. A broken file is kept as `.bad.toml`.
- Settings: theme, both text sizes, what comes back at start, and looking for a
  new version on GitHub when netNIMA starts.
- `netnima-helper`, the small program that will hold the rights the app itself
  never asks for. It is in every installer, beside the app, and for now it says
  its version.
- CI on Windows, macOS and Linux, and a release workflow that makes the
  installers from a tag.
- UDP tabs: listen, send, or both, on any address and port, with broadcast,
  multicast groups on IPv4 and IPv6, TTL and a shared port. Each datagram
  stays whole, on a line of its own, with the peer it came from.
- TCP and Telnet clients and servers. A client connects again by itself when
  the other end goes away, and can end with a reset. A server takes many
  clients: the send box sends to one, to all, or to the one heard from last,
  and a client can be dropped. Telnet's option talk is answered and kept out
  of what is shown.
- terNIMA's views in every tab: the terminal, hex, lines with each line's time,
  direction and peer, and the plot of the numbers in the lines; the send box
  with history, macros and sequences; highlights; the log, the recording
  (`.nrec`, which plays terNIMA's `.trec` too) and sending a file.
- TLS clients and servers, TLS 1.2 and 1.3 with rustls: the certificate
  checked against the PC's trusted ones or a CA file, or not at all; the name
  asked for (SNI) and checked, or not; client certificates asked for,
  required, or any taken to see what a device sends; ALPN; a key log for
  Wireshark. What the two ends agreed and the other end's certificates are
  shown, and TLS errors are said in words, with what to try.
- A second TLS engine for old and small devices: OpenSSL 3, built into
  netNIMA. It speaks TLS 1.0 and 1.1 with the old CBC and RSA suites,
  pre-shared keys (PSK) over TLS 1.2 and 1.3, the AES-CCM suites, and any
  cipher list in OpenSSL's names. A tab picks it by itself when its settings
  need it, or it can be chosen; rustls stays the engine for the rest. Both
  engines talk to each other, and protocols over TLS, such as MQTT, use it too.
- DTLS clients and servers, with dimpl in pure Rust: DTLS 1.2 and 1.3 with
  ECDSA certificates, and DTLS 1.2 with a pre-shared key and AES-128-CCM-8, as
  CoAP and LwM2M devices use. A client handshakes again when its connection
  ends; a server takes many clients, with a cookie first and client
  certificates if asked. CoAP and LwM2M run over DTLS too.
- DTLS through OpenSSL as well, for old and small devices: DTLS 1.0 and 1.2,
  pre-shared keys with any PSK suite (CBC, CCM, CCM_8), RSA certificates, and
  any cipher list in OpenSSL's names, such as an ECDSA CCM_8 suite. A tab
  picks it by itself for DTLS 1.0 or a cipher list, or it can be chosen under
  "For old and small devices"; dimpl stays the engine for the rest, and the
  two talk to each other.
- netNIMA's own server certificate, made for the PC's names and addresses and
  kept, for TLS servers with none chosen; Tools > Certificates shows it and
  makes test sets: a CA with a server's and a client's certificate, as PEM,
  DER and a `certs.h` of C arrays for firmware.
- Tools > The PC's interfaces: every network card of the PC, its own cards
  first, each with its IPv4 and IPv6 addresses and their prefixes, whether
  DHCP gave them, its MAC address, MTU, link speed, gateway and DNS servers,
  whether it is up, Wi-Fi or virtual, and which one has the default route;
  and the bytes it took and sent, in all and a second. It is read again
  every two seconds, so a cable plugged in shows. A click on an address
  copies it, and Copy takes a card as text. An address of 169.254 is said
  for what it is: no DHCP server answered. In a tab's settings, the
  addresses of cards that are down are marked, and a DHCP server's own
  address is offered from the PC's.
- Protocol tabs, each driven by its commands, with every message shown as a
  line, both ends of each. The send box has a form for them, which a
  protocol tab opens with: the command from a menu, then a field for each
  thing it takes: boxes for its values, a check box for a flag such as
  retain, a list for a choice such as the QoS, and its data as text or hex.
  Under the form, what the command does and the line it sends. Text, the
  other choice, takes the same line typed: its first letters list the
  commands that fit, with what each takes and does, and Tab puts one in the
  line; once it is there, how it goes on shows above the line. A right-click
  or Ctrl+Space lists them all, with the protocol's notes, and `help` lists
  them in the tab:
  - MQTT 3.1, 3.1.1 and 5.0: a client that publishes and subscribes with QoS 0,
    1 and 2, retains, keeps alive and has a will; a broker with retained
    messages, wills, topic aliases, a user name and password, and its own
    publishing. Both run over TLS too, and over WebSocket (ws and wss): the
    client upgrades on a path such as /mqtt, and the broker takes WebSocket
    and plain clients on the same port. Both open on an MQTT view: messages
    to publish in rows, each with its topic, QoS, Retain and payload as text
    or hex, its Publish, and when it was delivered; a client's
    subscriptions, made again each time it connects, with what the broker
    granted; a broker's clients with what they subscribed to, and its
    retained messages; and every topic heard with its last value, and a
    topic's last messages as text, JSON or hex.
  - CoAP over UDP: a client with confirmable requests sent again until
    answered, Observe, block-wise responses followed to their end, and
    discovery; a server with resources to GET, PUT, POST, DELETE and observe.
    Both run over TCP, TLS and WebSocket too (RFC 8323), with CSM, Ping and
    Pong. Both open on a CoAP view: a client's requests in rows, each with its
    method or Observe, path, formats, NON, and payload as text or hex, its
    Send, and the answer under it with its code, time and format, and each
    change while observed; Discover lists the server's resources, each ready
    to get or observe. A server's view has its resources to change, add and
    remove, and the requests it heard with what it answered.
  - MQTT-SN 1.2 over UDP: a client that registers topics, publishes with QoS
    -1 to 2 and subscribes, and a gateway with a broker inside that its
    clients publish to each other through, with wills and retained messages.
  - SNMP v1 and v2c: a manager that gets, walks, bulks and sets, with
    Net-SNMP's type letters, and shows traps and answers informs; and an
    agent with the system group and a board's values, that sends traps.
  - Modbus TCP, in terNIMA's Modbus view rather than commands: a master's
    requests in rows, each with its unit, function, address and count or
    values, its Send and its Poll, and the values it got under it, as
    unsigned, signed, hex or float; a scan for the units that answer; and a
    slave's four tables to fill in, which answer each master that connects
    on its own connection, and which the masters' writes change, with
    Stop answering to see what a master does with no answer. A Traffic page
    lists every frame, each response under its request with the time it
    took. Plain Modbus TCP, or RTU or ASCII frames over TCP as gateways pass
    them on; over TLS too.
  - LwM2M 1.1: a server that devices register with, and that reads (TLV,
    SenML JSON, SenML CBOR, CBOR or text), writes, executes, discovers and
    observes them; and a
    device with the Server, Device, Firmware Update, Temperature and Light
    Control objects, whose temperature changes for the observers. Over UDP
    or DTLS with a PSK. The server is a bootstrap server too when given the
    address to hand out, and pushes firmware to /5/0/0 in blocks; the device
    can bootstrap first, then registers where it is told, and takes the
    firmware, its version read from the MCUboot header, and updates to it.
    Both open on an LwM2M view: a server's devices, each with the seconds
    left of its lifetime; the chosen one's objects and resources by their
    names, each value as it was read and what it means, such as a firmware
    state's name, to write, read again, observe and execute; a bar for any
    path, with Discover and attributes; firmware to push from a file, with
    its progress, or an address for the device to fetch it from, then
    Update; and every request with its answer, and each one a device made.
    A device's view says whether it is registered, with Register, Update,
    Deregister and Bootstrap, and lists its resources to change, marked
    when the server observes them, and every request the server made.
  - MCUmgr over UDP, as Zephyr serves it: a client for echo, info, taskstat,
    params, images, firmware upload with the image's MCUboot version, test,
    confirm, erase and reset; and a simulated Zephyr device that answers them.
    Both open on an MCUmgr view: a client's Info, Params, Datetime, Echo and
    Reset; the board's threads with how much of each stack is used; its
    images with their versions, hashes and flags, to test and confirm, and
    Erase; an image to upload, with its progress and speed; and every
    request with its answer. The simulated device's view has its images, an
    upload coming in, and every request it heard.
  - iperf2 and zperf throughput over TCP and UDP: a client that sends at a
    rate for a while, and a server that counts each second, with losses,
    jitter and the server's report on UDP.
  - mDNS / DNS-SD: browse the services on the network, and advertise one of
    our own; SSDP: search for UPnP devices, and answer as one.
  - DHCP: a server that gives addresses from a pool, for a board wired
    straight to the PC, and a client that asks a server for one and shows
    what it was given, without changing the PC's own address.
  - Ping, with times, losses and TTLs: through Windows' ICMP API, which needs
    no rights, and an ICMP datagram socket on Linux and macOS.
  - Echo (RFC 862) over TCP and UDP, as Zephyr's echo_server and
    echo_client samples speak it: a server that sends back what comes, and a
    client that sends a line or a test of many messages, checks each echo
    byte for byte, and times each round trip on its own thread.
  - STUN (RFC 8489): a client that asks a server the address and port a NAT
    gives it, and a server that answers with XOR-MAPPED-ADDRESS.
  - FTP: a client that logs in, lists, gets and puts files, and a server
    that serves a folder, both in passive mode. With TLS on, FTPS: explicit,
    with AUTH TLS on a plain connection, or implicit, as on port 990, and
    PROT P so files and listings go in TLS too. The data connections take up
    the control connection's TLS session, as servers such as vsftpd want.
  - HTTP/1.1 clients and servers, plain or HTTPS: requests with headers and
    bodies, responses by length or in chunks; a server with routes made by
    hand, an echo, and a folder of files. Both open on an HTTP view: a
    client's requests in rows, each with the response under it, its status,
    time, type, headers and body, laid out when it is JSON, and the headers
    every request has; a server's routes to add and drop, and the requests
    it answered.
  - WebSocket clients and servers, ws and wss: text, binary, ping and close.
  - Syslog (RFC 3164 and 5424), NTP, DNS, TFTP (with blksize and tsize, for
    U-Boot) and Wake-on-LAN, each with both ends. Syslog also over TCP and
    TLS (RFC 6587 and 5425: each message with its length in front, or one a
    line), and DNS over TCP and TLS (DNS over TLS, on port 853). A syslog
    receiver filters by level, and by module: Zephyr's, as in
    `<inf> net_dhcpv4: ...`, or else the app name.

### Fixed

- On Windows, a UDP tab could lose a datagram that came just as its read
  waited out; it now waits for datagrams with poll instead.
- Saving a tab's settings could say for a moment that its port was in use:
  the new socket opened before the old one had closed. The old one now
  closes first.
- What a tab sent, and every answer a protocol tab gave, could wait up to
  16 ms on Windows (10 ms elsewhere) before it went out, until the socket
  next looked at what it was asked; round trips and answer times showed that
  wait. Each socket is now woken the moment it has something to send: an
  Echo round trip on the PC itself takes 0.1 ms, not 16.
- A big send over TCP to a slow device could fail after 5 s while the device
  was still taking it, and a TCP client could hang on one that took nothing.
  A write now waits as long as the other end keeps taking bytes, and gives up
  after 5 s with nothing taken.
- In a protocol tab, a `\n` in a payload ended the command there, and `\xHH`
  of 80 or more came out as other bytes: the send box turned the escapes into
  bytes before the protocol read the line. A protocol tab's line now goes as
  it is typed, and the protocol turns the escapes in a payload into its bytes,
  as its help says; a syslog message takes them too.
- A CoAP client took a format only written onto its flag, as in `-ajson`,
  though its help writes `-a json`. It takes both now, as LwM2M and iperf do.
- An LwM2M server's `cancel` forgot the observations of that path on every
  device, not only on the one named, so the others' changes came without
  their path. And a device's registration update that brought a new
  lifetime, binding or list of objects was taken without them: the server
  went on counting down the old lifetime.

[Unreleased]: https://github.com/nimaltd/netNIMA/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/nimaltd/netNIMA/releases/tag/v0.1.2
[0.1.1]: https://github.com/nimaltd/netNIMA/releases/tag/v0.1.1
[0.1.0]: https://github.com/nimaltd/netNIMA/releases/tag/v0.1.0
