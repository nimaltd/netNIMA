# 🌐 netNIMA

[![CI](https://github.com/nimaltd/netNIMA/actions/workflows/ci.yml/badge.svg)](https://github.com/nimaltd/netNIMA/actions/workflows/ci.yml)
[![Stars](https://img.shields.io/github/stars/nimaltd/netNIMA?style=social)](https://github.com/nimaltd/netNIMA)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE.md)

A network tester for embedded developers: UDP, TCP, TLS and DTLS, and the protocols on top of them, each one as a client and as a server, the same on Windows, macOS and Linux.

The name is "net" with my name, Nima, in it: net-NIMA. It is terNIMA's and bleNIMA's sister: the same look, the same menus and tabs, for the network.

---

## ⬇️ Download

netNIMA for Windows, macOS and Linux is on the [Releases](https://github.com/nimaltd/netNIMA/releases/latest) page:

| OS | File |
|---|---|
| Windows 10 and 11, x64 | the `-setup.exe` installer, or the `.msi` |
| macOS, Apple Silicon and Intel | the `.dmg` |
| Linux, x64 | the `.AppImage`, or the `.deb` or `.rpm` |

The apps are not signed yet, so the first time:

- **Windows** may say "Windows protected your PC": click **More info**, then **Run anyway**. The first tab that listens, such as a server, makes Windows Firewall ask whether other devices may reach netNIMA: allow it on the networks your boards are on.
- **macOS** may say the app is damaged or cannot be checked: move it to Applications, then run `xattr -cr /Applications/netNIMA.app` in Terminal. It asks once to find devices on your local network: allow it.
- **Linux**: make the AppImage runnable with `chmod +x`. A server on a port below 1024, such as DHCP on 67 or Modbus on 502, needs root for now.

What changed in each version is in [CHANGELOG.md](CHANGELOG.md).

---

## 🚧 Where it is

netNIMA is young: 0.1.0 is its first release. Phases 1 to 9 of the [plan](docs/PLAN.md) are built, but for a few items it lists, and the sniffer comes next. What works now, each with both ends:

- **Sockets:** UDP (with broadcast and multicast), TCP and Telnet, clients and servers
- **TLS 1.0 to 1.3:** clients and servers, with certificates checked or not, client certificates, ALPN and a key log for Wireshark; pre-shared keys, the AES-CCM suites and the old CBC suites through a built-in OpenSSL; test certificates made in the app
- **DTLS 1.0 to 1.3:** clients and servers with certificates, or a pre-shared key with AES-128-CCM-8; DTLS 1.0, the other PSK suites and any cipher list through the built-in OpenSSL
- **Protocols:** MQTT 3.1.1 and 5.0 (client and broker, over TCP, TLS and WebSocket), MQTT-SN (client and gateway), CoAP and CoAPS (with Observe and block-wise, over UDP, DTLS, TCP, TLS and WebSocket), Echo over TCP and UDP (timed round trips), STUN, SNMP v1 and v2c (manager and agent), LwM2M (server and device, TLV and SenML, bootstrap and firmware update), Modbus TCP and RTU over TCP (master and slave), MCUmgr over UDP (with firmware upload), HTTP and HTTPS, WebSocket (ws and wss), iperf2 / zperf over TCP and UDP, mDNS / DNS-SD, SSDP, DHCP, Ping, FTP and FTPS, Syslog and DNS over UDP, TCP and TLS, NTP, TFTP and Wake-on-LAN
- **The PC's interfaces:** every network card with its addresses, MAC address, gateway, DNS servers and traffic, in the Tools menu

A protocol tab opens on a form: pick a command, fill in its boxes and send. Text takes the same commands typed, such as `pub sensors/temp 21.5`, and lists them as you type. MQTT, CoAP, HTTP, LwM2M, MCUmgr and Modbus open on views of their own, with each request in a row and its answer under it.

---

## ✨ What it will do

- **Both ends on one PC:** every protocol has a client and a server in netNIMA, so each one can be tried with no device, and a device can be tested from either side
- **Sockets:** UDP, TCP and Telnet, with terNIMA's terminal, hex, lines and plot views, send box, macros, log, record and replay
- **TLS of every kind:** TLS 1.0 to 1.3 and DTLS 1.0 to 1.3, with certificates or pre-shared keys, AES-GCM and AES-CCM, and DTLS's Connection ID, so old and small devices can be tested too
- **Protocols:** MQTT (client and broker), CoAP, LwM2M, HTTP, WebSocket, Modbus TCP, MCUmgr, TFTP, FTP, syslog, NTP, DNS, DHCP, mDNS, SSDP and iperf2 / zperf, plain and secure
- **Sniffer:** the packets on any interface, read layer by layer by the same code that speaks each protocol, and saved as pcapng for Wireshark

---

## 🛠️ Building it

netNIMA is written in Rust and TypeScript with [Tauri](https://tauri.app), like terNIMA. With Rust, Node.js and Tauri's prerequisites installed:

```bash
npm install
npm run tauri dev
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists what to install on each OS, how to make the installers, and the checks CI runs.

---

## 🤝 Contributing

Bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Nothing to sign, just open a pull request.

---

## 💖 Support

I write these tools in my own time and give them away, because good tools should be easy to get. If this one saved you an afternoon, there are two things that genuinely help:

**⭐ Star the repo.** It costs you one click, it helps other engineers find the project, and it is the main reason I keep going.

**☕ [Buy me a coffee on Ko-fi](https://ko-fi.com/nimaltd).** Any amount is a real motivation to keep writing, documenting and maintaining this work.

[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/NimaLTD)
[![YouTube](https://img.shields.io/badge/YouTube-Subscribe-red?style=for-the-badge&logo=youtube)](https://youtube.com/@nimaltd)
[![Instagram](https://img.shields.io/badge/Instagram-Follow-purple?style=for-the-badge&logo=instagram)](https://instagram.com/github.nimaltd)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/nimaltd)
[![Email](https://img.shields.io/badge/Email-Contact-red?style=for-the-badge&logo=gmail)](mailto:nima.askari@gmail.com)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-orange?style=for-the-badge&logo=ko-fi)](https://ko-fi.com/nimaltd)

---

## 📜 License

Apache License 2.0. See [LICENSE.md](LICENSE.md).

You are free to use this in commercial and closed source products. What the license asks in return is that you keep the copyright notice and pass along the [NOTICE](NOTICE) file, so the credit travels with the code.
