<script lang="ts">
  import { onMount, untrack } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import FileField from "./FileField.svelte";
  import type { Interface } from "./interfaces";
  import Modal from "./Modal.svelte";
  import {
    DEFAULT_DTLS,
    DEFAULT_TLS_CLIENT,
    DEFAULT_TLS_SERVER,
    dtlsOverOpenssl,
    portProblem,
    type DtlsOptions,
    type TcpClientConfig,
    type TcpServerConfig,
    type TlsClientOptions,
    type TlsServerOptions,
    type UdpConfig,
  } from "./net";
  import { endOf } from "./new-tab";
  import { setupOf } from "./protocols";
  import type { Tab } from "./tabs.svelte";
  import type { LineEnding, TerminalOptions } from "./types";

  // A tab's settings: where its socket listens or connects, and how its
  // terminal sends and shows. A new tab opens with it, and starts on Save.
  let { tab, starting = false, onclose }: { tab: Tab; starting?: boolean; onclose: () => void } = $props();

  // Copies of the tab's settings as the dialog opens: nothing changes until Save.
  const before = untrack(() =>
    $state.snapshot({
      udp: tab.udp,
      client: tab.client,
      server: tab.server,
      terminal: tab.terminal,
      protocol: tab.protocol,
      dtls: tab.dtls,
    }),
  );
  /** A protocol tab's setup, with its own fields; undefined for a socket tab. */
  const protocolSetup = setupOf(untrack(() => tab.kind));
  let options: Record<string, unknown> = $state({ ...before.protocol });
  /** Whether a protocol that can run over TLS does. */
  let overTls = $state(Boolean(before.client.tls || before.server.tls));
  let dtls: DtlsOptions = $state({ ...DEFAULT_DTLS, ...before.dtls });
  /** Whether a protocol that can run over DTLS does. */
  let overDtls = $state(Boolean(before.dtls));
  /** A DTLS tab, or a protocol over DTLS. */
  const showsDtls = $derived(
    tab.kind === "dtls_client" || tab.kind === "dtls_server" || (protocolSetup?.dtlsPort !== undefined && overDtls),
  );
  /** Whether this end is DTLS's client, which checks the server's certificate. */
  const dtlsClient = $derived(tab.kind.endsWith("_client"));
  /** Whether the DTLS settings make the tab use OpenSSL rather than dimpl. */
  const dtlsOpenssl = $derived(dtlsOverOpenssl(dtls));
  let udp: UdpConfig = $state(structuredClone(before.udp));
  let client: TcpClientConfig = $state({ ...before.client });
  let server: TcpServerConfig = $state({ ...before.server });
  let tlsClient: TlsClientOptions = $state({ ...DEFAULT_TLS_CLIENT, ...before.client.tls });
  let tlsServer: TlsServerOptions = $state({ ...DEFAULT_TLS_SERVER, ...before.server.tls });
  const CERTIFICATES = [{ name: "Certificates", extensions: ["pem", "crt", "cer", "der"] }, { name: "Every file", extensions: ["*"] }];
  const KEYS = [{ name: "Keys", extensions: ["key", "pem", "der"] }, { name: "Every file", extensions: ["*"] }];
  const KEY_LOGS = [{ name: "Key logs", extensions: ["log", "txt"] }];
  let terminal: TerminalOptions = $state({ ...before.terminal });
  let multicast = $state(Boolean(before.udp.multicast?.group));
  let interfaces: Interface[] = $state([]);
  let error = $state("");

  onMount(() => {
    invoke<Interface[]>("list_interfaces")
      .then((found) => (interfaces = found))
      .catch(() => (interfaces = []));
  });

  /** Every address of this computer, for a tab to listen on, with its interface's name, and whether it is down. */
  const localChoices = $derived(
    interfaces.flatMap((entry) =>
      [...entry.ipv4, ...entry.ipv6].map((address) => ({
        address,
        label: `${address}  ${entry.name}${entry.up ? "" : " (down)"}`,
      })),
    ),
  );
  /** This computer's IPv4 addresses on the cards that are up, offered for a field that takes one. */
  const ownIpv4 = $derived(
    interfaces.filter((entry) => entry.up && !entry.loopback).flatMap((entry) => entry.ipv4.map((address) => ({ address, name: entry.name }))),
  );

  const tls = $derived(tab.kind === "tls_client" || tab.kind === "tls_server");
  /** Whether the TLS section shows: a TLS tab, or a protocol over TLS. */
  const clientTls = $derived(tab.kind === "tls_client" || (protocolSetup?.tlsPort !== undefined && overTls && tab.socket === "client"));
  const serverTls = $derived(tab.kind === "tls_server" || (protocolSetup?.tlsPort !== undefined && overTls && tab.socket === "server"));
  const title = $derived(
    protocolSetup
      ? `${endOf(tab.kind)?.end.title ?? tab.kind} settings`.replace(/^./, (first) => first.toUpperCase())
      : tab.socket === "udp"
        ? tab.kind === "dtls_client"
          ? "DTLS client settings"
          : tab.kind === "dtls_server"
            ? "DTLS server settings"
            : "UDP settings"
        : `${tls ? "TLS " : ""}${tab.socket === "server" ? "server" : "client"} settings`.replace(/^./, (first) => first.toUpperCase()),
  );

  /** Turns DTLS on or off for a protocol, moving the port between its usual two. */
  function toggleDtls() {
    if (!protocolSetup?.dtlsPort) return;
    const [from, to] = overDtls ? [protocolSetup.port, protocolSetup.dtlsPort] : [protocolSetup.dtlsPort, protocolSetup.port];
    if (udp.remote_port === from) udp.remote_port = to;
    if (udp.local_port === from) udp.local_port = to;
  }

  /** Turns TLS on or off for a protocol, moving the port between its usual two. */
  function toggleTls() {
    if (!protocolSetup?.tlsPort) return;
    const [from, to] = overTls ? [protocolSetup.port, protocolSetup.tlsPort] : [protocolSetup.tlsPort, protocolSetup.port];
    if (client.port === from) client.port = to;
    if (server.port === from) server.port = to;
  }

  function submit() {
    error = "";
    if (tab.socket === "udp") {
      const problem =
        portProblem(udp.local_port, false) ?? portProblem(udp.remote_port, udp.remote_host.trim() !== "");
      if (problem) {
        error = problem;
        return;
      }
      const config: UdpConfig = {
        ...udp,
        multicast: multicast && udp.multicast?.group.trim() ? { ...udp.multicast } : null,
      };
      if (showsDtls && dtls.psk && !dtls.psk_key.trim()) {
        error = "Enter the pre-shared key, in hex or in quotes.";
        return;
      }
      if (showsDtls && !dtls.psk && dtlsClient && dtls.verify === "file" && !dtls.ca_file.trim()) {
        error = "Choose the CA file to check the server's certificate with, or check it another way.";
        return;
      }
      if (protocolSetup) tab.reconfigureProtocol({ udp: config, dtls: showsDtls ? { ...dtls } : null }, { ...options });
      else if (tab.kind === "dtls_client" || tab.kind === "dtls_server") tab.reconfigureDtls(config, { ...dtls });
      else tab.reconfigureUdp(config);
    } else if (tab.socket === "client") {
      const problem = client.host.trim() === "" ? "Enter the host: a name or an IP address." : portProblem(client.port, true);
      if (problem) {
        error = problem;
        return;
      }
      if (clientTls && tlsClient.verify === "file" && !tlsClient.ca_file.trim()) {
        error = "Choose the CA file to check the server's certificate with, or check it another way.";
        return;
      }
      const config = { ...client, tls: clientTls ? { ...tlsClient } : null };
      if (protocolSetup) tab.reconfigureProtocol({ client: config }, { ...options });
      else tab.reconfigureClient(config);
    } else if (tab.socket === "server") {
      const problem = portProblem(server.port, false);
      if (problem) {
        error = problem;
        return;
      }
      const checks = tlsServer.client_auth === "optional" || tlsServer.client_auth === "required";
      if (serverTls && checks && !tlsServer.ca_file.trim()) {
        error = "Choose the CA file that client certificates must be signed by.";
        return;
      }
      const config = { ...server, tls: serverTls ? { ...tlsServer } : null };
      if (protocolSetup) tab.reconfigureProtocol({ server: config }, { ...options });
      else tab.reconfigureServer(config);
    }
    if (tab.socket === "none") tab.reconfigureProtocol({}, { ...options });
    tab.setTerminal({ ...terminal });
    if (starting) tab.start();
    onclose();
  }

  function ensureMulticast() {
    udp.multicast ??= { group: "", interface: "", interface_index: 0, loopback: false };
  }
</script>

<Modal {title} {onclose} onsubmit={submit}>
  {#if tab.socket === "udp"}
    <h2 class="dlg-section">This end</h2>
    <div class="dlg-grid">
      <label class="dlg-label wide">
        Listen on
        <select class="field mono" bind:value={udp.local_address}>
          <option value="">All IPv4 addresses</option>
          <option value="::">All IPv6 addresses</option>
          {#each localChoices as choice (choice.label)}
            <option value={choice.address}>{choice.label}</option>
          {/each}
        </select>
      </label>
      <label class="dlg-label">
        Port
        <input class="field mono" type="number" min="0" max="65535" bind:value={udp.local_port} />
      </label>
    </div>
    <p class="dlg-hint">Port 0 takes any free port: enough for a tab that sends and hears the answers.</p>

    <h2 class="dlg-section">Where the send box sends</h2>
    <div class="dlg-grid">
      <label class="dlg-label wide">
        Remote host
        <input class="field mono" placeholder="Empty: answer the peer heard last" bind:value={udp.remote_host} />
      </label>
      <label class="dlg-label">
        Port
        <input class="field mono" type="number" min="0" max="65535" bind:value={udp.remote_port} />
      </label>
    </div>

    <div class="dlg-checks">
      <label class="dlg-check"><input type="checkbox" bind:checked={udp.broadcast} /> Broadcast</label>
      <label class="dlg-check" title="Lets other programs listen on the same port too">
        <input type="checkbox" bind:checked={udp.reuse_address} /> Share the port
      </label>
      <label class="dlg-check">
        <input type="checkbox" bind:checked={multicast} onchange={ensureMulticast} /> Join a multicast group
      </label>
      <label class="dlg-check">
        TTL <input class="field mono ttl" type="number" min="1" max="255" bind:value={udp.ttl} />
      </label>
    </div>

    {#if multicast && udp.multicast}
      <div class="dlg-grid group">
        <label class="dlg-label">
          Group
          <input class="field mono" placeholder="239.1.2.3 or ff02::fb" bind:value={udp.multicast.group} />
        </label>
        <label class="dlg-label">
          IPv4 interface
          <select class="field mono" bind:value={udp.multicast.interface}>
            <option value="">The OS's choice</option>
            {#each interfaces as entry (`${entry.index}/${entry.id || entry.name}`)}
              {#each entry.ipv4 as address (address)}
                <option value={address}>{address} {entry.name}{entry.up ? "" : " (down)"}</option>
              {/each}
            {/each}
          </select>
        </label>
        <label class="dlg-label">
          IPv6 interface
          <select class="field" bind:value={udp.multicast.interface_index}>
            <option value={0}>The OS's choice</option>
            {#each interfaces as entry (`${entry.index}/${entry.id || entry.name}`)}
              {#if entry.index > 0 && (entry.ipv6.length > 0 || entry.index === udp.multicast.interface_index)}
                <option value={entry.index}>{entry.name} ({entry.index}){entry.up ? "" : " (down)"}</option>
              {/if}
            {/each}
          </select>
        </label>
      </div>
      <div class="dlg-checks">
        <label class="dlg-check"><input type="checkbox" bind:checked={udp.multicast.loopback} /> Hear our own datagrams to the group</label>
      </div>
    {/if}

    {#if protocolSetup?.dtlsPort}
      <div class="dlg-checks">
        <label class="dlg-check"><input type="checkbox" bind:checked={overDtls} onchange={toggleDtls} /> Over DTLS</label>
      </div>
    {/if}

    {#if showsDtls}
      <h2 class="dlg-section">DTLS</h2>
      <div class="dlg-grid">
        <label class="dlg-label">
          Version
          <select class="field" bind:value={dtls.version}>
            <option value="auto">{dtlsClient ? (dtlsOpenssl ? "1.0 and 1.2" : dtls.psk ? "1.2" : "1.2 and 1.3") : "Any"}</option>
            <option value="dtls12">DTLS 1.2</option>
            <option value="dtls13" disabled={dtls.psk || dtls.engine === "openssl"}>DTLS 1.3</option>
            <option value="dtls10" disabled={dtls.engine === "rustls"}>DTLS 1.0 (OpenSSL)</option>
            <option value="all" disabled={dtls.engine === "rustls"}>DTLS 1.0 and 1.2 (OpenSSL)</option>
          </select>
        </label>
        {#if dtls.psk}
          <label class="dlg-label">
            PSK identity
            <input class="field mono" placeholder={dtlsClient ? "device-01" : "Empty: any"} spellcheck="false" bind:value={dtls.psk_identity} />
          </label>
          <label class="dlg-label">
            Key
            <input class="field mono" placeholder="Hex, or &quot;text&quot;" spellcheck="false" bind:value={dtls.psk_key} />
          </label>
        {:else}
          <FileField label="This end's certificate" wide kinds={CERTIFICATES} placeholder={dtlsClient ? (dtlsOpenssl ? "Empty: none" : "Empty: one made now") : "Empty: netNIMA's own"} bind:value={dtls.cert_file} />
          {#if dtlsClient}
            <label class="dlg-label">
              Check the server's certificate
              <select class="field" bind:value={dtls.verify}>
                <option value="system">With the PC's trusted ones</option>
                <option value="file">With a CA file</option>
                <option value="none">Do not check</option>
              </select>
            </label>
          {:else}
            <span></span>
          {/if}
          <FileField label="Its key" wide kinds={KEYS} placeholder="Empty: in the certificate's file" bind:value={dtls.key_file} />
          {#if dtlsClient && dtls.verify === "file"}
            <span></span>
            <FileField label="CA file" wide kinds={CERTIFICATES} placeholder="ca.crt: PEM or DER" bind:value={dtls.ca_file} />
          {/if}
          {#if dtlsClient && dtls.verify !== "none"}
            <label class="dlg-label wide">
              Name the certificate is for
              <input class="field mono" placeholder="Empty: the remote host" spellcheck="false" bind:value={dtls.server_name} />
            </label>
          {/if}
        {/if}
      </div>
      <div class="dlg-checks">
        <label class="dlg-check" title="A key both ends know, instead of certificates: AES-128-CCM-8 with the Rust engine, as CoAP and LwM2M devices use, or any PSK suite with OpenSSL">
          <input type="checkbox" bind:checked={dtls.psk} /> Pre-shared key (PSK)
        </label>
        {#if !dtlsClient}
          <label class="dlg-check"><input type="checkbox" bind:checked={dtls.client_auth} disabled={dtls.psk} /> Ask clients for a certificate</label>
          <label class="dlg-check" title="HelloVerifyRequest, against spoofed addresses"><input type="checkbox" bind:checked={dtls.cookie} /> Cookie first</label>
        {:else if !dtls.psk && dtls.verify !== "none"}
          <label class="dlg-check"><input type="checkbox" bind:checked={dtls.check_name} /> Check the name</label>
        {/if}
      </div>
      <h2 class="dlg-section">For old and small devices</h2>
      <div class="dlg-grid">
        <label class="dlg-label" title="Auto uses dimpl, in Rust, and OpenSSL when DTLS 1.0 or a cipher list needs it">
          Engine
          <select class="field" bind:value={dtls.engine}>
            <option value="auto">Auto</option>
            <option value="rustls">Rust (dimpl)</option>
            <option value="openssl">OpenSSL</option>
          </select>
        </label>
        <label class="dlg-label wide" title="OpenSSL's names, such as PSK-AES128-CCM8, PSK-AES128-CBC-SHA256 or ECDHE-ECDSA-AES128-CCM8">
          Cipher suites
          <input class="field mono" placeholder="Empty: all of them" spellcheck="false" bind:value={dtls.ciphers} />
        </label>
      </div>
      <p class="dlg-hint">The Rust engine speaks DTLS 1.2 and 1.3 with ECDSA certificates, or DTLS 1.2 with a PSK and AES-128-CCM-8. OpenSSL speaks DTLS 1.0 and 1.2 with any suite it has, and RSA keys too.</p>
    {/if}
  {:else if tab.socket === "client"}
    <h2 class="dlg-section">The other end</h2>
    <div class="dlg-grid">
      <label class="dlg-label wide">
        Host
        <input class="field mono" placeholder="192.168.1.50 or a name" bind:value={client.host} />
      </label>
      <label class="dlg-label">
        Port
        <input class="field mono" type="number" min="1" max="65535" bind:value={client.port} />
      </label>
    </div>
    <div class="dlg-grid">
      <label class="dlg-label">
        From local port
        <input class="field mono" type="number" min="0" max="65535" bind:value={client.local_port} />
      </label>
      <label class="dlg-label">
        TCP keep-alive, s
        <input class="field mono" type="number" min="0" max="7200" bind:value={client.keep_alive} />
      </label>
    </div>
    <div class="dlg-checks">
      {#if tab.kind === "tcp_client"}
        <label class="dlg-check"><input type="checkbox" bind:checked={client.telnet} /> Telnet</label>
      {/if}
      <label class="dlg-check" title="Sends small writes at once (TCP_NODELAY)"><input type="checkbox" bind:checked={client.no_delay} /> No delay</label>
      <label class="dlg-check"><input type="checkbox" bind:checked={client.reconnect} /> Connect again when it ends</label>
    </div>

    {#if protocolSetup?.tlsPort}
      <div class="dlg-checks">
        <label class="dlg-check"><input type="checkbox" bind:checked={overTls} onchange={toggleTls} /> Over TLS</label>
      </div>
    {/if}

    {#if clientTls}
      <h2 class="dlg-section">TLS</h2>
      <div class="dlg-grid">
        <label class="dlg-label">
          Check the server's certificate
          <select class="field" bind:value={tlsClient.verify}>
            <option value="system">With the PC's trusted ones</option>
            <option value="file">With a CA file</option>
            <option value="none">Do not check</option>
          </select>
        </label>
        {#if tlsClient.verify === "file"}
          <FileField label="CA file" wide kinds={CERTIFICATES} placeholder="ca.crt: PEM or DER" bind:value={tlsClient.ca_file} />
        {:else}
          <span class="wide"></span>
        {/if}
        <label class="dlg-label wide">
          Name asked for (SNI)
          <input class="field mono" placeholder="Empty: the host" spellcheck="false" bind:value={tlsClient.server_name} />
        </label>
        <label class="dlg-label">
          Versions
          <select class="field" bind:value={tlsClient.versions}>
            <option value="both">TLS 1.2 and 1.3</option>
            <option value="tls12">TLS 1.2 only</option>
            <option value="tls13">TLS 1.3 only</option>
            <option value="all">TLS 1.0 to 1.3 (OpenSSL)</option>
            <option value="tls11">TLS 1.1 only (OpenSSL)</option>
            <option value="tls10">TLS 1.0 only (OpenSSL)</option>
          </select>
        </label>
        <FileField label="This end's certificate" wide kinds={CERTIFICATES} placeholder="For a server that asks for one" bind:value={tlsClient.cert_file} />
        <label class="dlg-label">
          ALPN
          <input class="field mono" placeholder="mqtt, h2, http/1.1" spellcheck="false" bind:value={tlsClient.alpn} />
        </label>
        <FileField label="Its key" wide kinds={KEYS} placeholder="Empty: in the certificate's file" bind:value={tlsClient.key_file} />
        <span></span>
        <FileField label="Key log, for Wireshark" wide saving kinds={KEY_LOGS} placeholder="Empty: none" bind:value={tlsClient.key_log} />
      </div>
      <div class="dlg-checks">
        <label class="dlg-check" title="Checks that the certificate is for the name asked for, as browsers do">
          <input type="checkbox" bind:checked={tlsClient.check_name} disabled={tlsClient.verify === "none"} /> Check the name
        </label>
        <label class="dlg-check" title="Some servers turn down a name they do not know">
          <input type="checkbox" bind:checked={tlsClient.no_sni} /> Ask for no name
        </label>
      </div>
      <h2 class="dlg-section">For old and small devices</h2>
      <div class="dlg-grid">
        <label class="dlg-label" title="Auto uses rustls, and OpenSSL when TLS 1.0 or 1.1, a PSK or a cipher list needs it">
          Engine
          <select class="field" bind:value={tlsClient.engine}>
            <option value="auto">Auto</option>
            <option value="rustls">rustls</option>
            <option value="openssl">OpenSSL</option>
          </select>
        </label>
        <label class="dlg-label wide" title="OpenSSL's names, such as ECDHE-ECDSA-AES128-CCM8, PSK-AES128-CCM8 or AES128-SHA">
          Cipher suites
          <input class="field mono" placeholder="Empty: all of them" spellcheck="false" bind:value={tlsClient.ciphers} />
        </label>
        {#if tlsClient.psk}
          <label class="dlg-label">
            PSK identity
            <input class="field mono" placeholder={"device-01"} spellcheck="false" bind:value={tlsClient.psk_identity} />
          </label>
          <label class="dlg-label wide">
            Key
            <input class="field mono" placeholder="Hex, or &quot;text&quot;" spellcheck="false" bind:value={tlsClient.psk_key} />
          </label>
        {/if}
      </div>
      <div class="dlg-checks">
        <label class="dlg-check" title="A key both ends know, instead of certificates, with OpenSSL">
          <input type="checkbox" bind:checked={tlsClient.psk} /> Pre-shared key (PSK)
        </label>
      </div>
    {/if}
  {:else if tab.socket === "server"}
    <h2 class="dlg-section">Listen</h2>
    <div class="dlg-grid">
      <label class="dlg-label wide">
        On
        <select class="field mono" bind:value={server.address}>
          <option value="">All IPv4 addresses</option>
          <option value="::">All IPv6 addresses</option>
          {#each localChoices as choice (choice.label)}
            <option value={choice.address}>{choice.label}</option>
          {/each}
        </select>
      </label>
      <label class="dlg-label">
        Port
        <input class="field mono" type="number" min="0" max="65535" bind:value={server.port} />
      </label>
    </div>
    <div class="dlg-grid">
      <label class="dlg-label">
        Clients at most
        <input class="field mono" type="number" min="0" bind:value={server.max_clients} />
      </label>
      <label class="dlg-label">
        TCP keep-alive, s
        <input class="field mono" type="number" min="0" max="7200" bind:value={server.keep_alive} />
      </label>
    </div>
    <p class="dlg-hint">Clients at most 0 takes as many as come. Port 0 takes any free port, which the tab then shows.</p>
    <div class="dlg-checks">
      {#if tab.kind === "tcp_server"}
        <label class="dlg-check"><input type="checkbox" bind:checked={server.telnet} /> Telnet</label>
      {/if}
      <label class="dlg-check" title="Sends small writes at once (TCP_NODELAY)"><input type="checkbox" bind:checked={server.no_delay} /> No delay</label>
    </div>

    {#if protocolSetup?.tlsPort}
      <div class="dlg-checks">
        <label class="dlg-check"><input type="checkbox" bind:checked={overTls} onchange={toggleTls} /> Over TLS</label>
      </div>
    {/if}

    {#if serverTls}
      <h2 class="dlg-section">TLS</h2>
      <div class="dlg-grid">
        <FileField label="Certificate" wide kinds={CERTIFICATES} placeholder="Empty: netNIMA's own" bind:value={tlsServer.cert_file} />
        <label class="dlg-label">
          Versions
          <select class="field" bind:value={tlsServer.versions}>
            <option value="both">TLS 1.2 and 1.3</option>
            <option value="tls12">TLS 1.2 only</option>
            <option value="tls13">TLS 1.3 only</option>
            <option value="all">TLS 1.0 to 1.3 (OpenSSL)</option>
            <option value="tls11">TLS 1.1 only (OpenSSL)</option>
            <option value="tls10">TLS 1.0 only (OpenSSL)</option>
          </select>
        </label>
        <FileField label="Its key" wide kinds={KEYS} placeholder="Empty: in the certificate's file" bind:value={tlsServer.key_file} />
        <label class="dlg-label">
          ALPN
          <input class="field mono" placeholder="mqtt, http/1.1" spellcheck="false" bind:value={tlsServer.alpn} />
        </label>
        <label class="dlg-label">
          Client certificates
          <select class="field" bind:value={tlsServer.client_auth}>
            <option value="none">Not asked for</option>
            <option value="optional">Asked for, checked if sent</option>
            <option value="required">Required and checked</option>
            <option value="any">Asked for, any taken</option>
          </select>
        </label>
        {#if tlsServer.client_auth === "optional" || tlsServer.client_auth === "required"}
          <FileField label="CA file for them" wide kinds={CERTIFICATES} placeholder="ca.crt: PEM or DER" bind:value={tlsServer.ca_file} />
        {:else}
          <span class="wide"></span>
        {/if}
        <FileField label="Key log, for Wireshark" wide saving kinds={KEY_LOGS} placeholder="Empty: none" bind:value={tlsServer.key_log} />
      </div>
      <h2 class="dlg-section">For old and small devices</h2>
      <div class="dlg-grid">
        <label class="dlg-label" title="Auto uses rustls, and OpenSSL when TLS 1.0 or 1.1, a PSK or a cipher list needs it">
          Engine
          <select class="field" bind:value={tlsServer.engine}>
            <option value="auto">Auto</option>
            <option value="rustls">rustls</option>
            <option value="openssl">OpenSSL</option>
          </select>
        </label>
        <label class="dlg-label wide" title="OpenSSL's names, such as ECDHE-ECDSA-AES128-CCM8, PSK-AES128-CCM8 or AES128-SHA">
          Cipher suites
          <input class="field mono" placeholder="Empty: all of them" spellcheck="false" bind:value={tlsServer.ciphers} />
        </label>
        {#if tlsServer.psk}
          <label class="dlg-label">
            PSK identity
            <input class="field mono" placeholder={"Empty: any"} spellcheck="false" bind:value={tlsServer.psk_identity} />
          </label>
          <label class="dlg-label wide">
            Key
            <input class="field mono" placeholder="Hex, or &quot;text&quot;" spellcheck="false" bind:value={tlsServer.psk_key} />
          </label>
        {/if}
      </div>
      <div class="dlg-checks">
        <label class="dlg-check" title="A key both ends know, instead of certificates, with OpenSSL">
          <input type="checkbox" bind:checked={tlsServer.psk} /> Pre-shared key (PSK)
        </label>
      </div>
      <p class="dlg-hint">netNIMA's own certificate is self-signed for this PC's names and addresses: a device must trust it, or not check. Tools > Certificates shows it and makes others.</p>
    {/if}
  {/if}

  {#if protocolSetup}
    <h2 class="dlg-section">{endOf(tab.kind)?.protocol.name ?? "Protocol"}</h2>
    <div class="dlg-grid">
      {#each protocolSetup.fields.filter((field) => field.type !== "check") as field (field.key)}
        <label class="dlg-label" class:wide={field.wide} title={field.title}>
          {field.label}
          {#if field.type === "select"}
            <select class="field" bind:value={options[field.key]}>
              {#each field.choices ?? [] as [value, words] (value)}
                <option {value}>{words}</option>
              {/each}
            </select>
          {:else if field.type === "number"}
            <input class="field mono" type="number" min={field.min} max={field.max} bind:value={options[field.key]} />
          {:else}
            <input
              class="field mono"
              type={field.type === "password" ? "password" : "text"}
              placeholder={field.placeholder}
              spellcheck="false"
              list={field.suggest === "address" ? "own-addresses" : undefined}
              bind:value={options[field.key]}
            />
          {/if}
        </label>
      {/each}
    </div>
    {#if protocolSetup.fields.some((field) => field.suggest === "address")}
      <!-- The PC's own addresses, offered as such a field is typed in. -->
      <datalist id="own-addresses">
        {#each ownIpv4 as choice (`${choice.address}/${choice.name}`)}
          <option value={choice.address}>{choice.name}</option>
        {/each}
      </datalist>
    {/if}
    {#if protocolSetup.fields.some((field) => field.type === "check")}
      <div class="dlg-checks">
        {#each protocolSetup.fields.filter((field) => field.type === "check") as field (field.key)}
          <label class="dlg-check" title={field.title}>
            <input type="checkbox" checked={Boolean(options[field.key])} onchange={(event) => (options[field.key] = event.currentTarget.checked)} />
            {field.label}
          </label>
        {/each}
      </div>
    {/if}
    {#if protocolSetup.hint}
      <p class="dlg-hint">{protocolSetup.hint}</p>
    {/if}
  {/if}

  <h2 class="dlg-section">Terminal</h2>
  <div class="dlg-grid">
    <label class="dlg-label">
      Enter sends
      <select class="field" bind:value={terminal.enter}>
        {#each [["cr", "CR"], ["lf", "LF"], ["crlf", "CR LF"]] as [value, label] (value)}
          <option value={value as LineEnding}>{label}</option>
        {/each}
      </select>
    </label>
    <label class="dlg-label">
      New line after a pause, ms
      <input class="field mono" type="number" min="0" bind:value={terminal.pause_ms} />
    </label>
  </div>
  <div class="dlg-checks">
    <label class="dlg-check"><input type="checkbox" bind:checked={terminal.local_echo} /> Show what is sent</label>
    <label class="dlg-check"><input type="checkbox" bind:checked={terminal.lf_is_newline} /> LF starts a new line</label>
  </div>

  {#if error}
    <p class="dlg-error">{error}</p>
  {/if}

  {#snippet buttons()}
    <button class="btn" onclick={onclose}>Cancel</button>
    <button class="btn primary" onclick={submit}>{starting ? (tab.socket === "server" ? "Listen" : tab.socket === "udp" ? "Open" : tab.socket === "none" ? "Start" : "Connect") : "Save"}</button>
  {/snippet}
</Modal>

<style>
  .wide {
    grid-column: span 2;
  }

  .ttl {
    width: 64px;
    height: 24px;
  }

  .group {
    margin-top: 10px;
  }
</style>
