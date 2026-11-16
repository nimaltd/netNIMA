<script lang="ts">
  import { open } from "@tauri-apps/plugin-dialog";
  import { DATAGRAM_DEFAULT, duration, fileName, type Tab } from "./tabs.svelte";
  import type { View } from "./types";

  // The bar over a tab's view: connect or listen, the settings in a few
  // words, the peers, the log and the recording, and the views.
  let { tab, onsettings }: { tab: Tab; onsettings: () => void } = $props();

  const VIEWS: { view: View; label: string; title: string }[] = [
    { view: "terminal", label: "Terminal", title: "What comes, as a terminal shows it; type to send" },
    { view: "hex", label: "Hex", title: "Every byte sent and received, in hex" },
    { view: "lines", label: "Lines", title: "Each line and datagram with its time and peer, filtered and searched" },
    { view: "plot", label: "Plot", title: "The numbers in the lines, as a chart" },
  ];
  /** The views of the protocols' own. */
  const OWN_VIEWS: Partial<Record<View, { view: View; label: string; title: string }>> = {
    modbus: {
      view: "modbus",
      label: "Modbus",
      title: "Ask the slave as a master, or answer the masters as a slave, and every frame on the connection",
    },
    mqtt: {
      view: "mqtt",
      label: "MQTT",
      title: "Publish and subscribe, a broker's clients and retained messages, and every message by its topic",
    },
    coap: {
      view: "coap",
      label: "CoAP",
      title: "Requests in rows, each with its answer, Observe and Discover; or a server's resources and the requests it heard",
    },
    http: {
      view: "http",
      label: "HTTP",
      title: "Requests in rows, each with its response; or a server's routes and the requests it answered",
    },
    lwm2m: {
      view: "lwm2m",
      label: "LwM2M",
      title: "A server's devices, their objects to read, write, observe and execute, and firmware to push; or a device's state and resources",
    },
    mcumgr: {
      view: "mcumgr",
      label: "MCUmgr",
      title: "A board's info, images to test and confirm, an image to upload, and its threads; or a simulated board's images",
    },
  };
  /** A tab whose protocol has a view of its own has it first. */
  const views = $derived.by(() => {
    const own = tab.ownView ? OWN_VIEWS[tab.ownView] : undefined;
    return own ? [own, ...VIEWS] : VIEWS;
  });

  let peersOpen = $state(false);
  let bar: HTMLDivElement;

  const startLabel = $derived(
    tab.socket === "server"
      ? "Listen"
      : tab.socket === "udp" || tab.socket === "replay"
        ? "Open"
        : tab.socket === "none"
          ? "Start"
          : "Connect",
  );
  const stopLabel = $derived(
    tab.socket === "server" || tab.socket === "none"
      ? "Stop"
      : tab.socket === "udp" || tab.socket === "replay"
        ? "Close"
        : "Disconnect",
  );

  async function sendFile() {
    const path = await open({ title: "Send a file", multiple: false, directory: false });
    if (typeof path === "string") {
      void tab.sendFile(path, 0, DATAGRAM_DEFAULT);
    }
  }

  async function openRecording() {
    const path = await open({
      title: "Play back a recording",
      multiple: false,
      filters: [{ name: "Recordings", extensions: ["nrec", "trec"] }],
    });
    if (typeof path === "string") {
      tab.stop();
      tab.replay = { ...tab.replay, path };
      tab.name = fileName(path);
      tab.play();
    }
  }

  function onWindowMouseDown(event: MouseEvent) {
    if (peersOpen && !bar.contains(event.target as Node)) peersOpen = false;
  }

  function position(seconds: number): string {
    return duration(seconds * 1000);
  }
</script>

<svelte:window onmousedown={onWindowMouseDown} />

<div class="toolbar" bind:this={bar}>
  {#if tab.socket === "replay"}
    {#if tab.playback?.playing}
      <button class="btn small" onclick={() => tab.pause()}>Pause</button>
    {:else}
      <button class="btn small primary" onclick={() => tab.play()}>Play</button>
    {/if}
    {#if tab.playback}
      <input
        class="seek"
        type="range"
        min="0"
        max={tab.playback.length}
        step="0.1"
        value={tab.playback.position}
        title="Where it plays from"
        oninput={(event) => tab.seek(Number(event.currentTarget.value))}
      />
      <span class="muted mono">{position(tab.playback.position)} / {position(tab.playback.length)}</span>
    {/if}
    <select
      class="field small"
      title="How fast it plays"
      value={String(tab.replay.speed)}
      onchange={(event) => tab.setSpeed(Number(event.currentTarget.value))}
    >
      {#each [0.25, 0.5, 1, 2, 5, 10, 100] as speed (speed)}
        <option value={String(speed)}>{speed}×</option>
      {/each}
    </select>
    <button class="btn small" onclick={() => void openRecording()}>Open...</button>
  {:else}
    {#if tab.running}
      <button class="btn small" onclick={() => tab.stop()}>{stopLabel}</button>
    {:else}
      <button class="btn small primary" onclick={() => tab.start()}>{startLabel}</button>
    {/if}
    <button class="target mono" title="Change the tab's settings" onclick={onsettings}>{tab.target}</button>

    {#if tab.manyPeers}
      <div class="peers">
        <button class="btn small" disabled={tab.peers.length === 0} onclick={() => (peersOpen = !peersOpen)}>
          {tab.peers.length}
          {tab.socket === "server" ? (tab.peers.length === 1 ? "client" : "clients") : tab.peers.length === 1 ? "peer" : "peers"}
          ▾
        </button>
        {#if peersOpen && tab.peers.length > 0}
          <div class="popover" role="menu">
            {#each tab.peers as peer (peer.id)}
              <div class="peer">
                <span class="mono">{peer.address}</span>
                <button
                  class="link"
                  title="Send to this one only"
                  onclick={() => {
                    tab.sendTo = `peer:${peer.id}`;
                    peersOpen = false;
                  }}>Send to</button
                >
                {#if tab.socket === "server"}
                  <button class="link" title="Close its connection" onclick={() => tab.dropPeer(peer.id, false)}>Drop</button>
                  <button class="link" title="End its connection with a reset (RST)" onclick={() => tab.dropPeer(peer.id, true)}
                    >Reset</button
                  >
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
    {#if tab.socket === "client" && tab.connected}
      <button class="btn small" title="End the connection with a reset (RST) instead of a FIN" onclick={() => tab.resetConnection()}
        >Reset</button
      >
    {/if}

    <span class="divider"></span>
    <button
      class="btn small"
      class:on={tab.log}
      title={tab.logPath ? `Logging to ${tab.logPath}` : "Write what comes to a log file"}
      onclick={() => tab.setLog(!tab.log)}
    >
      Log
    </button>
    <button
      class="btn small"
      class:on={tab.recordPath !== null}
      disabled={!tab.running}
      title={tab.recordPath ? `Recording to ${tab.recordPath}` : "Record what comes and goes, to play back later"}
      onclick={() => tab.setRecording(tab.recordPath === null)}
    >
      {tab.recordPath ? "■ Rec" : "● Rec"}
    </button>
    {#if tab.sending}
      <button class="btn small on" title="Stop sending the file" onclick={() => tab.cancelSend()}>
        {tab.sending.name}
        {tab.sending.total > 0 ? `${Math.floor((tab.sending.sent * 100) / tab.sending.total)}%` : ""} ■
      </button>
    {:else}
      <button class="btn small" disabled={!tab.connected} title="Send a file" onclick={() => void sendFile()}>File...</button>
    {/if}
  {/if}

  <span class="spacer"></span>
  <button
    class="btn small"
    class:on={tab.scrollLock}
    title="Scroll lock: the screen stays where it is while lines come below"
    onclick={() => tab.setScrollLock(!tab.scrollLock)}
  >
    Lock
  </button>
  <div class="views" role="tablist">
    {#each views as { view, label, title } (view)}
      <button class="view" class:on={tab.view === view} role="tab" aria-selected={tab.view === view} {title} onclick={() => tab.setView(view)}>
        {label}
      </button>
    {/each}
  </div>
</div>

<style>
  .toolbar {
    position: relative;
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 36px;
    padding: 0 10px;
    overflow: visible;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  .small {
    height: 26px;
    padding: 0 10px;
    font-size: 12px;
  }

  .btn.on {
    border-color: var(--accent);
    background: var(--accent-soft);
  }

  .target {
    max-width: 380px;
    overflow: hidden;
    padding: 2px 6px;
    font-size: 12px;
    color: var(--text);
    text-overflow: ellipsis;
    background: none;
    border: 1px dashed var(--border);
    border-radius: 5px;
    cursor: default;
  }

  .target:hover {
    border-color: var(--accent);
  }

  .divider {
    width: 1px;
    height: 16px;
    background: var(--border);
  }

  .spacer {
    flex: 1;
  }

  .muted {
    font-size: 12px;
    color: var(--muted);
  }

  .seek {
    width: 200px;
    accent-color: var(--accent);
  }

  .views {
    display: flex;
    padding: 2px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .view {
    height: 24px;
    padding: 0 10px;
    font: inherit;
    font-size: 12px;
    color: var(--muted);
    background: none;
    border: 0;
    border-radius: 4px;
    cursor: default;
  }

  .view:hover {
    color: var(--text);
  }

  .view.on {
    color: var(--on-accent);
    background: var(--accent);
  }

  .peers {
    position: relative;
  }

  .popover {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    z-index: 15;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 320px;
    max-height: 300px;
    padding: 6px;
    overflow-y: auto;
    background: var(--menu-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: var(--shadow);
  }

  .peer {
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 3px 6px;
    font-size: 12px;
  }

  .peer .mono {
    flex: 1;
  }

  .link {
    padding: 0;
    font: inherit;
    color: var(--accent);
    background: none;
    border: 0;
    cursor: pointer;
  }
</style>
