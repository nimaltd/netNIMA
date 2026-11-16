<script lang="ts">
  import { open } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import { READ_FORMATS, byPath, isExecutable, meaning, objectName, parsePath, resourceName, resourcesOf, type Ask } from "./lwm2m";
  import type { Lwm2mDevice } from "./lwm2m.svelte";
  import { changed, type Tab } from "./tabs.svelte";
  import { clearActiveTerminal, setActiveTerminal, type TerminalActions } from "./terminal-actions";

  // An LwM2M tab's own view, beside its terminal. A server's: the devices
  // registered; the chosen one's objects and resources, to read, write,
  // observe and execute; its firmware to push and update to; and every
  // request with its answer. A device's: whether it is registered, its
  // resources to change, and what its server asked of it. It asks the
  // tab's engine with the lines a person would type.
  let {
    tab,
    active,
  }: {
    tab: Tab;
    /** Whether this view has the keyboard. */
    active: boolean;
  } = $props();

  const setup = $derived(tab.lwm2mSetup);
  const session = $derived(tab.lwm2m);
  const server = $derived(tab.kind === "lwm2m_server");

  let root: HTMLDivElement | undefined = $state();
  /** The values being typed, by path, until they are written or set. */
  let editing: Record<string, string> = $state({});
  /** The clock lifetimes count down by. */
  let now = $state(Date.now());

  function save() {
    changed();
  }

  // ----- The server -----

  const selected = $derived(session.devices.find((device) => device.endpoint === setup.selected) ?? session.devices[0]);
  const data = $derived(selected ? session.data[selected.endpoint] : undefined);
  /** The paths known on the chosen device: those read, and those Discover listed. */
  const known = $derived(data ? [...Object.keys(data.values), ...Object.keys(data.links)] : []);
  /** The chosen device's object instances, from its registration and its answers; an object listed with no instance stands for itself. */
  const instances = $derived.by(() => {
    if (!selected) return [];
    const found = new Set<string>();
    for (const path of [...selected.objects, ...known]) {
      const parts = parsePath(path);
      if (parts) found.add(parts.length >= 2 ? `/${parts[0]}/${parts[1]}` : `/${parts[0]}`);
    }
    for (const path of [...found]) {
      if (parsePath(path)?.length === 1 && [...found].some((other) => other.startsWith(`${path}/`))) found.delete(path);
    }
    return [...found].sort(byPath);
  });
  const firmware = $derived(selected ? session.firmware[selected.endpoint] : undefined);
  const percent = $derived(firmware && firmware.total > 0 ? Math.floor((firmware.sent * 100) / firmware.total) : 0);
  const pushing = $derived(firmware !== undefined && !firmware.done && firmware.problem === null);

  function select(endpoint: string) {
    setup.selected = endpoint;
    editing = {};
    save();
  }

  function ask(request: Ask) {
    if (selected) void session.ask(selected.location, request);
  }

  function read(path: string) {
    ask({ what: "read", path, format: setup.format || undefined });
  }

  function observed(path: string): boolean {
    return data?.observed[path] !== undefined;
  }

  function toggleObserve(path: string) {
    ask({ what: observed(path) ? "cancel" : "observe", path });
  }

  function write(path: string) {
    const value = editing[path];
    if (value === undefined) return;
    ask({ what: "write", path, value });
    delete editing[path];
  }

  async function chooseFirmware() {
    const chosen = await open({
      title: "The firmware to push",
      multiple: false,
      directory: false,
      defaultPath: setup.firmware || undefined,
      filters: [
        { name: "Firmware", extensions: ["bin"] },
        { name: "All files", extensions: ["*"] },
      ],
    });
    if (typeof chosen === "string") {
      setup.firmware = chosen;
      save();
    }
  }

  /** Observes Firmware Update's state and result, and the version the device runs. */
  function watchFirmware() {
    for (const path of ["/5/0/3", "/5/0/5", "/3/0/3"]) if (!observed(path)) ask({ what: "observe", path });
  }

  function left(device: Lwm2mDevice): number {
    return Math.max(0, device.left - Math.floor((now - device.at) / 1000));
  }

  /** A value read, with what it means. */
  function shown(path: string): string {
    const value = data?.values[path]?.value;
    if (value === undefined) return "not read";
    const means = meaning(path, value);
    return means ? `${value} (${means})` : value || "empty";
  }

  // ----- The device -----

  /** The device's resources by object instance. */
  const deviceInstances = $derived.by(() => {
    const groups = new Map<string, { path: string; value: string; kind: string }[]>();
    for (const resource of session.device?.resources ?? []) {
      const parts = parsePath(resource.path);
      if (!parts || parts.length < 3) continue;
      const instance = `/${parts[0]}/${parts[1]}`;
      groups.set(instance, [...(groups.get(instance) ?? []), resource]);
    }
    return [...groups.entries()].sort(([a], [b]) => byPath(a, b));
  });
  const registered = $derived(tab.connected && session.device?.location != null);
  const deviceState = $derived.by(() => {
    const device = session.device;
    if (!tab.connected || !device) return "Not running";
    if (device.location) return `Registered at ${device.location}`;
    if (device.bootstrapping) return "Bootstrapping…";
    if (device.registering) return "Registering…";
    return "Not registered";
  });

  /** Whether the server observes a resource, itself or what it is in. */
  function serverObserves(path: string): boolean {
    return (session.device?.observed ?? []).some((each) => path === each || path.startsWith(`${each}/`));
  }

  function set(path: string) {
    const value = editing[path];
    if (value === undefined) return;
    void session.set(path, value);
    delete editing[path];
  }

  // ----- Both -----

  function time(at: number): string {
    const date = new Date(at);
    const two = (value: number) => String(value).padStart(2, "0");
    return `${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())}.${String(date.getMilliseconds()).padStart(3, "0")}`;
  }

  const ms = (value: number) => `${Number(value.toFixed(1))} ms`;
  const oneLine = (text: string) => text.replace(/\s*\r?\n\s*/g, " · ");

  const actions: TerminalActions = {
    hasSelection: () => false,
    copy: async () => {},
    paste: async () => {},
    selectAll: () => {},
    clear: () => (server ? session.clearLog() : session.clearHeard()),
    text: () =>
      (server
        ? session.log.map((each) => `${time(each.at)} ${each.endpoint} ${each.what} ${each.path} ${each.detail} ${each.code ?? each.problem ?? ""} ${oneLine(each.text)}`)
        : session.heard.map((each) => `${time(each.at)} ${each.what} ${each.path} ${each.detail} ${each.code}`)
      ).join("\n") + "\n",
    focus: () => root?.focus(),
    openSearch: () => {},
    findNext: () => {},
    findPrevious: () => {},
  };

  $effect(() => {
    if (active) setActiveTerminal(actions);
  });

  onMount(() => {
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => {
      clearInterval(timer);
      clearActiveTerminal(actions);
    };
  });
</script>

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div class="lwm2mview" tabindex="0" role="region" aria-label="LwM2M" bind:this={root}>
  {#if server}
    <div class="bar">
      <span class="state">{session.devices.length === 1 ? "1 device" : `${session.devices.length} devices`} registered</span>
      <label class="option" title="The format reads ask the device for">
        Read as
        <select class="field" bind:value={setup.format} onchange={save}>
          {#each READ_FORMATS as [value, label] (value)}
            <option {value}>{label}</option>
          {/each}
        </select>
      </label>
      <span class="spacer"></span>
      {#if session.problem}
        <span class="bad problem">{session.problem}</span>
      {/if}
    </div>

    <div class="body three">
      <div class="devices">
        <h3>Devices</h3>
        {#each session.devices as device (device.location)}
          <button class="device" class:on={device === selected} title="Its objects: {device.objects.join(' ')}" onclick={() => select(device.endpoint)}>
            <span class="name">{device.endpoint}</span>
            <span class="muted">/rd/{device.location} · LwM2M {device.version} · {device.binding}</span>
            <span class="muted">{left(device)} s of its {device.lifetime} s left</span>
          </button>
        {:else}
          <p class="empty">{tab.connected ? "No device has registered yet." : "Start the tab: devices register at its port."}</p>
        {/each}
      </div>

      <div class="side">
        {#if selected}
          <div class="fields ask">
            <input class="field mono path" spellcheck="false" placeholder="/3/0" title="A path: an object, an instance or a resource" bind:value={setup.path} onchange={save} />
            <button class="btn small" title="Read it" onclick={() => read(setup.path)}>Read</button>
            <button class="btn small" title="Observe it: each change comes" onclick={() => ask({ what: "observe", path: setup.path })}>Observe</button>
            <button class="btn small" title="Stop observing it" onclick={() => ask({ what: "cancel", path: setup.path })}>Cancel</button>
            <button class="btn small" title="The resources there, with their attributes" onclick={() => ask({ what: "discover", path: setup.path })}>Discover</button>
          </div>
          <div class="fields ask">
            <input class="field mono grow" spellcheck="false" placeholder="a value, or arguments" title="The value to write to the path, or the arguments to execute it with" bind:value={setup.value} onchange={save} />
            <button class="btn small" title="Write the value to the path, a resource" onclick={() => ask({ what: "write", path: setup.path, value: setup.value })}>Write</button>
            <button class="btn small" title="Execute the path, a resource, with the arguments" onclick={() => ask({ what: "execute", path: setup.path, args: setup.value })}>Execute</button>
            <input class="field mono grow" spellcheck="false" placeholder="pmin=1&pmax=60" title="Attributes: when notifications of the path go" bind:value={setup.attributes} onchange={save} />
            <button class="btn small" title="Write these attributes to the path" onclick={() => ask({ what: "attributes", path: setup.path, query: setup.attributes })}>Attributes</button>
          </div>

          {#each instances as instance (instance)}
            {@const object = parsePath(instance)?.[0] ?? 0}
            <section class="instance">
              <div class="instance-head">
                <span class="title">{objectName(object)}</span>
                <span class="mono muted">{instance}</span>
                <span class="spacer"></span>
                <button class="btn small" title="Read all of it" onclick={() => read(instance)}>Read</button>
                <button class="btn small" class:watching={observed(instance)} title={observed(instance) ? "Stop observing it" : "Observe all of it"} onclick={() => toggleObserve(instance)}>
                  {observed(instance) ? "Cancel" : "Observe"}
                </button>
                <button class="btn small" title="Its resources, with their attributes" onclick={() => ask({ what: "discover", path: instance })}>Discover</button>
              </div>
              {#each resourcesOf(instance, known) as path (path)}
                {@const resource = parsePath(path)?.[2] ?? 0}
                {@const value = data?.values[path]}
                <div class="line">
                  <span class="mono id">{resource}</span>
                  <span class="label" title="{path}{data?.links[path] ? ` ${data.links[path]}` : ''}">{resourceName(object, resource) || path}</span>
                  {#if isExecutable(object, resource)}
                    <span class="spacer"></span>
                    <button class="btn small" title="Execute {path}" onclick={() => ask({ what: "execute", path })}>Execute</button>
                  {:else}
                    <input
                      class="field mono value-field"
                      spellcheck="false"
                      placeholder={value ? "" : "not read yet"}
                      title="Its value: Enter writes it"
                      value={editing[path] ?? value?.value ?? ""}
                      oninput={(event) => (editing[path] = event.currentTarget.value)}
                      onkeydown={(event) => event.key === "Enter" && write(path)}
                    />
                    {#if editing[path] !== undefined}
                      <button class="btn small primary" onclick={() => write(path)}>Write</button>
                    {:else if value && meaning(path, value.value)}
                      <span class="muted means">{meaning(path, value.value)}</span>
                    {/if}
                    <button class="icon" title="Read it" onclick={() => read(path)}>↻</button>
                    <button class="icon" class:watching={observed(path)} title={observed(path) ? "Observed: click to stop" : "Observe it: each change comes"} onclick={() => toggleObserve(path)}>◉</button>
                  {/if}
                </div>
              {:else}
                <p class="empty">Read or Discover it to list its resources.</p>
              {/each}
            </section>
          {/each}

          {#if instances.some((instance) => instance === "/5" || instance.startsWith("/5/"))}
            <section class="instance">
              <div class="instance-head">
                <span class="title">Firmware update</span>
                <span class="spacer"></span>
                <span class="muted">Runs {shown("/3/0/3")}</span>
              </div>
              <div class="fields">
                <input
                  class="field mono grow"
                  spellcheck="false"
                  placeholder="The image: zephyr.signed.bin, in Downloads without a folder"
                  title="The image to push to /5/0/0, a block at a time"
                  bind:value={setup.firmware}
                  onchange={save}
                />
                <button class="btn small" title="Choose the file" onclick={chooseFirmware}>...</button>
                <button class="btn small primary" disabled={!tab.connected || pushing} onclick={() => ask({ what: "firmware", file: setup.firmware })}>Push</button>
              </div>
              {#if firmware}
                <div class="progress" class:failed={firmware.problem !== null}>
                  <div class="done" style:width="{firmware.problem ? 100 : percent}%"></div>
                </div>
                <span class="muted" class:bad={firmware.problem !== null}>
                  {#if firmware.problem}
                    Stopped at {firmware.sent} of {firmware.total} bytes: {firmware.problem}
                  {:else if firmware.done}
                    All {firmware.total} bytes are on the device: Update runs them.
                  {:else}
                    {percent}% · {firmware.sent} of {firmware.total} bytes
                  {/if}
                </span>
              {/if}
              <div class="fields">
                <input
                  class="field mono grow"
                  spellcheck="false"
                  placeholder="Or an address it fetches: coap://192.168.1.10/fw.bin"
                  title="Written to /5/0/1, Package URI: the device fetches the image itself"
                  bind:value={setup.uri}
                  onchange={save}
                />
                <button class="btn small" title="Write the address to /5/0/1" onclick={() => ask({ what: "firmware-uri", uri: setup.uri })}>Fetch</button>
              </div>
              <div class="fields">
                <button class="btn small primary" title="Execute /5/0/2: the device updates to the image it has" onclick={() => ask({ what: "execute", path: "/5/0/2" })}>Update</button>
                <button class="btn small" title="Observe its state, the update's result and the version it runs" onclick={watchFirmware}>Watch</button>
                <span class="muted">State: {shown("/5/0/3")} · Result: {shown("/5/0/5")}</span>
              </div>
            </section>
          {/if}
        {:else}
          <p class="empty">The devices that register are listed on the left: choose one to read, write, observe and execute its resources, and to update its firmware.</p>
        {/if}
      </div>

      <div class="main">
        <div class="head">
          <h3>Requests</h3>
          <span class="spacer"></span>
          <button class="btn small" onclick={() => session.clearLog()}>Clear</button>
        </div>
        <div class="list">
          {#each session.log as entry (entry.id)}
            <div class="entry" title={entry.text}>
              <div class="entry-line">
                <span class="mono muted">{time(entry.at)}</span>
                <span class="mono dir" title={entry.kind === "asked" ? "The server asked" : "A device asked"}>{entry.kind === "asked" ? "→" : "←"}</span>
                <span class="mono">{entry.what}</span>
                <span class="mono">{entry.path}</span>
                {#if entry.problem}
                  <span class="bad">{entry.problem}</span>
                {:else if entry.code}
                  <span class="mono" class:good={entry.ok} class:bad={!entry.ok}>{entry.code}</span>
                {:else}
                  <span class="muted">…</span>
                {/if}
                {#if entry.ms !== null}
                  <span class="muted">{ms(entry.ms)}</span>
                {/if}
                {#if entry.notifications > 0}
                  <span class="muted">{entry.notifications} {entry.notifications === 1 ? "change" : "changes"}</span>
                {/if}
                <span class="muted" title="The device">{entry.endpoint}</span>
              </div>
              {#if entry.detail || entry.text}
                <div class="mono value muted">{oneLine([entry.detail, entry.text].filter(Boolean).join(" → "))}</div>
              {/if}
            </div>
          {:else}
            <p class="empty">Each request the server makes is listed here with its answer, and each one a device makes of it.</p>
          {/each}
        </div>
      </div>
    </div>
  {:else}
    <div class="bar">
      <span class="state" class:good={registered}>{deviceState}</span>
      {#if session.device}
        <span>{session.device.endpoint} · lifetime {session.device.lifetime} s</span>
      {/if}
      <span class="spacer"></span>
      {#if session.problem}
        <span class="bad problem">{session.problem}</span>
      {/if}
      <button class="btn small" disabled={!tab.connected} title="Register with the server again" onclick={() => void session.act("register")}>Register</button>
      <button class="btn small" disabled={!registered} title="Update the registration now" onclick={() => void session.act("update")}>Update</button>
      <button class="btn small" disabled={!registered} title="Leave the server" onclick={() => void session.act("deregister")}>Deregister</button>
      <button class="btn small" disabled={!tab.connected} title="Ask the server for bootstrap, then register where it says" onclick={() => void session.act("bootstrap")}>
        Bootstrap
      </button>
    </div>

    <div class="body two">
      <div class="side">
        {#each deviceInstances as [instance, resources] (instance)}
          {@const object = parsePath(instance)?.[0] ?? 0}
          <section class="instance">
            <div class="instance-head">
              <span class="title">{objectName(object)}</span>
              <span class="mono muted">{instance}</span>
            </div>
            {#each resources as resource (resource.path)}
              {@const id = parsePath(resource.path)?.[2] ?? 0}
              <div class="line">
                <span class="mono id">{id}</span>
                <span class="label" title="{resource.path}, {resource.kind}">{resourceName(object, id) || resource.path}</span>
                <input
                  class="field mono value-field"
                  spellcheck="false"
                  title="Its value: Enter changes it, and the server is told if it observes it"
                  value={editing[resource.path] ?? resource.value}
                  oninput={(event) => (editing[resource.path] = event.currentTarget.value)}
                  onkeydown={(event) => event.key === "Enter" && set(resource.path)}
                />
                {#if editing[resource.path] !== undefined}
                  <button class="btn small primary" onclick={() => set(resource.path)}>Set</button>
                {:else if meaning(resource.path, resource.value)}
                  <span class="muted means">{meaning(resource.path, resource.value)}</span>
                {/if}
                {#if serverObserves(resource.path)}
                  <span class="badge" title="The server observes it: each change goes to it">observed</span>
                {/if}
              </div>
            {/each}
          </section>
        {:else}
          <p class="empty">Start the tab: the device registers with the server at once, or bootstraps first, and its resources are listed here to change.</p>
        {/each}
      </div>
      <div class="main">
        <div class="head">
          <h3>What the server asked</h3>
          <span class="spacer"></span>
          <button class="btn small" onclick={() => session.clearHeard()}>Clear</button>
        </div>
        <div class="list">
          {#each session.heard as each (each.id)}
            <div class="entry">
              <div class="entry-line">
                <span class="mono muted">{time(each.at)}</span>
                <span class="mono">{each.what}</span>
                <span class="mono name">{each.path}</span>
                <span class="mono" class:good={each.ok} class:bad={!each.ok}>{each.code}</span>
              </div>
              {#if each.detail}
                <div class="mono value muted">{oneLine(each.detail)}</div>
              {/if}
            </div>
          {:else}
            <p class="empty">Each read, write, observe and execute the server sends is listed here, with what the device answered.</p>
          {/each}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .lwm2mview {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    font-size: 12px;
    outline: none;
  }

  .bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 10px;
    padding-bottom: 6px;
    color: var(--muted);
  }

  .state {
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .state.good {
    color: var(--good, var(--accent));
    border-color: currentColor;
  }

  .problem {
    max-width: 50%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .option {
    display: flex;
    gap: 6px;
    align-items: center;
    white-space: nowrap;
  }

  .bar .field {
    height: 24px;
    font-size: 12px;
  }

  .small {
    height: 24px;
    padding: 0 10px;
    font-size: 12px;
  }

  .spacer {
    flex: 1;
  }

  .body {
    display: grid;
    flex: 1;
    gap: 12px;
    min-height: 0;
  }

  .body.three {
    grid-template-columns: minmax(150px, 1fr) minmax(360px, 3fr) minmax(0, 2fr);
  }

  .body.two {
    grid-template-columns: minmax(340px, 3fr) minmax(0, 2fr);
  }

  .devices,
  .side {
    min-width: 0;
    min-height: 0;
    padding-right: 4px;
    overflow-x: hidden;
    overflow-y: auto;
  }

  .main {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }

  h3 {
    margin: 0 0 6px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    color: var(--muted);
    text-transform: uppercase;
  }

  .head {
    display: flex;
    gap: 10px;
    align-items: center;
    margin-bottom: 6px;
  }

  .head h3 {
    margin: 0;
  }

  .device {
    display: flex;
    flex-direction: column;
    gap: 1px;
    width: 100%;
    margin-bottom: 4px;
    padding: 6px 8px;
    font: inherit;
    color: var(--text);
    text-align: left;
    background: none;
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: default;
  }

  .device:hover {
    background: var(--hover);
  }

  .device.on {
    border-color: var(--accent);
  }

  .device .name {
    font-weight: 600;
  }

  .fields {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
    min-width: 0;
    margin-bottom: 6px;
  }

  .fields .field {
    height: 26px;
    font-size: 12px;
  }

  .fields .btn {
    height: 26px;
  }

  .path {
    flex: 0 1 150px;
    min-width: 90px;
  }

  .grow {
    flex: 1 1 140px;
    min-width: 100px;
  }

  .instance {
    margin: 8px 0 4px;
    padding: 6px 8px 4px;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .instance-head {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 4px;
  }

  .instance-head .title {
    font-weight: 600;
  }

  .line {
    display: flex;
    gap: 8px;
    align-items: center;
    min-width: 0;
    padding: 3px 0;
    border-top: 1px solid var(--border);
  }

  .line .field {
    height: 24px;
    font-size: 12px;
  }

  .id {
    flex: 0 0 34px;
    color: var(--muted);
    text-align: right;
  }

  .label {
    flex: 0 1 170px;
    min-width: 60px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .value-field {
    flex: 1;
    min-width: 60px;
  }

  .means {
    flex: 0 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .icon {
    width: 24px;
    height: 24px;
    padding: 0;
    font-size: 14px;
    color: var(--muted);
    background: none;
    border: 0;
    border-radius: 5px;
    cursor: default;
  }

  .icon:hover {
    color: var(--text);
    background: var(--hover);
  }

  .watching {
    color: var(--accent);
  }

  .btn.watching {
    border-color: var(--accent);
  }

  .badge {
    padding: 0 6px;
    font-size: 11px;
    color: var(--accent);
    border: 1px solid currentColor;
    border-radius: 9px;
  }

  .progress {
    height: 6px;
    margin: 2px 0 4px;
    overflow: hidden;
    background: var(--panel);
    border-radius: 3px;
  }

  .progress .done {
    height: 100%;
    background: var(--accent);
    transition: width 0.2s;
  }

  .progress.failed .done {
    background: var(--bad);
  }

  .name {
    overflow: hidden;
    color: var(--text);
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .value {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .muted {
    color: var(--muted);
  }

  .good {
    color: var(--good, var(--accent));
  }

  .bad {
    color: var(--bad);
  }

  .empty {
    margin: 6px 8px;
    color: var(--muted);
  }

  .list {
    flex: 1;
    min-height: 60px;
    padding: 2px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .entry {
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
  }

  /* In a narrow column, a line goes on under itself a word at a time. */
  .entry-line {
    display: flex;
    flex-wrap: wrap;
    gap: 2px 8px;
    align-items: baseline;
    min-width: 0;
  }

  .entry-line > span {
    flex: none;
    white-space: nowrap;
  }

  .dir {
    color: var(--muted);
  }

  @media (max-width: 980px) {
    .body.three,
    .body.two {
      grid-template-columns: 1fr;
      overflow: auto;
    }
  }
</style>
