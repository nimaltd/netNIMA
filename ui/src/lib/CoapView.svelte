<script lang="ts">
  import { onMount } from "svelte";
  import { showPayload, type PayloadFormat } from "./mqtt";
  import { COAP_FORMATS, COAP_METHODS, DEFAULT_COAP_ROW } from "./requests";
  import { changed, type Tab } from "./tabs.svelte";
  import { clearActiveTerminal, setActiveTerminal, type TerminalActions } from "./terminal-actions";

  // A CoAP tab's own view, beside its terminal: a client's requests, each in
  // a row with the answer it got under it, and what Discover found; or a
  // server's resources, to change, and the requests it heard. It asks the
  // tab's engine with the lines a person would type.
  let {
    tab,
    active,
  }: {
    tab: Tab;
    /** Whether this view has the keyboard. */
    active: boolean;
  } = $props();

  const setup = $derived(tab.coapSetup);
  const session = $derived(tab.coap);
  const server = $derived(tab.kind.endsWith("_server"));

  const FORMATS: { value: PayloadFormat; label: string }[] = [
    { value: "auto", label: "Auto" },
    { value: "text", label: "Text" },
    { value: "hex", label: "Hex" },
    { value: "json", label: "JSON" },
  ];

  let root: HTMLDivElement | undefined = $state();
  let newPath = $state("");
  let newValue = $state("");
  /** The values being typed for resources, by path, until they are set. */
  let editing: Record<string, string> = $state({});

  function save() {
    changed();
  }

  function addRequest(path = setup.requests.at(-1)?.path ?? DEFAULT_COAP_ROW.path, method: "GET" | "OBSERVE" = "GET") {
    setup.requests.push({ ...DEFAULT_COAP_ROW, path, method });
    save();
  }

  function removeRequest(index: number) {
    setup.requests.splice(index, 1);
    session.results.splice(index, 1);
    save();
  }

  function setResource(path: string, value: string) {
    void session.set(path, value);
    delete editing[path];
  }

  function addResource() {
    if (!newPath.trim()) return;
    void session.set(newPath, newValue);
    newPath = "";
    newValue = "";
  }

  function time(at: number): string {
    const date = new Date(at);
    const two = (value: number) => String(value).padStart(2, "0");
    return `${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())}.${String(date.getMilliseconds()).padStart(3, "0")}`;
  }

  const oneLine = (payload: Uint8Array) => showPayload(payload, setup.format).text.replace(/\s*\r?\n\s*/g, " ⏎ ");
  const ms = (value: number) => `${Number(value.toFixed(1))} ms`;

  const actions: TerminalActions = {
    hasSelection: () => false,
    copy: async () => {},
    paste: async () => {},
    selectAll: () => {},
    clear: () => session.clearHeard(),
    text: () => session.heard.map((each) => `${time(each.at)} ${each.method} ${each.path} ${each.answer}`).join("\n") + "\n",
    focus: () => root?.focus(),
    openSearch: () => {},
    findNext: () => {},
    findPrevious: () => {},
  };

  $effect(() => {
    if (active) setActiveTerminal(actions);
  });

  onMount(() => () => clearActiveTerminal(actions));
</script>

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div class="requestsview" tabindex="0" role="region" aria-label="CoAP" bind:this={root}>
  <div class="bar">
    {#if server}
      <span class="state">{session.resources.length} resources · {session.heard.length} requests heard</span>
    {:else}
      <button class="btn small" disabled={!tab.connected} title="Ask the server for /.well-known/core: its resources" onclick={() => void session.discover()}>
        Discover
      </button>
      <button class="btn small" disabled={!tab.connected} title="An empty CON, which a CoAP server answers with RST" onclick={() => void session.ping()}>
        Ping
      </button>
      {#if session.pinged}
        <span class="muted">{time(session.pinged.at)} · {session.pinged.text}</span>
      {/if}
    {/if}
    <span class="spacer"></span>
    <label class="option" title="How payloads are shown: Auto shows JSON as JSON, text as text, and the rest in hex">
      Show
      <select class="field" bind:value={setup.format} onchange={save}>
        {#each FORMATS as { value, label } (value)}
          <option {value}>{label}</option>
        {/each}
      </select>
    </label>
  </div>

  {#if server}
    <div class="body two">
      <div class="side">
        <section>
          <h3>Resources</h3>
          {#each session.resources as resource (resource.path)}
            <div class="line">
              <span class="mono name">{resource.path}</span>
              <input
                class="field mono value-field"
                spellcheck="false"
                title="Its value: Enter sets it, and its observers are told"
                value={editing[resource.path] ?? new TextDecoder().decode(resource.value)}
                oninput={(event) => (editing[resource.path] = event.currentTarget.value)}
                onkeydown={(event) => event.key === "Enter" && setResource(resource.path, event.currentTarget.value)}
              />
              {#if editing[resource.path] !== undefined}
                <button class="btn small primary" onclick={() => setResource(resource.path, editing[resource.path])}>Set</button>
              {/if}
              <span class="muted" title="Who observes it">{resource.observers ? `${resource.observers} observing` : ""}</span>
              <button class="icon" title="Remove it" onclick={() => void session.remove(resource.path)}>×</button>
            </div>
          {:else}
            <p class="empty">No resource yet: add one, or a client can PUT one.</p>
          {/each}
          <div class="fields add">
            <input class="field mono grow" spellcheck="false" placeholder="/sensors/temp" bind:value={newPath} />
            <input
              class="field mono grow"
              spellcheck="false"
              placeholder="its value"
              bind:value={newValue}
              onkeydown={(event) => event.key === "Enter" && addResource()}
            />
            <button class="btn small" onclick={addResource}>Add</button>
          </div>
        </section>
      </div>
      <div class="main">
        <div class="head">
          <h3>Requests heard</h3>
          <span class="spacer"></span>
          <button class="btn small" onclick={() => session.clearHeard()}>Clear</button>
        </div>
        <div class="list">
          {#each session.heard as each, index (index)}
            <div class="heard">
              <span class="mono muted">{time(each.at)}</span>
              <span class="mono">{each.method}</span>
              <span class="mono name">{each.path}</span>
              <span class="mono" class:good={each.ok} class:bad={!each.ok}>{each.answer}</span>
              {#if each.payload.length > 0}
                <span class="mono value">{oneLine(each.payload)}</span>
              {/if}
            </div>
          {:else}
            <p class="empty">Each request a client makes is listed here, with what this server answered.</p>
          {/each}
        </div>
      </div>
    </div>
  {:else}
    <div class="body two">
      <div class="side">
        <section>
          <h3>Requests</h3>
          {#each setup.requests as row, index (index)}
            {@const result = session.results[index]}
            {@const body = row.method === "POST" || row.method === "PUT"}
            <div class="request">
              <div class="fields">
                <select class="field" title="The method; Observe is a GET that gets each change" bind:value={row.method} onchange={save}>
                  {#each COAP_METHODS as method (method)}
                    <option value={method}>{method === "OBSERVE" ? "Observe" : method}</option>
                  {/each}
                </select>
                <input class="field mono grow" spellcheck="false" placeholder="/sensors/temp" title="The path; it may have a ?query" bind:value={row.path} onchange={save} />
                <label class="check" title="NON: not confirmed, and not sent again">
                  <input type="checkbox" bind:checked={row.non} onchange={save} /> NON
                </label>
                <button class="icon" title="Remove" onclick={() => removeRequest(index)}>×</button>
              </div>
              {#if body}
                <div class="fields top">
                  <select class="field" title="The payload's content format" bind:value={row.format} onchange={save}>
                    {#each COAP_FORMATS as format (format)}
                      <option value={format}>{format || "no format"}</option>
                    {/each}
                  </select>
                  <select
                    class="field"
                    title="The payload as text, with \r \n \xHH for bytes, or as hex bytes"
                    value={row.hex ? "hex" : "text"}
                    onchange={(event) => {
                      row.hex = event.currentTarget.value === "hex";
                      save();
                    }}
                  >
                    <option value="text">Text</option>
                    <option value="hex">Hex</option>
                  </select>
                  <textarea class="field mono payload-field" rows="2" spellcheck="false" placeholder={row.hex ? "01 02 ff" : "the payload"} bind:value={row.payload} onchange={save}></textarea>
                </div>
              {/if}
              <div class="fields">
                <button class="btn small primary" disabled={!tab.connected} onclick={() => void session.send(index)}>Send</button>
                {#if row.method === "OBSERVE" && result?.observe !== null && result?.observe !== undefined}
                  <button class="btn small" title="Stop observing it" onclick={() => void session.cancel(index)}>Cancel</button>
                {/if}
                <select class="field" title="The format wanted back" bind:value={row.accept} onchange={save}>
                  {#each COAP_FORMATS as format (format)}
                    <option value={format}>{format ? `accept ${format}` : "accept any"}</option>
                  {/each}
                </select>
                {#if result}
                  <span class="outcome" class:bad={!result.ok}>
                    {time(result.at)} ·
                    {#if result.problem}
                      {result.problem}
                    {:else}
                      {result.code}{result.ms !== null ? ` · ${ms(result.ms)}` : ""}{result.format ? ` · ${result.format}` : ""}{result.blocks
                        ? ` · ${result.blocks} blocks`
                        : ""}{result.observe !== null ? ` · observed, ${result.notifications} so far` : ""}
                    {/if}
                  </span>
                {/if}
              </div>
              {#if result && !result.problem && result.payload.length > 0}
                <pre class="mono payload">{showPayload(result.payload, setup.format, true).text}</pre>
              {/if}
            </div>
          {/each}
          <button class="btn small" onclick={() => addRequest()}>Add a request</button>
        </section>
      </div>
      <div class="main">
        <div class="head">
          <h3>On the server</h3>
          <span class="muted">{session.discovered === null ? "Discover lists its resources." : `${session.discovered.length} resources`}</span>
        </div>
        <div class="list">
          {#each session.discovered ?? [] as link (link.path)}
            <div class="heard">
              <span class="mono name">{link.path}</span>
              <span class="mono muted value">{link.attributes}</span>
              <button class="btn small" title="Add a request that gets it" onclick={() => addRequest(link.path)}>GET</button>
              {#if link.attributes.split(";").includes("obs")}
                <button class="btn small" title="Add a request that observes it" onclick={() => addRequest(link.path, "OBSERVE")}>Observe</button>
              {/if}
            </div>
          {:else}
            <p class="empty">Discover asks the server for /.well-known/core: its resources are listed here, each ready to GET or observe.</p>
          {/each}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .requestsview {
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

  .option,
  .check {
    display: flex;
    gap: 6px;
    align-items: center;
    white-space: nowrap;
  }

  .check:has(input:checked) {
    color: var(--text);
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

  .body.two {
    display: grid;
    flex: 1;
    grid-template-columns: minmax(340px, 3fr) minmax(0, 2fr);
    gap: 12px;
    min-height: 0;
  }

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

  .request {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 6px 0 8px;
    border-bottom: 1px solid var(--border);
  }

  .fields {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
    min-width: 0;
  }

  .fields.top {
    flex-wrap: nowrap;
    align-items: flex-start;
  }

  .fields .field {
    height: 26px;
    font-size: 12px;
  }

  .fields .btn {
    height: 26px;
  }

  .grow {
    flex: 1 1 140px;
    min-width: 100px;
  }

  .fields .payload-field {
    flex: 1;
    min-width: 0;
    height: auto;
    min-height: 44px;
    padding: 4px 8px;
    resize: vertical;
  }

  .outcome {
    min-width: 0;
    overflow: hidden;
    color: var(--muted);
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .add {
    margin-top: 8px;
  }

  .icon {
    width: 24px;
    height: 24px;
    padding: 0;
    font-size: 15px;
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

  .line {
    display: flex;
    gap: 8px;
    align-items: center;
    min-width: 0;
    padding: 4px 0;
    border-bottom: 1px solid var(--border);
  }

  .line .field {
    height: 24px;
    font-size: 12px;
  }

  .value-field {
    flex: 1;
    min-width: 60px;
  }

  .name {
    overflow: hidden;
    color: var(--text);
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .value {
    flex: 1;
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

  .heard {
    display: flex;
    gap: 10px;
    align-items: center;
    min-width: 0;
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
  }

  pre.payload {
    margin: 2px 0 0;
    padding: 6px 8px;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    background: var(--panel);
    border-radius: 5px;
  }

  @media (max-width: 820px) {
    .body.two {
      grid-template-columns: 1fr;
      overflow: auto;
    }
  }
</style>
