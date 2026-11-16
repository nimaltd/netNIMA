<script lang="ts">
  import { onMount } from "svelte";
  import { showPayload, type PayloadFormat } from "./mqtt";
  import { DEFAULT_HTTP_ROW, HTTP_METHODS, statusClass } from "./requests";
  import { changed, type Tab } from "./tabs.svelte";
  import { clearActiveTerminal, setActiveTerminal, type TerminalActions } from "./terminal-actions";

  // An HTTP tab's own view, beside its terminal: a client's requests, each
  // in a row with the response it got under it, and the headers every
  // request has; or a server's routes, to add and drop, and the requests it
  // answered. It asks the tab's engine with the lines a person would type.
  let {
    tab,
    active,
  }: {
    tab: Tab;
    /** Whether this view has the keyboard. */
    active: boolean;
  } = $props();

  const setup = $derived(tab.httpSetup);
  const session = $derived(tab.http);
  const server = $derived(tab.kind === "http_server");

  const FORMATS: { value: PayloadFormat; label: string }[] = [
    { value: "auto", label: "Auto" },
    { value: "text", label: "Text" },
    { value: "hex", label: "Hex" },
    { value: "json", label: "JSON" },
  ];

  let root: HTMLDivElement | undefined = $state();
  let headerName = $state("");
  let headerValue = $state("");
  let route = $state({ method: "GET", path: "/api/temp", status: 200, body: '{"t":21.5}' });
  let routeProblem = $state("");

  function save() {
    changed();
  }

  function addRequest() {
    const last = setup.requests.at(-1);
    setup.requests.push({ ...DEFAULT_HTTP_ROW, path: last?.path ?? DEFAULT_HTTP_ROW.path });
    save();
  }

  function removeRequest(index: number) {
    setup.requests.splice(index, 1);
    session.results.splice(index, 1);
    save();
  }

  function addHeader() {
    if (!headerName.trim()) return;
    void session.header(headerName, headerValue);
    headerName = "";
    headerValue = "";
  }

  async function addRoute() {
    routeProblem = await session.route(route);
  }

  function time(at: number): string {
    const date = new Date(at);
    const two = (value: number) => String(value).padStart(2, "0");
    return `${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())}.${String(date.getMilliseconds()).padStart(3, "0")}`;
  }

  const oneLine = (payload: Uint8Array) => showPayload(payload, setup.format).text.replace(/\s*\r?\n\s*/g, " ⏎ ");
  const header = (headers: [string, string][], name: string) =>
    headers.find(([found]) => found.toLowerCase() === name)?.[1] ?? "";

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
<div class="requestsview" tabindex="0" role="region" aria-label="HTTP" bind:this={root}>
  <div class="bar">
    {#if server}
      <span class="state">{session.routes.length} routes · {session.heard.length} requests answered</span>
    {:else}
      <span class="muted">Every request has</span>
      {#each session.headers as [name, value] (name)}
        <span class="chip mono">
          {name}: {value}
          <button class="icon" title="Drop it" onclick={() => void session.header(name, "")}>×</button>
        </span>
      {:else}
        <span class="muted">only Host, User-Agent and Accept</span>
      {/each}
      <input class="field mono short" spellcheck="false" placeholder="Header" bind:value={headerName} />
      <input
        class="field mono"
        spellcheck="false"
        placeholder="its value"
        bind:value={headerValue}
        onkeydown={(event) => event.key === "Enter" && addHeader()}
      />
      <button class="btn small" onclick={addHeader}>Add</button>
    {/if}
    <span class="spacer"></span>
    <label class="option" title="How bodies are shown: Auto shows JSON as JSON, text as text, and the rest in hex">
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
          <h3>Routes</h3>
          {#each session.routes as each (`${each.method} ${each.path}`)}
            <div class="line">
              <span class="mono">{each.method}</span>
              <span class="mono name">{each.path}</span>
              <span class="mono" class:good={statusClass(each.status) === 2} class:bad={statusClass(each.status) >= 4}>{each.status}</span>
              <span class="mono value" title={each.type}>{oneLine(each.body)}</span>
              <button class="icon" title="Drop the route" onclick={() => void session.unroute(each.method, each.path)}>×</button>
            </div>
          {:else}
            <p class="empty">No route: GET / lists the routes, POST /echo answers with what came, and a folder's files are served.</p>
          {/each}
          <div class="fields add">
            <select class="field" bind:value={route.method}>
              {#each HTTP_METHODS as method (method)}
                <option value={method}>{method}</option>
              {/each}
            </select>
            <input class="field mono grow" spellcheck="false" placeholder="/api/temp" bind:value={route.path} />
            <input class="field mono status" type="number" min="100" max="599" title="The status it answers with" bind:value={route.status} />
          </div>
          <div class="fields top">
            <textarea class="field mono payload-field" rows="2" spellcheck="false" placeholder="The body it answers with: JSON goes as JSON" bind:value={route.body}></textarea>
            <button class="btn small primary" onclick={() => void addRoute()}>Add</button>
          </div>
          {#if routeProblem}
            <p class="outcome bad">{routeProblem}</p>
          {/if}
        </section>
      </div>
      <div class="main">
        <div class="head">
          <h3>Requests answered</h3>
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
            <p class="empty">Each request a client makes is listed here, with the status it was answered with.</p>
          {/each}
        </div>
      </div>
    </div>
  {:else}
    <div class="body one">
      {#each setup.requests as row, index (index)}
        {@const result = session.results[index]}
        {@const body = row.method !== "GET" && row.method !== "HEAD"}
        <div class="request">
          <div class="fields">
            <select class="field" bind:value={row.method} onchange={save}>
              {#each HTTP_METHODS as method (method)}
                <option value={method}>{method}</option>
              {/each}
            </select>
            <input class="field mono grow" spellcheck="false" placeholder="/api/status" title="The path, with its ?query" bind:value={row.path} onchange={save} />
            <button class="btn small primary" disabled={!tab.connected} onclick={() => void session.send(index)}>Send</button>
            <button class="icon" title="Remove" onclick={() => removeRequest(index)}>×</button>
          </div>
          {#if body}
            <textarea
              class="field mono payload-field wide"
              rows="2"
              spellcheck="false"
              placeholder={'The body: one that starts with { or [ goes as JSON'}
              bind:value={row.body}
              onchange={save}
            ></textarea>
          {/if}
          {#if result}
            <div class="fields">
              <span class="outcome" class:good={statusClass(result.status) === 2} class:bad={result.problem !== null || statusClass(result.status) >= 4}>
                {time(result.at)} ·
                {#if result.problem}
                  {result.problem}
                {:else}
                  {result.start}{result.ms !== null ? ` · ${Number(result.ms.toFixed(1))} ms` : ""}{header(result.headers, "content-type")
                    ? ` · ${header(result.headers, "content-type")}`
                    : ""} · {result.body.length} bytes
                {/if}
              </span>
            </div>
            {#if !result.problem}
              <details>
                <summary class="muted">{result.headers.length} headers</summary>
                <pre class="mono headers">{result.headers.map(([name, value]) => `${name}: ${value}`).join("\n")}</pre>
              </details>
              {#if result.body.length > 0}
                <pre class="mono payload">{showPayload(result.body, setup.format, true).text}</pre>
              {/if}
            {/if}
          {/if}
        </div>
      {/each}
      <button class="btn small add" onclick={addRequest}>Add a request</button>
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

  .bar .field {
    height: 24px;
    font-size: 12px;
  }

  .short {
    width: 120px;
  }

  .state {
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .chip {
    display: inline-flex;
    gap: 4px;
    align-items: center;
    padding: 0 0 0 8px;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .option {
    display: flex;
    gap: 6px;
    align-items: center;
    white-space: nowrap;
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

  .body.one {
    flex: 1;
    min-height: 0;
    padding-right: 4px;
    overflow-x: hidden;
    overflow-y: auto;
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
    margin-top: 6px;
  }

  .fields .field {
    height: 26px;
    font-size: 12px;
  }

  .fields .btn {
    height: 26px;
  }

  .grow {
    flex: 1 1 160px;
    min-width: 100px;
  }

  .status {
    width: 72px;
  }

  .payload-field {
    flex: 1;
    min-width: 0;
    min-height: 44px;
    padding: 4px 8px;
    font-size: 12px;
    resize: vertical;
  }

  .fields .payload-field {
    height: auto;
  }

  .payload-field.wide {
    width: 100%;
  }

  .outcome {
    min-width: 0;
    margin: 0;
    overflow: hidden;
    color: var(--muted);
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .add {
    margin-top: 8px;
  }

  .icon {
    width: 22px;
    height: 22px;
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
    gap: 10px;
    align-items: center;
    min-width: 0;
    padding: 4px 0;
    border-bottom: 1px solid var(--border);
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
    color: var(--muted);
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

  details summary {
    cursor: default;
  }

  pre.headers,
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
