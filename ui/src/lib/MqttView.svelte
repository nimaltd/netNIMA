<script lang="ts">
  import { onMount } from "svelte";
  import { listed, showPayload, type PayloadFormat } from "./mqtt";
  import { changed, type Tab } from "./tabs.svelte";
  import { clearActiveTerminal, setActiveTerminal, type TerminalActions } from "./terminal-actions";

  // An MQTT tab's own view, beside its terminal: the messages to publish,
  // each with its Send; a client's subscriptions, or a broker's clients and
  // retained messages; and every topic heard, with its last messages. It
  // asks the tab's engine with the lines a person would type, so the
  // terminal shows what goes and comes as before.
  let {
    tab,
    active,
  }: {
    tab: Tab;
    /** Whether this view has the keyboard. */
    active: boolean;
  } = $props();

  const setup = $derived(tab.mqttSetup);
  const session = $derived(tab.mqtt);
  const broker = $derived(tab.kind === "mqtt_server");

  const FORMATS: { value: PayloadFormat; label: string }[] = [
    { value: "auto", label: "Auto" },
    { value: "text", label: "Text" },
    { value: "hex", label: "Hex" },
    { value: "json", label: "JSON" },
  ];

  let root: HTMLDivElement | undefined = $state();
  /** Words to find topics by, in their names or their last values. */
  let find = $state("");
  let newFilter = $state("");
  let newQos = $state(0);

  // The topics are plain values, for speed: `version` changes as messages come.
  const topics = $derived.by(() => {
    void session.version;
    return listed(session.topics, find);
  });
  const picked = $derived.by(() => {
    void session.version;
    return session.picked === null ? null : (session.topics.get(session.picked) ?? null);
  });
  const clients = $derived(Object.values(session.clients));
  const retained = $derived(Object.entries(session.retained).sort(([a], [b]) => a.localeCompare(b)));

  function save() {
    changed();
  }

  function addPublish() {
    const last = setup.publishes.at(-1);
    setup.publishes.push({ topic: last?.topic ?? "sensors/temp", qos: last?.qos ?? 0, retain: false, payload: "", hex: false });
    save();
  }

  function removePublish(index: number) {
    setup.publishes.splice(index, 1);
    session.results.splice(index, 1);
    save();
  }

  /** Adds a subscription to the list, made now if connected and each time the client connects. */
  function addSubscription() {
    const filter = newFilter.trim();
    if (!filter) return;
    if (!setup.subscriptions.some((each) => each.filter === filter)) {
      setup.subscriptions.push({ filter, qos: newQos });
      save();
    }
    newFilter = "";
    if (tab.connected) void session.subscribe(filter, newQos);
  }

  function removeSubscription(index: number) {
    const [gone] = setup.subscriptions.splice(index, 1);
    save();
    if (gone && tab.connected) void session.unsubscribe(gone.filter);
  }

  function time(at: number): string {
    const date = new Date(at);
    const two = (value: number) => String(value).padStart(2, "0");
    return `${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())}.${String(date.getMilliseconds()).padStart(3, "0")}`;
  }

  /** A payload on one line, as a list shows it. */
  function oneLine(payload: Uint8Array): string {
    return showPayload(payload, setup.format).text.replace(/\s*\r?\n\s*/g, " ⏎ ");
  }

  const actions: TerminalActions = {
    hasSelection: () => false,
    copy: async () => {},
    paste: async () => {},
    selectAll: () => {},
    clear: () => session.clearTopics(),
    text: () =>
      topics
        .flatMap((state) => state.history.map((message) => `${time(message.at)} ${state.topic} ${oneLine(message.payload)}`))
        .join("\n") + "\n",
    focus: () => root?.focus(),
    openSearch: () => {},
    findNext: () => {},
    findPrevious: () => {},
  };

  // The view on screen is the one the menus act on.
  $effect(() => {
    if (active) setActiveTerminal(actions);
  });

  onMount(() => () => clearActiveTerminal(actions));
</script>

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div class="mqttview" tabindex="0" role="region" aria-label="MQTT" bind:this={root}>
  <div class="bar">
    {#if broker}
      <span class="state">{clients.length === 1 ? "1 client" : `${clients.length} clients`} connected</span>
    {:else}
      <span class="state" class:good={session.accepted === true} class:bad={session.accepted === false}>
        {session.accepted === true
          ? "Connected: the broker took it"
          : session.accepted === false
            ? `Refused: ${session.reason}`
            : tab.connected
              ? "Waiting for CONNACK"
              : "Not connected"}
      </span>
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
    <span class="stats">{session.heard} messages · {topics.length} topics</span>
    <button class="btn small" title="Forget the messages heard" onclick={() => session.clearTopics()}>Clear</button>
  </div>

  <div class="body">
    <div class="side">
      <section>
        <h3>Publish</h3>
        {#each setup.publishes as row, index (index)}
          {@const result = session.results[index]}
          <!-- The topic and how it goes; the payload; then Publish and what it got. -->
          <div class="publish">
            <div class="fields">
              <input class="field mono topic" spellcheck="false" placeholder="topic" title="The topic" bind:value={row.topic} onchange={save} />
              <select class="field" title="QoS: 0 at most once, 1 at least once, 2 exactly once" bind:value={row.qos} onchange={save}>
                <option value={0}>QoS 0</option>
                <option value={1}>QoS 1</option>
                <option value={2}>QoS 2</option>
              </select>
              <label class="check" title="The broker keeps it, and gives it to those who subscribe later">
                <input type="checkbox" bind:checked={row.retain} onchange={save} /> Retain
              </label>
              <button class="icon" title="Remove" onclick={() => removePublish(index)}>×</button>
            </div>
            <div class="fields top">
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
              <textarea
                class="field mono payload-field"
                rows="2"
                spellcheck="false"
                placeholder={row.hex ? "01 02 ff" : 'The payload, such as 21.5 or {"t": 21.5}'}
                title="Ctrl+Enter publishes it"
                bind:value={row.payload}
                onchange={save}
                onkeydown={(event) => {
                  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                    event.preventDefault();
                    void session.publish(index);
                  }
                }}
              ></textarea>
            </div>
            <div class="fields">
              <button class="btn small primary" disabled={!tab.connected} onclick={() => void session.publish(index)}>Publish</button>
              {#if result}
                <span class="outcome" class:bad={!result.ok}>{time(result.at)} · {result.text}</span>
              {/if}
            </div>
          </div>
        {/each}
        <button class="btn small" onclick={addPublish}>Add a message</button>
      </section>

      {#if broker}
        <section>
          <h3>Clients</h3>
          {#each clients as client (client.peer)}
            <div class="client">
              <div class="line">
                <span class="mono name">{client.clientId}</span>
                <span class="spacer"></span>
                <button class="btn small" title="Close its connection" onclick={() => void session.kick(client.peer)}>Close</button>
              </div>
              <div class="muted">
                {client.address} · {client.version}{client.keepAlive ? ` · keep-alive ${client.keepAlive} s` : ""}{client.will
                  ? ` · will on ${client.will}`
                  : ""}
              </div>
              <div class="muted mono">
                {Object.keys(client.filters).length > 0
                  ? Object.entries(client.filters)
                      .map(([filter, qos]) => `${filter} (QoS ${qos})`)
                      .join(", ")
                  : "no subscriptions yet"}
              </div>
            </div>
          {:else}
            <p class="empty">No client is connected. Those that connect are listed here, with what they subscribe to.</p>
          {/each}
        </section>
        <section>
          <h3>Retained</h3>
          {#each retained as [topic, kept] (topic)}
            <div class="line retained">
              <span class="mono name">{topic}</span>
              <span class="mono value">{oneLine(kept.payload)}</span>
              <button class="icon" title="Forget it" onclick={() => void session.clearRetained(topic)}>×</button>
            </div>
          {:else}
            <p class="empty">No message is retained. A message published with Retain is kept here for later subscribers.</p>
          {/each}
        </section>
      {:else}
        <section>
          <h3>Subscriptions</h3>
          {#each setup.subscriptions as subscription, index (subscription.filter)}
            {@const answer = session.granted[subscription.filter]}
            <div class="line">
              <span class="mono name">{subscription.filter}</span>
              <span class="muted">QoS {subscription.qos}</span>
              <span class="answer" class:bad={answer !== undefined && !answer.ok}>
                {answer?.text ?? (tab.connected ? "" : "made when it connects")}
              </span>
              <span class="spacer"></span>
              <button class="icon" title="Unsubscribe, and take it off the list" onclick={() => removeSubscription(index)}>×</button>
            </div>
          {/each}
          <div class="fields add">
            <input
              class="field mono topic"
              spellcheck="false"
              placeholder="sensors/# or board/+/state"
              title="A topic filter: + takes one level, # the rest"
              bind:value={newFilter}
              onkeydown={(event) => event.key === "Enter" && addSubscription()}
            />
            <select class="field" title="The most QoS the messages come with" bind:value={newQos}>
              <option value={0}>QoS 0</option>
              <option value={1}>QoS 1</option>
              <option value={2}>QoS 2</option>
            </select>
            <button class="btn small" onclick={addSubscription}>Subscribe</button>
          </div>
        </section>
      {/if}
    </div>

    <div class="main">
      <section class="topics">
        <div class="head">
          <h3>Messages</h3>
          <input class="field find" spellcheck="false" placeholder="Find a topic or a value" bind:value={find} />
        </div>
        <div class="list">
          {#each topics as state (state.topic)}
            {@const last = state.history[0]}
            <button class="heard" class:on={session.picked === state.topic} onclick={() => (session.picked = state.topic)}>
              <span class="mono name">{state.topic}</span>
              <span class="mono value">{oneLine(last.payload)}</span>
              <span class="count" title="How many came">{state.count}</span>
              <span class="mono when">{time(last.at)}</span>
            </button>
          {:else}
            <p class="empty">
              {broker
                ? "Every message a client publishes, or this broker does, is listed here by its topic, with its last value."
                : "The messages that come on the subscriptions are listed here by their topics, with their last values. Pick one to see its last messages."}
            </p>
          {/each}
        </div>
      </section>
      {#if picked}
        <section class="history">
          <div class="head">
            <h3 class="mono">{picked.topic}</h3>
            <span class="muted">the last {picked.history.length} of {picked.count}</span>
          </div>
          <div class="list">
            {#each picked.history as message, index (index)}
              {@const shown = showPayload(message.payload, setup.format, true)}
              <div class="message">
                <div class="muted">
                  <span class="mono">{time(message.at)}</span>
                  · QoS {message.qos}{message.retain ? " · retained" : ""}{message.from !== undefined
                    ? ` · from ${message.from || "this broker"}`
                    : ""} · {message.payload.length} bytes{shown.as === "text" ? "" : ` · ${shown.as === "json" ? "JSON" : "hex"}`}
                </div>
                <pre class="mono payload">{shown.text}</pre>
              </div>
            {/each}
          </div>
        </section>
      {/if}
    </div>
  </div>
</div>

<style>
  .mqttview {
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
    border-color: var(--good, var(--accent));
  }

  .state.bad,
  .bad {
    color: var(--bad);
  }

  .state.bad {
    border-color: var(--bad);
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

  .stats {
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .body {
    display: grid;
    flex: 1;
    grid-template-columns: minmax(320px, 2fr) minmax(0, 3fr);
    gap: 12px;
    min-height: 0;
  }

  /* Its own scroll, down only: what is wide is cut short instead. */
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
    gap: 10px;
    min-width: 0;
    min-height: 0;
  }

  section {
    margin-bottom: 12px;
  }

  h3 {
    margin: 0 0 6px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    color: var(--muted);
    text-transform: uppercase;
  }

  h3.mono {
    text-transform: none;
    letter-spacing: 0;
    color: var(--text);
  }

  .publish {
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

  .topic {
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
    gap: 10px;
    align-items: center;
    min-width: 0;
    padding: 4px 0;
    border-bottom: 1px solid var(--border);
  }

  .client {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 2px 0 6px;
    border-bottom: 1px solid var(--border);
  }

  .client .line {
    border-bottom: 0;
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

  .answer {
    color: var(--muted);
  }

  .muted {
    color: var(--muted);
  }

  .empty {
    margin: 4px 0;
    color: var(--muted);
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

  .find {
    flex: 1;
    max-width: 280px;
    height: 24px;
    font-size: 12px;
  }

  .topics,
  .history {
    display: flex;
    flex: 1;
    flex-direction: column;
    min-height: 0;
    margin: 0;
  }

  .list {
    flex: 1;
    min-height: 60px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .topics .list {
    padding: 2px;
  }

  .heard {
    display: grid;
    grid-template-columns: minmax(120px, 2fr) minmax(0, 3fr) 48px 96px;
    gap: 10px;
    align-items: center;
    width: 100%;
    padding: 4px 8px;
    font: inherit;
    color: var(--text);
    text-align: left;
    background: none;
    border: 0;
    border-radius: 5px;
    cursor: default;
  }

  .heard:hover {
    background: var(--hover);
  }

  .heard.on {
    background: var(--accent-soft);
  }

  .count {
    color: var(--muted);
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .when {
    color: var(--muted);
    text-align: right;
  }

  .message {
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
  }

  pre.payload {
    margin: 4px 0 0;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
  }

  @media (max-width: 820px) {
    .body {
      grid-template-columns: 1fr;
      overflow: auto;
    }
  }
</style>
