<script lang="ts">
  import { open } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import { baseName, flagsOf, shortHash, size, tasksOf, type Image } from "./mcumgr";
  import type { Answer, LogEntry } from "./mcumgr.svelte";
  import { changed, type Tab } from "./tabs.svelte";
  import { clearActiveTerminal, setActiveTerminal, type TerminalActions } from "./terminal-actions";

  // An MCUmgr tab's own view, beside its terminal. A client's: the board's
  // answers to echo, info, params, datetime and taskstat; its images, to
  // test and confirm; and an image to upload, with its progress; every
  // request with its answer beside. A simulated board's: its images, an
  // upload coming in, and what it was asked. It asks the tab's engine
  // with the lines a person would type.
  let {
    tab,
    active,
  }: {
    tab: Tab;
    /** Whether this view has the keyboard. */
    active: boolean;
  } = $props();

  const setup = $derived(tab.mcumgrSetup);
  const session = $derived(tab.mcumgr);
  const board = $derived(tab.kind === "mcumgr_server");

  let root: HTMLDivElement | undefined = $state();

  function save() {
    changed();
  }

  const upload = $derived(session.upload);
  const percent = $derived(upload && upload.total > 0 ? Math.floor((upload.sent * 100) / upload.total) : 0);
  const tasks = $derived(tasksOf(session.answers.taskstat?.body));
  const receivingPercent = $derived(session.receiving && session.receiving.total > 0 ? Math.floor((session.receiving.got * 100) / session.receiving.total) : 0);

  /** A field of an answer's body, as text. */
  function field(answer: Answer | undefined, name: string): string {
    const body = answer?.body as Record<string, unknown> | undefined;
    const value = body?.[name];
    return value === undefined || value === null ? "" : typeof value === "string" ? value : JSON.stringify(value);
  }

  /** An answer's outcome, after its value: its time, or what went wrong. */
  function outcome(answer: Answer): string {
    return answer.problem ?? `${time(answer.at)}${answer.ms !== null ? ` · ${ms(answer.ms)}` : ""}`;
  }

  async function chooseImage() {
    const chosen = await open({
      title: "The image to upload",
      multiple: false,
      directory: false,
      defaultPath: setup.file || undefined,
      filters: [
        { name: "Images", extensions: ["bin"] },
        { name: "All files", extensions: ["*"] },
      ],
    });
    if (typeof chosen === "string") {
      setup.file = chosen;
      save();
    }
  }

  /** Whether an image can be marked to run once at the next reset: it is not running, nor marked yet. */
  const testable = (image: Image) => !image.active && !image.pending && !image.permanent;
  /** Whether an image can be kept: it runs on test, or waits for its test. */
  const confirmable = (image: Image) => !image.confirmed;

  function time(at: number): string {
    const date = new Date(at);
    const two = (value: number) => String(value).padStart(2, "0");
    return `${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())}.${String(date.getMilliseconds()).padStart(3, "0")}`;
  }

  const ms = (value: number) => `${Number(value.toFixed(1))} ms`;

  const actions: TerminalActions = {
    hasSelection: () => false,
    copy: async () => {},
    paste: async () => {},
    selectAll: () => {},
    clear: () => (board ? session.clearHeard() : session.clearLog()),
    text: () =>
      (board ? session.heard : session.log)
        .map((each) => `${time(each.at)} ${each.what} ${each.op} ${each.problem ?? (each.rc === null ? "" : `rc ${each.rc}`)} ${each.text}`)
        .join("\n") + "\n",
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

{#snippet imageTable(images: Image[], buttons: boolean)}
  {#each images as image (`${image.image}/${image.slot}`)}
    <div class="line">
      <span class="mono slot" title="Image {image.image}, slot {image.slot}">{image.image}/{image.slot}</span>
      <span class="mono version">{image.version || "?"}</span>
      <span class="mono muted hash" title="Its SHA-256: {image.hash}">{shortHash(image.hash)}</span>
      <span class="flags">
        {#each flagsOf(image) as flag (flag)}
          <span class="badge" class:on={flag === "active" || flag === "confirmed"}>{flag}</span>
        {/each}
      </span>
      {#if buttons}
        <span class="spacer"></span>
        {#if testable(image)}
          <button class="btn small" disabled={!tab.connected} title="Run it once at the next reset; if it is not confirmed then, the board goes back" onclick={() => void session.mark("test", image.hash)}>
            Test
          </button>
        {/if}
        {#if confirmable(image)}
          <button class="btn small" disabled={!tab.connected} title="Keep it for good" onclick={() => void session.mark("confirm", image.active ? "" : image.hash)}>Confirm</button>
        {/if}
      {/if}
    </div>
  {:else}
    <p class="empty">{buttons ? "Read lists the board's images." : "No image."}</p>
  {/each}
{/snippet}

{#snippet logList(entries: LogEntry[], empty: string)}
  {#each entries as entry (entry.id)}
    <div class="entry">
      <div class="entry-line">
        <span class="mono muted">{time(entry.at)}</span>
        <span class="mono">{entry.what}</span>
        <span class="mono muted">{entry.op}</span>
        {#if entry.problem}
          <span class="bad">{entry.problem}</span>
        {:else if !entry.answered}
          <span class="muted">…</span>
        {:else if entry.rc !== null && entry.rc !== 0}
          <span class="mono bad">rc {entry.rc}</span>
        {:else}
          <span class="good">ok</span>
        {/if}
        {#if entry.ms !== null}
          <span class="muted">{ms(entry.ms)}</span>
        {/if}
      </div>
      {#if entry.text}
        <div class="mono value muted" title={entry.text}>{entry.text}</div>
      {/if}
    </div>
  {:else}
    <p class="empty">{empty}</p>
  {/each}
{/snippet}

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div class="mcumgrview" tabindex="0" role="region" aria-label="MCUmgr" bind:this={root}>
  {#if board}
    <div class="bar">
      <span class="state">A simulated Zephyr board · {session.heard.length} requests heard</span>
    </div>
    <div class="body">
      <div class="side">
        <section>
          <h3>Its images</h3>
          {@render imageTable(session.boardImages, false)}
          {#if session.receiving}
            <div class="progress"><div class="done" style:width="{receivingPercent}%"></div></div>
            <span class="muted">An image coming: {size(session.receiving.got)} of {size(session.receiving.total)}</span>
          {/if}
        </section>
      </div>
      <div class="main">
        <div class="head">
          <h3>What it was asked</h3>
          <span class="spacer"></span>
          <button class="btn small" onclick={() => session.clearHeard()}>Clear</button>
        </div>
        <div class="list">
          {@render logList(session.heard, "Each request a client makes is listed here, with what this board answered; an upload's first chunk and its last.")}
        </div>
      </div>
    </div>
  {:else}
    <div class="bar">
      <button class="btn small" disabled={!tab.connected} title="os info: what the board is" onclick={() => void session.ask("info")}>Info</button>
      <button class="btn small" disabled={!tab.connected} title="os params: its buffer's size and count" onclick={() => void session.ask("params")}>Params</button>
      <button class="btn small" disabled={!tab.connected} title="os datetime: its clock" onclick={() => void session.ask("datetime")}>Datetime</button>
      <button class="btn small" disabled={!tab.connected} title="os taskstat: its threads and their stacks" onclick={() => void session.ask("taskstat")}>Threads</button>
      <button class="btn small" disabled={!tab.connected} title="os reset: the board restarts; an image marked to test runs then" onclick={() => void session.ask("reset")}>Reset</button>
      <span class="spacer"></span>
      {#if session.problem}
        <span class="bad problem">{session.problem}</span>
      {/if}
    </div>
    <div class="body">
      <div class="side">
        <section>
          <h3>The board</h3>
          <div class="fields">
            <input class="field mono grow" spellcheck="false" placeholder="text" title="What Echo sends: the board says it back" bind:value={setup.echo} onchange={save} />
            <button class="btn small" disabled={!tab.connected} onclick={() => void session.echo()}>Echo</button>
          </div>
          {#each [["echo", "Echo", "r"], ["info", "Info", "output"], ["datetime", "Datetime", "datetime"]] as [command, label, name] (command)}
            {@const answer = session.answers[command]}
            {#if answer}
              <div class="said">
                <span class="muted label">{label}</span>
                <span class="mono value">{field(answer, name)}</span>
                <span class="muted" class:bad={answer.problem !== null}>{outcome(answer)}</span>
              </div>
            {/if}
          {/each}
          {#if session.answers.params}
            {@const answer = session.answers.params}
            <div class="said">
              <span class="muted label">Params</span>
              <span class="mono value">{field(answer, "buf_count")} buffers of {field(answer, "buf_size")} bytes</span>
              <span class="muted" class:bad={answer.problem !== null}>{outcome(answer)}</span>
            </div>
          {/if}
        </section>

        <section>
          <div class="head">
            <h3>Images</h3>
            <span class="spacer"></span>
            <button class="btn small" disabled={!tab.connected} title="image state: the images and their hashes" onclick={() => void session.ask("images")}>Read</button>
            <button class="btn small" disabled={!tab.connected} title="Erase the slot that is not running" onclick={() => void session.ask("erase")}>Erase</button>
          </div>
          {@render imageTable(session.images, true)}
          {#if session.answers.state?.problem}
            <p class="bad">{session.answers.state.problem}</p>
          {/if}
        </section>

        <section>
          <h3>Upload</h3>
          <div class="fields">
            <input
              class="field mono grow"
              spellcheck="false"
              placeholder="zephyr.signed.bin, in the tab's folder without a folder"
              title="The image to upload: a signed MCUboot image"
              bind:value={setup.file}
              onchange={save}
            />
            <button class="btn small" title="Choose the file" onclick={chooseImage}>...</button>
            <label class="option" title="The image's number, on a board with more than one">
              Image
              <input class="field mono number" type="number" min="0" max="255" bind:value={setup.image} onchange={save} />
            </label>
            <button class="btn small primary" disabled={!tab.connected || session.uploading} onclick={() => void session.startUpload()}>Upload</button>
          </div>
          {#if upload}
            <div class="progress" class:failed={upload.problem !== null}>
              <div class="done" style:width="{upload.problem ? 100 : percent}%"></div>
            </div>
            <span class="muted" class:bad={upload.problem !== null}>
              <span title={upload.name}>{baseName(upload.name)}</span>{upload.version ? `, version ${upload.version}` : ""}:
              {#if upload.problem}
                stopped at {size(upload.sent)} of {size(upload.total)}: {upload.problem}
              {:else if upload.done}
                all {size(upload.total)} uploaded, {Number(upload.kbps.toFixed(1))} KB/s. Test it, then Reset.
              {:else}
                {percent}% · {size(upload.sent)} of {size(upload.total)} · {Number(upload.kbps.toFixed(1))} KB/s
              {/if}
            </span>
          {/if}
        </section>

        {#if tasks.length > 0}
          <section>
            <h3>Threads</h3>
            <div class="tasks">
              <span class="muted">Thread</span>
              <span class="muted">Priority</span>
              <span class="muted">Stack used</span>
              <span class="muted">Switches</span>
              {#each tasks as task (task.name)}
                <span class="mono">{task.name}</span>
                <span class="mono">{task.priority}</span>
                <span class="stack" title="{task.stackUsed} of {task.stackSize} bytes">
                  <span class="progress"><span class="done" class:full={task.stackUsed * 10 >= task.stackSize * 9} style:width="{task.stackSize ? (task.stackUsed * 100) / task.stackSize : 0}%"></span></span>
                  <span class="mono">{task.stackUsed}/{task.stackSize}</span>
                </span>
                <span class="mono">{task.switches}</span>
              {/each}
            </div>
          </section>
        {/if}
      </div>
      <div class="main">
        <div class="head">
          <h3>Requests</h3>
          <span class="spacer"></span>
          <button class="btn small" onclick={() => session.clearLog()}>Clear</button>
        </div>
        <div class="list">
          {@render logList(session.log, "Each request is listed here with the board's answer.")}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .mcumgrview {
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
    color: var(--muted);
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
    grid-template-columns: minmax(360px, 3fr) minmax(0, 2fr);
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

  section {
    margin-bottom: 14px;
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
    gap: 8px;
    align-items: center;
    margin-bottom: 6px;
  }

  .head h3 {
    margin: 0;
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

  .grow {
    flex: 1 1 160px;
    min-width: 100px;
  }

  .number {
    width: 64px;
  }

  .said {
    display: flex;
    gap: 10px;
    align-items: baseline;
    min-width: 0;
    padding: 3px 0;
    border-top: 1px solid var(--border);
  }

  .said .label {
    flex: 0 0 64px;
  }

  .line {
    display: flex;
    gap: 10px;
    align-items: center;
    min-width: 0;
    padding: 4px 0;
    border-top: 1px solid var(--border);
  }

  .slot {
    flex: 0 0 30px;
    color: var(--muted);
  }

  .version {
    flex: 0 0 auto;
    font-weight: 600;
  }

  .hash {
    flex: 0 0 auto;
  }

  .flags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    min-width: 0;
  }

  .badge {
    padding: 0 6px;
    font-size: 11px;
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 9px;
  }

  .badge.on {
    color: var(--accent);
    border-color: currentColor;
  }

  .progress {
    display: block;
    height: 6px;
    margin: 2px 0 4px;
    overflow: hidden;
    background: var(--panel);
    border-radius: 3px;
  }

  .progress .done {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 0.2s;
  }

  .progress.failed .done,
  .progress .done.full {
    background: var(--bad);
  }

  .tasks {
    display: grid;
    grid-template-columns: minmax(80px, 1.2fr) auto minmax(140px, 2fr) auto;
    gap: 4px 12px;
    align-items: center;
  }

  .stack {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .stack .progress {
    flex: 1;
    margin: 0;
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

  @media (max-width: 820px) {
    .body {
      grid-template-columns: 1fr;
      overflow: auto;
    }
  }
</style>
