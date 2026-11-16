<script module lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { NO_HELP, type ProtocolHelp } from "./commands";

  /** Each kind of tab's commands, asked for once. */
  const helps = new Map<string, Promise<ProtocolHelp>>();

  function helpFor(kind: string): Promise<ProtocolHelp> {
    let help = helps.get(kind);
    if (!help) {
      help = invoke<ProtocolHelp>("protocol_help", { kind }).catch(() => NO_HELP);
      helps.set(kind, help);
    }
    return help;
  }
</script>

<script lang="ts">
  import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
  import { lineOf, partsOf, startingValues, type ValuePart } from "./command-form";
  import { matching, typing, withCommand, wordOf, type CommandHelp } from "./commands";
  import { settings, type Macro, type Sequence } from "./settings.svelte";
  import { keys, shortcutLabel } from "./shortcuts";
  import type { Tab } from "./tabs.svelte";
  import { activeTerminal } from "./terminal-actions";

  let { tab, onmacros }: { tab: Tab; onmacros: () => void } = $props();

  const ENTER_NAMES = { cr: "CR", lf: "LF", crlf: "CR LF" };
  /** The widest a command's usage goes in the list before what it does. */
  const USAGE_WIDTH = 40;

  let input: HTMLInputElement;
  let error = $state("");
  /** Where ↑ and ↓ are in the history; null while typing a new line. */
  let position: number | null = null;
  /** The line being typed, and its mode, kept while ↑ shows older ones. */
  let typed = { text: "", hex: false };

  /** What the tab's protocol takes, from its help; nothing for a plain socket tab. */
  let help: ProtocolHelp = $state(NO_HELP);
  /** Whether the line has the focus: the commands show only then. */
  let focused = $state(false);
  /** The list above the line: the commands that fit what is typed, all of them, or none. */
  let listing: "typed" | "all" | null = $state(null);
  /** The command chosen in the list with ↑ and ↓; -1 for none yet. */
  let chosen = $state(-1);
  let list: HTMLElement | undefined = $state();

  $effect(() => {
    const kind = tab.kind;
    help = NO_HELP;
    if (!tab.engine) return;
    let current = true;
    void helpFor(kind).then((loaded) => {
      if (current) help = loaded;
    });
    return () => {
      current = false;
    };
  });

  /** A line of text, hex bytes, or, in a protocol tab, the form for its commands. */
  const mode: "text" | "hex" | "form" = $derived(
    tab.draft.hex ? "hex" : tab.engine && tab.sendForm ? "form" : "text",
  );

  /** The command the form is for, by its usage: the first until another is chosen. */
  let formUsage = $state("");
  /** What each command's fields hold, so they come back with it. */
  let formValues: Record<string, string[]> = $state({});
  /** Whether each command's data is written in hex. */
  let formHex: Record<string, boolean> = $state({});

  const formCommand: CommandHelp | undefined = $derived(
    help.commands.find((command) => command.usage === formUsage) ?? help.commands[0],
  );
  const parts = $derived(formCommand ? partsOf(formCommand.usage) : []);
  const values = $derived(formCommand ? (formValues[formCommand.usage] ?? startingValues(parts)) : []);
  const dataHex = $derived(formCommand ? (formHex[formCommand.usage] ?? false) : false);
  /** The line the form sends, or why it cannot yet. */
  const made = $derived(lineOf(parts, values, dataHex));

  /** The commands typed with a word of their own, which can be picked. */
  const commands = $derived(help.commands.filter((command) => wordOf(command) !== null));
  /** Lines such as <text>: what is sent when no command is typed. */
  const others = $derived(help.commands.filter((command) => wordOf(command) === null));

  const listed: CommandHelp[] = $derived.by(() => {
    if (!focused || tab.draft.hex || listing === null) return [];
    return listing === "all" ? commands : matching(commands, tab.draft.text);
  });

  /** How the command typed goes on, while what comes after its word is typed. */
  const hints = $derived(focused && !tab.draft.hex && listing !== "all" ? typing(commands, tab.draft.text) : []);

  /** Each usage takes as much room as the longest, so what they do lines up. */
  const usageWidth = $derived(
    Math.min(USAGE_WIDTH, Math.max(0, ...[...listed, ...hints, ...others].map((command) => command.usage.length))),
  );

  function showAll() {
    listing = "all";
    chosen = -1;
    input.focus();
  }

  /** Puts a command in the line, with the cursor after it for what it takes. */
  function pick(command: CommandHelp) {
    tab.draft.text = withCommand(tab.draft.text, command, commands);
    listing = null;
    chosen = -1;
    position = null;
    error = "";
    requestAnimationFrame(() => {
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    });
  }

  /** Moves the choice in the list down (1) or up (-1), round to the other end. */
  function choose(step: number) {
    const count = listed.length;
    chosen = chosen < 0 ? (step > 0 ? 0 : count - 1) : (chosen + step + count) % count;
    requestAnimationFrame(() => list?.querySelector(".chosen")?.scrollIntoView({ block: "nearest" }));
  }

  /** A right-click lists the commands; a plain socket tab keeps the web view's own menu. */
  function oncontextmenu(event: MouseEvent) {
    if (commands.length === 0) return;
    event.preventDefault();
    showAll();
  }

  /** Cut and Copy, as the web view's own menu has them, for the line. */
  async function copy(cut: boolean) {
    const start = input.selectionStart ?? 0;
    const end = input.selectionEnd ?? 0;
    listing = null;
    if (start === end) return;
    await writeText(input.value.slice(start, end));
    if (cut) {
      input.setRangeText("", start, end, "end");
      tab.draft.text = input.value;
    }
  }

  /** Paste, as the web view's own menu has it: line ends dropped, as a pasted line loses them. */
  async function paste() {
    const text = (await readText().catch(() => "")) ?? "";
    const start = input.selectionStart ?? input.value.length;
    const end = input.selectionEnd ?? start;
    listing = null;
    input.setRangeText(text.replace(/[\r\n]+/g, ""), start, end, "end");
    tab.draft.text = input.value;
    position = null;
  }

  async function send() {
    if (mode === "form") return sendForm();
    const { text, hex, enter } = tab.draft;
    if (!text && !enter) {
      return;
    }
    tab.setScrollLock(false);
    try {
      await tab.sendLine(text, hex, enter);
      if (text) {
        tab.remember(text, hex);
      }
      tab.draft.text = "";
      position = null;
      error = "";
    } catch (problem) {
      error = String(problem);
    }
  }

  async function sendMacro(macro: Macro) {
    tab.setScrollLock(false);
    try {
      await tab.sendLine(macro.text, macro.hex, macro.enter);
      error = "";
    } catch (problem) {
      error = `${macro.name}: ${problem}`;
    }
  }

  /** Shows an older line (-1) or a newer one (1) from the history. */
  function browse(step: number) {
    const history = tab.history;
    if (history.length === 0) {
      return;
    }
    if (position === null) {
      typed = { text: tab.draft.text, hex: tab.draft.hex };
      position = history.length;
    }
    const next = Math.min(history.length, Math.max(0, position + step));
    if (next === position) {
      return;
    }
    position = next;
    if (position === history.length) {
      tab.draft.text = typed.text;
      tab.draft.hex = typed.hex;
    } else {
      tab.draft.text = history[position].text;
      tab.draft.hex = history[position].hex ?? false;
    }
    error = "";
    // The cursor goes to the end, as in a shell.
    requestAnimationFrame(() => input.setSelectionRange(input.value.length, input.value.length));
  }

  function onkeydown(event: KeyboardEvent) {
    // While the commands are listed, ↑ ↓ choose one, and Tab, or Enter on
    // one chosen, puts it in the line; Enter alone still sends what is typed.
    if (listed.length > 0) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        choose(event.key === "ArrowDown" ? 1 : -1);
        return;
      }
      if ((event.key === "Tab" && !event.shiftKey) || (event.key === "Enter" && chosen >= 0)) {
        event.preventDefault();
        event.stopPropagation();
        pick(listed[Math.max(chosen, 0)]);
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        listing = null;
        chosen = -1;
        return;
      }
    }
    if (event.key === " " && event.ctrlKey && commands.length > 0) {
      event.preventDefault();
      showAll();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      event.stopPropagation();
      void send();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      browse(-1);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      browse(1);
    } else if (event.key === "Escape") {
      event.preventDefault();
      activeTerminal()?.focus();
    }
  }

  function setHex(hex: boolean) {
    tab.draft.hex = hex;
    // Hex is usually a whole packet; text is usually a command line.
    tab.draft.enter = !hex;
    error = "";
    input.focus();
  }

  function setMode(next: string) {
    error = "";
    if (next === "form") {
      tab.draft.hex = false;
      tab.setSendForm(true);
      return;
    }
    if (tab.engine) tab.setSendForm(false);
    setHex(next === "hex");
  }

  /** Sends the line the form makes, with the line end a command needs, and keeps it in the history. */
  async function sendForm() {
    if (!formCommand) return;
    if (made.problem) {
      error = made.problem;
      return;
    }
    tab.setScrollLock(false);
    try {
      await tab.sendLine(made.line, false, true);
      tab.remember(made.line, false);
      error = "";
    } catch (problem) {
      error = String(problem);
    }
  }

  function setValue(index: number, value: string) {
    if (!formCommand) return;
    const next = [...values];
    next[index] = value;
    formValues[formCommand.usage] = next;
    error = "";
  }

  /** A command in the form's menu: its word, or all of its usage when it has none or shares its word. */
  function commandLabel(command: CommandHelp): string {
    const word = wordOf(command);
    const shared = help.commands.filter((other) => wordOf(other) === word).length > 1;
    return word === null || shared ? command.usage : word;
  }

  function placeholderOf(part: ValuePart): string {
    const name = part.data && dataHex ? `${part.name} in hex, such as 01 02 ff` : part.name;
    const flagged = part.flag ? `${part.flag} ${name}` : name;
    return part.many ? `${flagged}...` : flagged;
  }

  /** Enter in a field sends, as in the line; Escape goes back to the terminal. */
  function onFormKey(event: KeyboardEvent) {
    if (event.key === "Enter") {
      event.preventDefault();
      event.stopPropagation();
      void sendForm();
    } else if (event.key === "Escape") {
      event.preventDefault();
      activeTerminal()?.focus();
    }
  }

  /** "Alt+1" on Windows and Linux, "⌘1" on macOS, for the first nine macros. */
  function macroKey(index: number): string | null {
    return index < 9 ? shortcutLabel(keys(`Alt+${index + 1}`, `Cmd+${index + 1}`)) : null;
  }

  function sequenceTitle(sequence: Sequence): string {
    const times = sequence.repeat === 0 ? "until stopped" : sequence.repeat === 1 ? "once" : `${sequence.repeat} times`;
    return `Sends ${sequence.steps.join(", ")}, ${sequence.delay_ms} ms apart, ${times}. Click again to stop.`;
  }

  /** Where a running sequence is: "3 of 10", or "3" when it goes on until stopped. */
  function progress(running: { round: number; rounds: number }): string {
    return running.rounds === 0 ? String(running.round) : `${running.round} of ${running.rounds}`;
  }

  function macroTitle(macro: Macro, index: number): string {
    const enter = macro.enter ? ` and ${ENTER_NAMES[tab.terminal.enter]}` : "";
    const key = macroKey(index);
    return `Sends ${macro.hex ? "hex " : ""}${macro.text}${enter}${key ? ` (${key})` : ""}`;
  }
</script>

<div class="sendbar">
  <div class="row">
    <select
      class="field mode"
      title={tab.engine
        ? "A form for the protocol's commands, or a line to type them in"
        : "Text, with escapes such as \\r, or hex bytes"}
      value={mode}
      onchange={(event) => setMode(event.currentTarget.value)}
    >
      {#if tab.engine}
        <option value="form">Form</option>
        <option value="text">Text</option>
      {:else}
        <option value="text">Text</option>
        <option value="hex">Hex</option>
      {/if}
    </select>
    {#if tab.manyPeers}
      <select class="field mode target" title="Who it goes to" bind:value={tab.sendTo}>
        <option value="default">{tab.socket === "udp" && tab.udp.remote_host.trim() ? "Remote" : "Last heard"}</option>
        <option value="all">All</option>
        {#each tab.peers as peer (peer.id)}
          <option value={`peer:${peer.id}`}>{peer.address}</option>
        {/each}
      </select>
    {/if}
    {#if mode === "form"}
      <!-- The command, then a field for each thing it takes, in the order it is typed. -->
      <div class="form">
        {#if formCommand}
          <select
            class="field mode command"
            title="The command to send"
            value={formCommand.usage}
            onchange={(event) => {
              formUsage = event.currentTarget.value;
              error = "";
            }}
          >
            {#each help.commands as command, index (index)}
              <option value={command.usage}>{commandLabel(command)}</option>
            {/each}
          </select>
        {/if}
        {#each parts as part, index (index)}
          {#if part.kind === "word"}
            {#if index > 0}
              <span class="word mono">{part.text}</span>
            {/if}
          {:else if part.kind === "switch"}
            <label class="check" title={`Send ${part.flag} with it`}>
              <input
                type="checkbox"
                checked={values[index] === "on"}
                onchange={(event) => setValue(index, event.currentTarget.checked ? "on" : "")}
              />
              {part.flag}
            </label>
          {:else if part.kind === "choice"}
            <select
              class="field mode"
              title={`One of ${part.options.join(" ")}${part.optional ? ", or none" : ""}`}
              value={values[index]}
              onchange={(event) => setValue(index, event.currentTarget.value)}
            >
              {#if part.optional}
                <option value="">—</option>
              {/if}
              {#each part.options as option (option)}
                <option value={option}>{option}</option>
              {/each}
            </select>
          {:else}
            {#if part.data}
              <select
                class="field mode"
                title="The data as text, with \r \n \xHH for bytes, or as hex bytes"
                value={dataHex ? "hex" : "text"}
                onchange={(event) => {
                  if (formCommand) formHex[formCommand.usage] = event.currentTarget.value === "hex";
                  error = "";
                }}
              >
                <option value="text">Text</option>
                <option value="hex">Hex</option>
              </select>
            {/if}
            <input
              class="field mono arg"
              class:data={part.data}
              class:bad={error !== ""}
              spellcheck="false"
              placeholder={placeholderOf(part)}
              title={`${part.name}: ${part.optional ? "may stay empty" : "needed"}`}
              value={values[index]}
              oninput={(event) => setValue(index, event.currentTarget.value)}
              onkeydown={onFormKey}
            />
          {/if}
        {/each}
      </div>
    {/if}
    <div class="entry" hidden={mode === "form"}>
      {#if listed.length > 0}
        <!-- Clicks in the list keep the focus in the line. -->
        <div
          class="offer"
          role="menu"
          tabindex="-1"
          style:--usage-width={`${usageWidth}ch`}
          onmousedown={(event) => event.preventDefault()}
        >
          <!-- Only the commands scroll: what is under them stays in view. -->
          <div class="items" bind:this={list}>
            {#each listed as command, index (index)}
              <button
                type="button"
                class="item"
                class:chosen={index === chosen}
                role="menuitem"
                tabindex="-1"
                title={`${command.usage}: ${command.what}`}
                onclick={() => pick(command)}
              >
                <span class="usage mono">{command.usage}</span>
                <span class="what">{command.what}</span>
              </button>
            {/each}
            {#if listing === "all"}
              {#each others as command, index (index)}
                <div class="item other">
                  <span class="usage mono">{command.usage}</span>
                  <span class="what">{command.what}</span>
                </div>
              {/each}
              {#each help.notes as note, index (index)}
                <p class="note">{note}</p>
              {/each}
            {/if}
          </div>
          {#if listing === "all"}
            <div class="edit">
              <button type="button" class="btn small" tabindex="-1" onclick={() => void copy(true)}>Cut</button>
              <button type="button" class="btn small" tabindex="-1" onclick={() => void copy(false)}>Copy</button>
              <button type="button" class="btn small" tabindex="-1" onclick={() => void paste()}>Paste</button>
            </div>
          {:else}
            <p class="keys">Tab or a click puts it in the line · ↑ ↓ choose · Esc closes · Ctrl+Space lists them all</p>
          {/if}
        </div>
      {:else if hints.length > 0}
        <div class="offer hint" style:--usage-width={`${usageWidth}ch`}>
          {#each hints as command, index (index)}
            <div class="item">
              <span class="usage mono">{command.usage}</span>
              <span class="what">{command.what}</span>
            </div>
          {/each}
        </div>
      {/if}
      <input
        class="field mono line"
        class:bad={error !== ""}
        spellcheck="false"
        placeholder={tab.draft.hex
          ? "Hex bytes, such as AA 55 01"
          : commands.length > 0
            ? "A command: type its first letters, or right-click for all of them"
            : "A command; \\r \\n \\t \\e \\xHH for bytes, \\\\ for a backslash"}
        bind:this={input}
        bind:value={tab.draft.text}
        oninput={() => {
          error = "";
          position = null;
          listing = "typed";
          chosen = -1;
        }}
        onfocus={() => (focused = true)}
        onblur={() => {
          focused = false;
          listing = null;
          chosen = -1;
        }}
        {onkeydown}
        {oncontextmenu}
      />
    </div>
    {#if mode !== "form"}
      <label class="check" title={`Send ${ENTER_NAMES[tab.terminal.enter]} after it`}>
        <input type="checkbox" bind:checked={tab.draft.enter} /> Enter
      </label>
    {/if}
    <button class="btn small" disabled={!tab.connected} onclick={() => void send()}>Send</button>
    <button class="btn small" title="Add or change macros" onclick={onmacros}>Macros...</button>
  </div>

  {#if mode === "form" && formCommand}
    <p class="formnote">
      <span class="what" title={formCommand.what}>{formCommand.what}</span>
      {#if made.line}
        <span class="made mono" title="The line the form sends: Text sends the same">→ {made.line}</span>
      {/if}
    </p>
  {/if}

  {#if error}
    <p class="error">{error}</p>
  {/if}

  {#if settings.macros.length > 0}
    <div class="row macros">
      {#each settings.macros as macro, index (index)}
        <button
          class="btn small macro"
          disabled={!tab.connected}
          title={macroTitle(macro, index)}
          onclick={() => void sendMacro(macro)}
        >
          {#if index < 9}
            <span class="key">{index + 1}</span>
          {/if}
          {macro.name}
        </button>
      {/each}
      {#each settings.sequences as sequence, index (index)}
        {@const running = tab.sequence?.name === sequence.name ? tab.sequence : null}
        <button
          class="btn small macro sequence"
          class:running={running !== null}
          disabled={!tab.connected || (tab.sequence !== null && running === null)}
          title={running ? "Stop it" : sequenceTitle(sequence)}
          onclick={() => (running ? tab.stopSequence() : void tab.runSequence(sequence))}
        >
          <span class="key">{running ? "■" : "▶"}</span>
          {sequence.name}
          {#if running}
            <span class="key">{progress(running)}</span>
          {/if}
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .sendbar {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 6px 10px;
    background: var(--bg);
    border-top: 1px solid var(--border);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .mode {
    height: 26px;
    padding: 0 4px;
  }

  .target {
    max-width: 200px;
  }

  .entry {
    position: relative;
    display: flex;
    flex: 1;
    min-width: 60px;
  }

  .entry[hidden] {
    display: none;
  }

  /* A protocol's command as fields, which wrap onto more lines when they need to. */
  .form {
    display: flex;
    flex: 1;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .command {
    max-width: 240px;
  }

  .arg {
    flex: 1 1 110px;
    min-width: 70px;
    height: 26px;
    font-size: 13px;
  }

  .arg.data {
    flex: 3 1 200px;
  }

  .arg.bad {
    border-color: var(--bad);
  }

  .word {
    color: var(--muted);
  }

  /* Under the form: what the command does, and the line it sends. */
  .formnote {
    display: flex;
    gap: 14px;
    min-width: 0;
    margin: 0;
    font-size: 12px;
    color: var(--muted);
  }

  .formnote .what {
    flex: 1;
    white-space: nowrap;
  }

  .made {
    max-width: 50%;
    overflow: hidden;
    color: var(--text);
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .line {
    flex: 1;
    min-width: 0;
    height: 26px;
    font-size: 13px;
  }

  /* Above the line: the commands that fit what is typed, or how the one typed goes on. */
  .offer {
    position: absolute;
    right: 0;
    bottom: calc(100% + 6px);
    left: 0;
    z-index: 11;
    display: flex;
    flex-direction: column;
    max-height: min(340px, 60vh);
    padding: 4px;
    overflow: hidden;
    font-size: 12px;
    background: var(--menu-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: var(--shadow);
  }

  .offer:focus {
    outline: none;
  }

  .items {
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow-y: auto;
  }

  /* Only something to read: clicks go to what is under it. */
  .hint {
    pointer-events: none;
  }

  .item {
    display: flex;
    flex: none;
    align-items: baseline;
    gap: 14px;
    min-width: 0;
    padding: 4px 8px;
    font: inherit;
    color: var(--text);
    text-align: left;
    background: none;
    border: 0;
    border-radius: 5px;
    cursor: default;
  }

  button.item:hover {
    background: var(--hover);
  }

  .item.chosen {
    background: var(--accent-soft);
  }

  .usage {
    flex: none;
    width: var(--usage-width);
    max-width: 60%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: pre;
  }

  .what {
    min-width: 0;
    overflow: hidden;
    color: var(--muted);
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .other .usage {
    color: var(--muted);
  }

  .note,
  .keys {
    margin: 4px 8px 2px;
    color: var(--muted);
  }

  .keys {
    font-size: 11px;
  }

  .edit {
    display: flex;
    gap: 6px;
    padding: 6px 8px 2px;
    margin-top: 4px;
    border-top: 1px solid var(--border);
  }

  .line.bad {
    border-color: var(--bad);
  }

  .check {
    display: flex;
    align-items: center;
    gap: 5px;
    color: var(--muted);
    white-space: nowrap;
  }

  .check:has(input:checked) {
    color: var(--text);
  }

  .small {
    height: 26px;
    padding: 0 10px;
    font-size: 12px;
    white-space: nowrap;
  }

  .error {
    margin: 0;
    font-size: 12px;
    color: var(--bad);
  }

  .macros {
    flex-wrap: wrap;
    gap: 6px;
  }

  .macro {
    gap: 6px;
  }

  .sequence.running {
    border-color: var(--accent);
    background: var(--accent-soft);
  }

  .key {
    font-size: 10px;
    color: var(--muted);
  }
</style>
