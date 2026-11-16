<script lang="ts">
  import { onMount } from "svelte";
  import Modal from "./Modal.svelte";
  import { findProtocols, linesOf, protocolReady } from "./new-tab";

  // Every protocol in its group, with a button for each of its ends, as
  // File > New tab and the + button open it: a line of a client and a server
  // for each transport, such as CoAP's UDP, TCP and WebSocket. A few letters
  // find a protocol, and Enter opens the first end of the first one found.
  let { onpick, onclose }: { onpick: (kind: string) => void; onclose: () => void } = $props();

  let query = $state("");
  let field: HTMLInputElement;

  const found = $derived(findProtocols(query));

  onMount(() => field.focus());

  function submit() {
    const first = found[0]?.protocols[0]?.ends[0];
    if (first) onpick(first.kind);
  }
</script>

<Modal title="New tab" {onclose} onsubmit={submit}>
  <p class="dlg-hint">Every protocol has both ends in netNIMA, so one PC is enough to try it.</p>
  <input
    class="field find"
    placeholder="Find a protocol: mqtt, broker, tftp..."
    spellcheck="false"
    bind:this={field}
    bind:value={query}
  />
  <div class="groups">
    {#each found as group (group.name)}
      <h2 class="dlg-section">{group.name}</h2>
      {#each group.protocols as protocol (protocol.name)}
        {@const lines = linesOf(protocol)}
        <div class="row" class:tall={lines.length > 1}>
          <div class="what">
            <span class="name">{protocol.name}</span>
            <span class="detail" title={protocol.detail}>{protocol.detail}</span>
          </div>
          {#if !protocolReady(protocol)}
            <span class="phase" title="Until then, the tab says what it will do">Phase {protocol.phase}</span>
          {/if}
          <div class="ends">
            {#each lines as line (line.transport ?? "")}
              <div class="line">
                {#if line.transport}
                  <span class="over">{line.transport}</span>
                {/if}
                {#each line.ends as end (end.kind)}
                  <button class="btn" title={`New ${end.title} tab`} onclick={() => onpick(end.kind)}>{end.label}</button>
                {/each}
              </div>
            {/each}
          </div>
        </div>
      {/each}
    {:else}
      <p class="dlg-empty">No protocol has "{query}" in it.</p>
    {/each}
  </div>

  {#snippet buttons()}
    <button class="btn" onclick={onclose}>Close</button>
  {/snippet}
</Modal>

<style>
  .find {
    margin-top: 10px;
  }

  .groups {
    max-height: min(520px, calc(100vh - 230px));
    margin-top: 4px;
    overflow-y: auto;
  }

  /* The name keeps some room however wide the buttons get, so they never cover it. */
  .row {
    display: grid;
    grid-template-columns: minmax(8em, 1fr) auto auto;
    align-items: center;
    gap: 10px;
    padding: 5px 8px;
    border-radius: 6px;
  }

  .row:hover {
    background: var(--hover);
  }

  /* A line for each transport: the name at the top, and room for all its words. */
  .row.tall {
    align-items: start;
  }

  .tall .detail {
    white-space: normal;
  }

  .what {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .name {
    font-weight: 600;
  }

  .detail {
    overflow: hidden;
    font-size: 12px;
    color: var(--muted);
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .phase {
    padding: 0 6px;
    font-size: 11px;
    line-height: 18px;
    color: var(--muted);
    white-space: nowrap;
    border: 1px solid var(--border);
    border-radius: 4px;
  }

  /* The last column, with a phase or without, so every row's buttons line up. */
  .ends {
    display: flex;
    flex-direction: column;
    grid-column: 3;
    gap: 4px;
    min-width: 172px;
  }

  .line {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 6px;
  }

  .over {
    font-size: 12px;
    color: var(--muted);
  }

  .ends .btn {
    min-width: 80px;
    justify-content: center;
  }
</style>
