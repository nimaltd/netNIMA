<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import { endOf } from "./new-tab";
  import { CURRENT_PHASE, PLAN, phaseName } from "./roadmap";
  import type { Tab } from "./tabs.svelte";

  /** A tab whose kind a later phase of the roadmap brings. */
  let { tab }: { tab: Tab } = $props();

  const found = $derived(endOf(tab.kind));
  const phase = $derived(found?.protocol.phase ?? 0);
  const next = $derived(phase === CURRENT_PHASE + 1);
  /** The protocol's other end, which netNIMA has too, so one PC can try both. */
  const other = $derived(found?.protocol.ends.find((end) => end.kind !== tab.kind));
</script>

<div class="coming">
  <div class="card">
    <span class="phase">Phase {phase} · {phaseName(phase)}</span>
    <h1>{tab.name}</h1>
    {#if found}
      <p>{found.protocol.detail}.</p>
    {/if}
    {#if other}
      <p>Its other end is in netNIMA too, as the {other.title} tab, so one PC is enough to try both.</p>
    {/if}
    <p class="when">
      This tab comes in Phase {phase} of the roadmap{next ? ", the next one" : ""}. Until then it keeps its place, and
      opens again with netNIMA.
    </p>
    <button class="btn" onclick={() => openUrl(PLAN)}>Read the plan</button>
  </div>
</div>

<style>
  .coming {
    display: grid;
    place-items: center;
    height: 100%;
    padding: 24px;
    overflow-y: auto;
    font-size: var(--view-size);
    box-sizing: border-box;
  }

  .card {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    width: min(480px, 100%);
    padding: 22px 24px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
  }

  .phase {
    padding: 0 8px;
    font-size: 11px;
    font-weight: 600;
    line-height: 20px;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    background: var(--accent-soft);
    border-radius: 4px;
  }

  h1 {
    margin: 12px 0 4px;
    font-size: 20px;
    font-weight: 600;
  }

  p {
    margin: 0 0 10px;
    line-height: 1.5;
  }

  .when {
    color: var(--muted);
  }

  .btn {
    margin-top: 6px;
  }
</style>
