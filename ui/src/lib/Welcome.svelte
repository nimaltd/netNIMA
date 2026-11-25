<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import Donate from "./Donate.svelte";
  import { helperIsGood, helperText, type HelperInfo } from "./helper";
  import { logo } from "./logo";
  import { NEW_TAB_SHORTCUT } from "./menus";
  import { ENDS } from "./new-tab";
  import { CURRENT_PHASE, GITHUB, LAST_PHASE, PLAN, phaseName } from "./roadmap";
  import { shortcutLabel } from "./shortcuts";

  // The page with no tab open, as terNIMA's, bleNIMA's and libNIMA's: the
  // logo, what netNIMA is, where to read more, and how to start.
  let {
    version,
    helper,
    onnew,
  }: {
    version: string;
    /** What the app found of netnima-helper; null while it looks. */
    helper: HelperInfo | null;
    /** Opens the New tab dialog. */
    onnew: () => void;
  } = $props();

  const drawn = logo();
  /** The protocols that can be spoken; the sniffer, which only listens, is counted apart. */
  const protocols = new Set(ENDS.filter(({ end }) => end.kind !== "capture").map(({ protocol }) => protocol.name)).size;
</script>

<div class="welcome">
  <div class="donate">
    <Donate app="netNIMA" />
  </div>

  <svg
    class="logo"
    width={drawn.width}
    height={drawn.height}
    viewBox="0 0 {drawn.width} {drawn.height}"
    role="img"
    aria-label="netNIMA"
  >
    <path class="net-shadow" d={drawn.netShadow} />
    <path class="net-face" d={drawn.netFace} />
    <path class="nima-shadow" d={drawn.nimaShadow} />
    <path class="nima-face" d={drawn.nimaFace} />
  </svg>

  <div class="lines">
    <p><span class="version">v{version}</span>&nbsp; a network tester for embedded developers</p>
    <p><button class="link" onclick={() => void openUrl(GITHUB)}>{GITHUB}</button></p>
    <p><span class="dim">Plan:</span> <button class="link" onclick={() => void openUrl(PLAN)}>{PLAN}</button></p>
  </div>

  <div class="table">
    <span class="label">Phase</span>
    <span>{CURRENT_PHASE} of {LAST_PHASE}, {phaseName(CURRENT_PHASE).toLowerCase()}: the window, its menus, tabs and settings</span>
    <span class="label">Next</span>
    <span>Phase {CURRENT_PHASE + 1}, {phaseName(CURRENT_PHASE + 1)}</span>
    <span class="label">New tab</span>
    <span>{protocols} protocols, as clients and as servers, and a sniffer</span>
    <span class="label">Helper</span>
    <span class:dim={!helper} class:problem={helper !== null && !helperIsGood(helper)} title={helper?.path ?? ""}
      >{helperText(helper)}</span
    >
  </div>

  <div class="lines">
    <p class="dim">Open a tab with this button, or File &gt; New tab. Until its phase is built, a tab says what it will do.</p>
    <p class="dim">Every protocol has both ends here, so one PC is enough to try it: no device needed.</p>
  </div>

  <button class="btn primary open" onclick={onnew}>
    New tab
    <span class="key">{shortcutLabel(NEW_TAB_SHORTCUT)}</span>
  </button>
</div>

<style>
  /* The same colors as the logo in terNIMA's welcome text and bleNIMA's and libNIMA's welcome pages. */
  .welcome {
    --logo-teal: #2dd4bf;
    --logo-teal-shadow: #135950;
    --logo-orange: #fb923c;
    --logo-orange-shadow: #693d19;

    height: 100%;
    padding: 18px 2ch;
    overflow: auto;
    font-family: var(--font-mono);
    font-size: 14px;
    font-variant-ligatures: none;
    line-height: 18px;
    box-sizing: border-box;
  }

  :global(:root[data-theme="light"]) .welcome {
    --logo-teal: #0d9488;
    --logo-teal-shadow: #99f6e4;
    --logo-orange: #ea580c;
    --logo-orange-shadow: #fed7aa;
  }

  .logo {
    display: block;
    shape-rendering: crispEdges;
  }

  /* At the right, beside the rest, which flows around it. */
  .donate {
    float: right;
    margin: 0 0 12px 3ch;
  }

  .net-face {
    fill: var(--logo-teal);
  }

  .net-shadow {
    fill: var(--logo-teal-shadow);
  }

  .nima-face {
    fill: var(--logo-orange);
  }

  .nima-shadow {
    fill: none;
    stroke: var(--logo-orange-shadow);
    stroke-width: 1;
  }

  .lines {
    margin-top: 18px;
  }

  p {
    margin: 0;
  }

  .version {
    color: var(--accent);
  }

  .dim,
  .link {
    color: var(--muted);
  }

  .problem {
    color: var(--bad);
  }

  .link {
    padding: 0;
    font: inherit;
    background: none;
    border: 0;
    cursor: pointer;
  }

  .link:hover {
    color: var(--accent);
    text-decoration: underline;
  }

  .table {
    display: grid;
    grid-template-columns: 14ch minmax(0, 1fr);
    margin-top: 18px;
    white-space: pre-wrap;
  }

  .label {
    color: var(--muted);
    white-space: nowrap;
  }

  .open {
    margin-top: 18px;
    font-family: var(--font-ui);
    font-size: 13px;
  }

  .key {
    margin-left: 8px;
    opacity: 0.7;
  }
</style>
