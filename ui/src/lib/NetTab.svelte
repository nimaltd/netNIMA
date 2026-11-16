<script lang="ts">
  import CoapView from "./CoapView.svelte";
  import HexBar from "./HexBar.svelte";
  import HttpView from "./HttpView.svelte";
  import LinesView from "./LinesView.svelte";
  import Lwm2mView from "./Lwm2mView.svelte";
  import McumgrView from "./McumgrView.svelte";
  import ModbusView from "./ModbusView.svelte";
  import MqttView from "./MqttView.svelte";
  import NetToolbar from "./NetToolbar.svelte";
  import PlotView from "./PlotView.svelte";
  import SendBar from "./SendBar.svelte";
  import Terminal from "./Terminal.svelte";
  import { settings } from "./settings.svelte";
  import type { Tab } from "./tabs.svelte";

  // A socket tab: its bar, its view, and the send box under it.
  let {
    tab,
    active,
    isAppKey,
    onsettings,
    onmacros,
    onhighlights,
  }: {
    tab: Tab;
    /** Whether the tab is the one in front, with the keyboard. */
    active: boolean;
    isAppKey: (event: KeyboardEvent) => boolean;
    onsettings: () => void;
    onmacros: () => void;
    onhighlights: () => void;
  } = $props();
</script>

<div class="nettab">
  <NetToolbar {tab} {onsettings} />
  {#if tab.problem && !tab.connected}
    <p class="problem" role="status">{tab.problem}</p>
  {/if}
  <div class="layer">
    <!-- The terminal stays while another view is shown, so nothing it showed is lost. -->
    <div class="view" class:hidden={tab.view !== "terminal"}>
      <Terminal {tab} active={active && tab.view === "terminal"} {isAppKey} />
    </div>
    {#if tab.view === "modbus" && active}
      <div class="view">
        <ModbusView {tab} {active} />
      </div>
    {/if}
    {#if tab.view === "mqtt" && active}
      <div class="view">
        <MqttView {tab} {active} />
      </div>
    {/if}
    {#if tab.view === "coap" && active}
      <div class="view">
        <CoapView {tab} {active} />
      </div>
    {/if}
    {#if tab.view === "http" && active}
      <div class="view">
        <HttpView {tab} {active} />
      </div>
    {/if}
    {#if tab.view === "lwm2m" && active}
      <div class="view">
        <Lwm2mView {tab} {active} />
      </div>
    {/if}
    {#if tab.view === "mcumgr" && active}
      <div class="view">
        <McumgrView {tab} {active} />
      </div>
    {/if}
    {#if tab.view === "lines" && active}
      <div class="view">
        <LinesView {tab} {active} {onhighlights} />
      </div>
    {/if}
    {#if tab.view === "plot" && active}
      <div class="view">
        <PlotView {tab} {active} />
      </div>
    {/if}
    {#if tab.view === "hex" && active}
      <div class="view hexview">
        <HexBar {tab} />
        <div class="hexterm">
          <Terminal {tab} hex {active} {isAppKey} />
        </div>
      </div>
    {/if}
  </div>
  {#if settings.send_box && tab.takesInput}
    <SendBar {tab} {onmacros} />
  {/if}
</div>

<style>
  .nettab {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .problem {
    margin: 0;
    padding: 6px 12px;
    font-size: 12px;
    color: var(--bad);
    background: var(--panel);
    border-bottom: 1px solid var(--border);
  }

  .layer {
    position: relative;
    flex: 1;
    min-height: 0;
  }

  .view {
    position: absolute;
    inset: 0;
    padding: 4px 0 0 8px;
    font-size: var(--view-size);
    box-sizing: border-box;
  }

  .view.hidden {
    display: none;
  }

  .hexview {
    display: flex;
    flex-direction: column;
  }

  .hexterm {
    flex: 1;
    min-height: 0;
  }
</style>
