<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { open } from "@tauri-apps/plugin-dialog";
  import { openPath, revealItemInDir } from "@tauri-apps/plugin-opener";
  import About from "./lib/About.svelte";
  import Coming from "./lib/Coming.svelte";
  import CommandPalette from "./lib/CommandPalette.svelte";
  import HighlightsDialog from "./lib/HighlightsDialog.svelte";
  import CertificatesDialog from "./lib/CertificatesDialog.svelte";
  import InterfacesDialog from "./lib/InterfacesDialog.svelte";
  import MacrosDialog from "./lib/MacrosDialog.svelte";
  import MenuBar from "./lib/MenuBar.svelte";
  import NetTab from "./lib/NetTab.svelte";
  import NewTabDialog from "./lib/NewTabDialog.svelte";
  import SettingsDialog from "./lib/SettingsDialog.svelte";
  import SetupDialog from "./lib/SetupDialog.svelte";
  import StatusBar from "./lib/StatusBar.svelte";
  import TabBar from "./lib/TabBar.svelte";
  import UpdateDialog from "./lib/UpdateDialog.svelte";
  import Welcome from "./lib/Welcome.svelte";
  import type { HelperInfo } from "./lib/helper";
  import { buildMenus, isEnabled, itemForKey, macroForKey, menuCommands, menuForAltKey } from "./lib/menus";
  import { ENDS } from "./lib/new-tab";
  import type { Command } from "./lib/palette";
  import { defaultLogFolder, loadSettings, settings, unzoomed, updateSettings } from "./lib/settings.svelte";
  import {
    DATAGRAM_DEFAULT,
    activeTab,
    loadWorkspace,
    newTab,
    openRecording,
    showTab,
    tabs,
    view,
    type Tab,
  } from "./lib/tabs.svelte";
  import { activeTerminal } from "./lib/terminal-actions";
  import { appScheme } from "./lib/theme.svelte";
  import { checkForUpdate, type UpdateCheck } from "./lib/update";

  type AppInfo = { version: string; os: string; arch: string };

  let info = $state<AppInfo>();
  /** What the app found of netnima-helper, beside it; null while it looks. */
  let helper: HelperInfo | null = $state(null);
  let ready = $state(false);
  let aboutOpen = $state(false);
  let settingsOpen = $state(false);
  let newTabOpen = $state(false);
  let macrosOpen = $state(false);
  let highlightsOpen = $state(false);
  let certificatesOpen = $state(false);
  let interfacesOpen = $state(false);
  /** The tab whose settings are open, and whether it starts when they are saved. */
  let setup: { tab: Tab; starting: boolean } | null = $state(null);
  /** The command palette's commands while it is open. */
  let palette: Command[] | null = $state(null);
  /** What looking for a newer version found, while it is shown. */
  let updateCheck: UpdateCheck | null = $state(null);
  /** Whether one of the app's own dialogs is open, which has the keyboard. */
  const dialogOpen = $derived(
    aboutOpen ||
      settingsOpen ||
      newTabOpen ||
      macrosOpen ||
      highlightsOpen ||
      certificatesOpen ||
      interfacesOpen ||
      setup !== null ||
      palette !== null ||
      updateCheck !== null,
  );
  let menuBar: MenuBar;

  const menus = buildMenus({
    about: () => (aboutOpen = true),
    exit: () => void getCurrentWindow().close(),
    newTab: () => (newTabOpen = true),
    settings: () => (settingsOpen = true),
    tabSettings: () => {
      const tab = activeTab();
      if (tab?.built && tab.socket !== "replay") setup = { tab, starting: false };
    },
    commandPalette: openPalette,
    checkUpdates: () => void lookForUpdate(true),
    playRecording: () => void playRecording(),
    openLogFolder: () => void openLogFolder(),
    sendFile: () => void sendFile(),
    macros: () => (macrosOpen = true),
    highlights: () => (highlightsOpen = true),
    certificates: () => (certificatesOpen = true),
    interfaces: () => (interfacesOpen = true),
  });

  /** Opens a new tab; one that can connect asks for its settings first, and starts on Save. */
  function openTab(kind: string) {
    const tab = newTab(kind);
    if (tab.built) setup = { tab, starting: true };
  }

  /**
   * Looks on GitHub for a newer netNIMA. Asked from the Help menu, it says
   * what it found; when netNIMA starts, it speaks only of a newer version
   * that was not skipped, and says nothing when GitHub cannot be reached.
   */
  async function lookForUpdate(asked: boolean) {
    if (!info) return;
    const check = await checkForUpdate(info.version);
    if (asked || (check.kind === "newer" && check.release.version !== settings.updates.skipped)) {
      updateCheck = check;
    }
  }

  /** Picks a recording, from the log folder where they are made, and plays it in a new tab. */
  async function playRecording() {
    const folder = settings.log.folder || (await defaultLogFolder().catch(() => undefined));
    const path = await open({
      title: "Play back a recording",
      defaultPath: folder,
      multiple: false,
      filters: [{ name: "Recordings", extensions: ["nrec", "trec"] }],
    });
    if (typeof path === "string") openRecording(path);
  }

  /** Shows the tab's log file in its folder, or the log folder when there is no log. */
  async function openLogFolder() {
    const path = activeTab()?.logPath;
    if (path) {
      await revealItemInDir(path).catch((error) => console.error(error));
      return;
    }
    const folder = settings.log.folder || (await defaultLogFolder());
    await openPath(folder).catch((error) => console.error(error));
  }

  async function sendFile() {
    const tab = activeTab();
    if (!tab?.connected) return;
    const path = await open({ title: "Send a file", multiple: false, directory: false });
    if (typeof path === "string") void tab.sendFile(path, 0, DATAGRAM_DEFAULT);
  }

  /** Opens the command palette with what can be done now: the menus, every kind of new tab, and the tabs. */
  function openPalette() {
    const commands = menuCommands(menus);
    for (const { end } of ENDS) {
      commands.push({ label: `New tab: ${end.title}`, group: "New tab", run: () => openTab(end.kind) });
    }
    settings.macros.forEach((macro, index) =>
      commands.push({
        label: `Send ${macro.name}`,
        group: "Macro",
        shortcut: index < 9 ? `Alt+${index + 1}` : undefined,
        run: () => void activeTab()?.sendMacro(macro),
      }),
    );
    tabs.forEach((tab, index) =>
      commands.push({
        label: `Go to ${tab.name}`,
        group: "Tab",
        checked: index === view.active,
        run: () => showTab(index),
      }),
    );
    palette = commands;
  }

  onMount(() => {
    const appInfo = invoke<AppInfo>("app_info").then((result) => (info = result));
    invoke<HelperInfo>("helper_info")
      .then((result) => (helper = result))
      .catch((error) => (helper = { path: "", version: "", problem: String(error) }));
    // The workspace waits for the settings, which say how much of it comes back.
    loadSettings()
      .catch((error) => console.error(error))
      .then(() => loadWorkspace())
      .catch((error) => console.error(error))
      .finally(() => (ready = true))
      // Once the tabs are back, if the settings let it.
      .then(() => appInfo)
      .then(() => (settings.updates.check ? lookForUpdate(false) : undefined))
      .catch((error) => console.error(error));
  });

  // The page and the window frame follow the theme.
  $effect(() => {
    document.documentElement.dataset.theme = appScheme();
  });
  $effect(() => {
    const theme = settings.theme;
    void getCurrentWindow().setTheme(theme === "system" ? null : theme);
  });

  function onkeydown(event: KeyboardEvent) {
    if (dialogOpen) return;
    const item = itemForKey(menus, event);
    if (item) {
      event.preventDefault();
      if (isEnabled(item)) item.run?.();
      return;
    }
    const macro = macroForKey(event);
    if (macro !== null) {
      event.preventDefault();
      const chosen = settings.macros[macro];
      if (chosen) void activeTab()?.sendMacro(chosen);
      return;
    }
    const menu = menuForAltKey(menus, event);
    if (menu !== null) {
      event.preventDefault();
      void menuBar.openMenu(menu);
    }
  }

  /** The keys that belong to the app, so a terminal does not send them. */
  function isAppKey(event: KeyboardEvent): boolean {
    return itemForKey(menus, event) !== null || macroForKey(event) !== null || menuForAltKey(menus, event) !== null;
  }

  /** The web view's own menu, with its emoji and writing direction, only where text is typed; terminals have their own. */
  function oncontextmenu(event: MouseEvent) {
    const target = event.target instanceof Element ? event.target : null;
    if (!target?.closest("input, textarea, [contenteditable]") || target.closest(".xterm")) {
      event.preventDefault();
    }
  }

  function focusTerminal() {
    activeTerminal()?.focus();
  }
</script>

<svelte:window {onkeydown} {oncontextmenu} />

<div class="app">
  <MenuBar bind:this={menuBar} {menus} onclose={focusTerminal} />
  <TabBar onnew={() => (newTabOpen = true)} />

  <main class="pane" style:--view-size={`${unzoomed(settings.font_size)}px`}>
    {#if ready}
      {#if tabs.length === 0}
        <Welcome version={info?.version ?? ""} {helper} onnew={() => (newTabOpen = true)} />
      {/if}
      <!-- Every tab stays, hidden behind the one in front, so a terminal keeps what it showed. -->
      {#each tabs as tab, i (tab.id)}
        <div class="slot" class:hidden={i !== view.active}>
          {#if tab.built}
            <NetTab
              {tab}
              active={i === view.active}
              {isAppKey}
              onsettings={() => (setup = { tab, starting: false })}
              onmacros={() => (macrosOpen = true)}
              onhighlights={() => (highlightsOpen = true)}
            />
          {:else}
            <Coming {tab} />
          {/if}
        </div>
      {/each}
    {/if}
  </main>

  <StatusBar tab={activeTab()} {info} />
</div>

{#if newTabOpen}
  <NewTabDialog
    onpick={(kind) => {
      newTabOpen = false;
      openTab(kind);
    }}
    onclose={() => (newTabOpen = false)}
  />
{/if}

{#if setup}
  <SetupDialog
    tab={setup.tab}
    starting={setup.starting}
    onclose={() => {
      setup = null;
      focusTerminal();
    }}
  />
{/if}

{#if settingsOpen}
  <SettingsDialog onclose={() => (settingsOpen = false)} />
{/if}

{#if macrosOpen}
  <MacrosDialog
    onclose={() => {
      macrosOpen = false;
      focusTerminal();
    }}
  />
{/if}

{#if highlightsOpen}
  <HighlightsDialog
    onclose={() => {
      highlightsOpen = false;
      focusTerminal();
    }}
  />
{/if}

{#if certificatesOpen}
  <CertificatesDialog onclose={() => (certificatesOpen = false)} />
{/if}

{#if interfacesOpen}
  <InterfacesDialog onclose={() => (interfacesOpen = false)} />
{/if}

{#if palette}
  <CommandPalette commands={palette} onclose={() => (palette = null)} />
{/if}

{#if updateCheck && info}
  <UpdateDialog
    check={updateCheck}
    current={info.version}
    onskip={(version) => {
      updateSettings({ updates: { ...settings.updates, skipped: version } });
      updateCheck = null;
    }}
    onclose={() => (updateCheck = null)}
  />
{/if}

{#if aboutOpen && info}
  <About version={info.version} {helper} onclose={() => (aboutOpen = false)} />
{/if}

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .pane {
    position: relative;
    flex: 1;
    min-height: 0;
    background: var(--bg);
  }

  .slot {
    position: absolute;
    inset: 0;
  }

  .slot.hidden {
    display: none;
  }
</style>
