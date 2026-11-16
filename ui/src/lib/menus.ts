// What is in the menu bar. Items for later phases of the roadmap are listed
// already, greyed out with their phase, so the menus show where the app is going.

import { openUrl } from "@tauri-apps/plugin-opener";
import type { Command } from "./palette";
import { GITHUB, LAST_PHASE, PLAN } from "./roadmap";
import {
  FONT_SIZE_DEFAULT,
  FONT_SIZE_MAX,
  FONT_SIZE_MIN,
  MENU_FONT_SIZE_DEFAULT,
  MENU_FONT_SIZE_MAX,
  MENU_FONT_SIZE_MIN,
  settings,
  updateSettings,
  type ThemeChoice,
} from "./settings.svelte";
import { isMac, keys, matches } from "./shortcuts";
import { activeTab, closeTab, showTab, tabs, view, type Tab } from "./tabs.svelte";
import { activeTerminal } from "./terminal-actions";
import type { View } from "./types";

export type Item = {
  label: string;
  shortcut?: string;
  /** Shown on the right where a shortcut would be. */
  hint?: string;
  /** The roadmap phase that brings this item. Until then it is greyed out. */
  phase?: number;
  enabled?: () => boolean;
  checked?: () => boolean;
  run?: () => void;
};

/**
 * A menu's items, with `null` for a separator line and a string for a heading over the items after it. `key` is
 * the letter Alt opens it with, when that is not the first letter of its title.
 */
export type Menu = { title: string; key?: string; items: (Item | string | null)[] };

/** What the menus ask of the app around them. */
export type AppActions = {
  about(): void;
  exit(): void;
  /** Opens the New tab dialog, with every protocol and its two ends. */
  newTab(): void;
  /** Opens the app's settings. */
  settings(): void;
  /** Opens the settings of the tab in front: its socket and its terminal. */
  tabSettings(): void;
  /** Opens the command palette. */
  commandPalette(): void;
  /** Looks on GitHub for a newer netNIMA, and says what it found. */
  checkUpdates(): void;
  /** Picks a recording and plays it in a new tab. */
  playRecording(): void;
  /** Shows the tab's log file, or the log folder, in the OS's file manager. */
  openLogFolder(): void;
  /** Picks a file and sends it through the tab in front. */
  sendFile(): void;
  macros(): void;
  highlights(): void;
  /** Makes test certificates, and shows netNIMA's own. */
  certificates(): void;
  /** Shows the PC's network cards, with their addresses. */
  interfaces(): void;
};

/** The shortcut for File > New tab, also shown on the welcome page. */
export const NEW_TAB_SHORTCUT = keys("Ctrl+Shift+N", "Cmd+N");

/** The tab in front, if it is one that runs a socket or a recording. */
function socketTab(): Tab | null {
  const tab = activeTab();
  return tab && tab.built ? tab : null;
}

export function buildMenus(app: AppActions): Menu[] {
  const theme = (label: string, choice: ThemeChoice): Item => ({
    label,
    checked: () => settings.theme === choice,
    run: () => updateSettings({ theme: choice }),
  });
  const textSize = (size: number) =>
    updateSettings({ font_size: Math.min(FONT_SIZE_MAX, Math.max(FONT_SIZE_MIN, size)) });
  const menuTextSize = (size: number) =>
    updateSettings({ menu_font_size: Math.min(MENU_FONT_SIZE_MAX, Math.max(MENU_FONT_SIZE_MIN, size)) });

  const hasTab = () => activeTab() !== undefined;
  const hasTabs = () => tabs.length > 1;
  const showView = (label: string, shown: View, shortcut?: string): Item => ({
    label,
    shortcut,
    enabled: () => socketTab() !== null,
    checked: () => socketTab()?.view === shown,
    run: () => socketTab()?.setView(shown),
  });
  const live = () => {
    const tab = socketTab();
    return tab !== null && tab.socket !== "replay" ? tab : null;
  };

  return [
    {
      title: "File",
      items: [
        { label: "New tab...", shortcut: NEW_TAB_SHORTCUT, run: app.newTab },
        {
          label: "Close tab",
          shortcut: keys("Ctrl+Shift+W", "Cmd+W"),
          enabled: hasTab,
          run: () => {
            const tab = activeTab();
            if (tab) closeTab(tab);
          },
        },
        null,
        {
          label: "Log this tab",
          shortcut: keys("Ctrl+Shift+L", "Cmd+Shift+L"),
          enabled: () => live() !== null,
          checked: () => live()?.log === true,
          run: () => {
            const tab = live();
            tab?.setLog(!tab.log);
          },
        },
        {
          label: "Record this tab",
          enabled: () => live()?.running === true,
          checked: () => live()?.recordPath != null,
          run: () => {
            const tab = live();
            tab?.setRecording(tab.recordPath === null);
          },
        },
        { label: "Play back a recording...", run: app.playRecording },
        { label: "Open log folder", run: app.openLogFolder },
        null,
        { label: "Open a capture file...", phase: 10 },
        null,
        { label: "Settings...", shortcut: keys("Ctrl+,", "Cmd+,"), run: app.settings },
        null,
        isMac ? { label: "Quit netNIMA", shortcut: "Cmd+Q", run: app.exit } : { label: "Exit", run: app.exit },
      ],
    },
    {
      title: "Edit",
      items: [
        {
          label: "Copy",
          shortcut: keys("Ctrl+Shift+C", "Cmd+C"),
          run: () => {
            const terminal = activeTerminal();
            if (terminal) void terminal.copy();
            else document.execCommand("copy");
          },
        },
        {
          label: "Paste",
          shortcut: keys("Ctrl+Shift+V", "Cmd+V"),
          enabled: () => activeTerminal() !== null,
          run: () => void activeTerminal()?.paste(),
        },
        {
          label: "Select all",
          shortcut: keys("Ctrl+Shift+A", "Cmd+A"),
          enabled: () => activeTerminal() !== null,
          run: () => activeTerminal()?.selectAll(),
        },
        null,
        {
          label: "Find...",
          shortcut: keys("Ctrl+Shift+F", "Cmd+F"),
          enabled: () => activeTerminal() !== null,
          run: () => activeTerminal()?.openSearch(),
        },
        {
          label: "Clear",
          shortcut: keys("Ctrl+Shift+K", "Cmd+K"),
          enabled: () => activeTerminal() !== null,
          run: () => activeTerminal()?.clear(),
        },
      ],
    },
    {
      title: "View",
      items: [
        {
          label: "Command palette...",
          shortcut: keys("Ctrl+Shift+P", "Cmd+Shift+P"),
          run: app.commandPalette,
        },
        null,
        showView("Terminal", "terminal", keys("Ctrl+Shift+T", "Cmd+Shift+T")),
        showView("Hex", "hex", keys("Ctrl+Shift+H", "Cmd+Shift+H")),
        showView("Lines", "lines", keys("Ctrl+Shift+J", "Cmd+Shift+J")),
        showView("Plot", "plot", keys("Ctrl+Shift+G", "Cmd+Shift+G")),
        { label: "Packets", phase: 10 },
        {
          label: "Scroll lock",
          shortcut: "ScrollLock",
          enabled: () => socketTab() !== null,
          checked: () => socketTab()?.scrollLock === true,
          run: () => {
            const tab = socketTab();
            tab?.setScrollLock(!tab.scrollLock);
          },
        },
        null,
        {
          label: "Next tab",
          shortcut: "Ctrl+Tab",
          enabled: hasTabs,
          run: () => showTab(view.active + 1),
        },
        {
          label: "Previous tab",
          shortcut: "Ctrl+Shift+Tab",
          enabled: hasTabs,
          run: () => showTab(view.active - 1),
        },
        null,
        {
          label: "Bigger text",
          shortcut: keys("Ctrl+=", "Cmd+="),
          run: () => textSize(settings.font_size + 1),
        },
        {
          label: "Smaller text",
          shortcut: keys("Ctrl+-", "Cmd+-"),
          run: () => textSize(settings.font_size - 1),
        },
        {
          label: "Normal text size",
          shortcut: keys("Ctrl+0", "Cmd+0"),
          run: () => textSize(FONT_SIZE_DEFAULT),
        },
        null,
        { label: "Bigger menu text", run: () => menuTextSize(settings.menu_font_size + 1) },
        { label: "Smaller menu text", run: () => menuTextSize(settings.menu_font_size - 1) },
        { label: "Normal menu text size", run: () => menuTextSize(MENU_FONT_SIZE_DEFAULT) },
        null,
        theme("System theme", "system"),
        theme("Dark theme", "dark"),
        theme("Light theme", "light"),
      ],
    },
    {
      title: "Connection",
      items: [
        {
          label: "Connect or listen",
          shortcut: "F5",
          enabled: () => live() !== null && !live()!.running,
          run: () => live()?.start(),
        },
        {
          label: "Disconnect or stop",
          shortcut: "Shift+F5",
          enabled: () => socketTab()?.running === true,
          run: () => socketTab()?.stop(),
        },
        {
          label: "Reset the connection",
          enabled: () => live()?.socket === "client" && live()!.connected,
          run: () => live()?.resetConnection(),
        },
        null,
        {
          label: "Tab settings...",
          shortcut: keys("Ctrl+Shift+E", "Cmd+Shift+E"),
          enabled: () => live() !== null,
          run: app.tabSettings,
        },
        { label: "Send a file...", enabled: () => live()?.connected === true, run: app.sendFile },
        { label: "Macros...", run: app.macros },
        { label: "Highlights...", run: app.highlights },
      ],
    },
    {
      // Alt+C is Connection's.
      title: "Capture",
      key: "P",
      items: [
        { label: "Start capturing", phase: 10 },
        { label: "Stop capturing", phase: 10 },
        null,
        { label: "Follow the stream", phase: 11 },
        { label: "Statistics", phase: 11 },
        { label: "Open in Wireshark", phase: 10 },
      ],
    },
    {
      title: "Tools",
      items: [
        { label: "Certificates...", run: app.certificates },
        { label: "The PC's interfaces...", run: app.interfaces },
      ],
    },
    {
      title: "Help",
      items: [
        { label: "netNIMA help", phase: LAST_PHASE },
        { label: "The plan", run: () => void openUrl(PLAN) },
        { label: "netNIMA on GitHub", run: () => void openUrl(GITHUB) },
        { label: "Report a bug...", run: () => void openUrl(`${GITHUB}/issues/new`) },
        { label: "Check for updates...", run: app.checkUpdates },
        null,
        { label: "About netNIMA", run: app.about },
      ],
    },
  ];
}

/**
 * Every menu item that can be used now, as commands for the palette: the
 * palette's own item and the items of later phases left out.
 */
export function menuCommands(menus: Menu[]): Command[] {
  const commands: Command[] = [];
  for (const menu of menus) {
    // Items under a heading are named with it: "New tab: UDP".
    let heading = "";
    for (const item of menu.items) {
      if (typeof item === "string" || item === null) {
        heading = item ?? "";
      } else if (isEnabled(item) && item.run && !item.label.startsWith("Command palette")) {
        commands.push({
          label: `${heading ? `${heading}: ` : ""}${item.label.replace(/\.\.\.$/, "")}`,
          group: menu.title,
          shortcut: item.shortcut,
          checked: item.checked?.() ?? false,
          run: item.run,
        });
      }
    }
  }
  return commands;
}

/** Whether an item can be used right now. */
export function isEnabled(item: Item): boolean {
  return item.phase === undefined && item.run !== undefined && (item.enabled?.() ?? true);
}

/** The item whose shortcut this key press is, if any. */
export function itemForKey(menus: Menu[], event: KeyboardEvent): Item | null {
  for (const menu of menus) {
    for (const item of menu.items) {
      if (item && typeof item !== "string" && item.shortcut && matches(item.shortcut, event)) {
        return item;
      }
    }
  }
  return null;
}

/** The macro whose key this is: Alt+1 to Alt+9, Cmd+1 to Cmd+9 on macOS. */
export function macroForKey(event: KeyboardEvent): number | null {
  for (let number = 1; number <= 9; number++) {
    if (matches(keys(`Alt+${number}`, `Cmd+${number}`), event)) {
      return number - 1;
    }
  }
  return null;
}

/** Alt+F opens File, Alt+E opens Edit, Alt+P opens Capture and so on; not on macOS, where Option types characters. */
export function menuForAltKey(menus: Menu[], event: KeyboardEvent): number | null {
  if (isMac || !event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) {
    return null;
  }
  const index = menus.findIndex((menu) => event.code === `Key${menu.key ?? menu.title[0]}`);
  return index >= 0 ? index : null;
}
