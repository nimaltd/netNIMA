// How a tab's state is shown: a colored dot and a few words.

import { endOf, isReady } from "./new-tab";
import { phaseName } from "./roadmap";
import type { Tab } from "./tabs.svelte";

export type Look = "connected" | "waiting" | "problem" | "stopped";

export function look(tab: Tab): Look {
  if (!tab.built || !tab.running) return "stopped";
  const status = tab.status;
  if (!status) return "waiting";
  switch (status.state) {
    case "connected":
    case "listening":
      return "connected";
    case "ended":
      return "problem";
    default:
      return status.problem ? "problem" : "waiting";
  }
}

export function stateText(tab: Tab): string {
  const found = endOf(tab.kind);
  if (found && !isReady(tab.kind)) {
    const phase = found.protocol.phase;
    return `Comes in Phase ${phase}: ${phaseName(phase)}`;
  }
  if (!tab.running) return tab.socket === "replay" ? "Not playing" : "Not connected";
  const status = tab.status;
  if (!status) return "Starting...";
  const count = tab.peers.length;
  switch (status.state) {
    case "connected":
      if (tab.socket === "replay") return tab.playback?.playing ? "Playing" : "Paused";
      return `Connected to ${status.address}`;
    case "listening":
      if (tab.socket === "none") return "Running";
      if (tab.socket === "server") return `Listening on ${status.local}, ${count} ${count === 1 ? "client" : "clients"}`;
      return `Open on ${status.local}, ${count} ${count === 1 ? "peer" : "peers"} heard`;
    case "ended":
      return `Ended${status.problem ? `: ${status.problem}` : ""}`;
    default:
      if (status.problem) return status.problem;
      return tab.socket === "client" ? "Waiting for the other end..." : "Waiting to open the port...";
  }
}
