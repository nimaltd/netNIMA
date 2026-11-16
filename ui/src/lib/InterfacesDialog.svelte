<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { writeText } from "@tauri-apps/plugin-clipboard-manager";
  import { onMount } from "svelte";
  import Modal from "./Modal.svelte";
  import { bytesText, rate, selfAssigned, shownAtFirst, speedText, summary, type Interface } from "./interfaces";

  // Tools > The PC's interfaces: every network card of this PC with its
  // addresses, MAC address, MTU, state, speed, gateway and DNS servers, and
  // which are Wi-Fi. Read again every two seconds while it is open, so a
  // cable plugged in shows, with the bytes each takes and sends a second.
  // A click on an address copies it.
  let { onclose }: { onclose: () => void } = $props();

  let list = $state<Interface[] | null>(null);
  let problem = $state("");
  /** Whether the loopback and the virtual cards that are down are listed too. */
  let all = $state(false);
  let copied = $state("");
  /** Bytes a second in and out, by interface, from the last two readings. */
  let rates: Record<string, { in: number | null; out: number | null }> = $state({});
  let last: { at: number; counts: Map<string, [number | null, number | null]> } | null = null;

  const key = (entry: Interface) => `${entry.index}/${entry.id || entry.name}`;

  async function read() {
    try {
      const found = await invoke<Interface[]>("list_interfaces");
      const at = Date.now();
      if (last) {
        const before = last;
        rates = Object.fromEntries(
          found.map((entry) => {
            const [received, sent] = before.counts.get(key(entry)) ?? [null, null];
            return [key(entry), { in: rate(received, entry.received, at - before.at), out: rate(sent, entry.sent, at - before.at) }];
          }),
        );
      }
      last = { at, counts: new Map(found.map((entry) => [key(entry), [entry.received, entry.sent]])) };
      list = found;
      problem = "";
    } catch (failed) {
      problem = String(failed);
    }
  }

  onMount(() => {
    void read();
    const timer = setInterval(() => void read(), 2000);
    return () => clearInterval(timer);
  });

  const shown = $derived((list ?? []).filter((entry) => all || shownAtFirst(entry)));
  const hidden = $derived((list ?? []).filter((entry) => !shownAtFirst(entry)).length);

  async function copy(what: string, text: string) {
    await writeText(text);
    copied = what;
    setTimeout(() => (copied = copied === what ? "" : copied), 1500);
  }
</script>

{#snippet address(label: string, text: string, title: string)}
  <button class="chip mono" {title} onclick={() => void copy(label, text)}>{copied === label ? "Copied" : label}</button>
{/snippet}

<Modal title="The PC's interfaces" {onclose} onsubmit={onclose}>
  <p class="dlg-hint">Every network card of this PC, read again every two seconds. A click on an address copies it.</p>
  {#if problem}
    <p class="dlg-error">{problem}</p>
  {/if}
  {#if list === null}
    <p class="dlg-hint">Looking...</p>
  {:else}
    {#each shown as entry (key(entry))}
      {@const now = rates[key(entry)]}
      <section class="card" class:down={!entry.up}>
        <div class="head">
          <span class="dot" class:up={entry.up} title={entry.up ? "Up" : "Down"}></span>
          <span class="name">{entry.name}</span>
          <span class="badge" class:on={entry.wifi}>{entry.kind}</span>
          {#if entry.default}
            <span class="badge on" title="The OS sends to the internet through it">default route</span>
          {/if}
          {#if !entry.physical && !entry.loopback}
            <span class="badge" title="Made by a VM, a VPN or the OS, not a card of this PC's own">virtual</span>
          {/if}
          <span class="spacer"></span>
          <span class="muted">{entry.up ? "up" : "down"}</span>
          <button class="btn small" title="Copy all of it as text" onclick={() => void copy(`all ${key(entry)}`, summary(entry))}>
            {copied === `all ${key(entry)}` ? "Copied" : "Copy"}
          </button>
        </div>
        {#if entry.description}
          <div class="muted description">{entry.description}</div>
        {/if}
        <dl class="facts">
          {#if entry.ipv4_networks.length > 0}
            <dt>IPv4</dt>
            <dd>
              {#each entry.ipv4_networks as network, at (network)}
                {@render address(network, entry.ipv4[at] ?? network, `Copy ${entry.ipv4[at] ?? network}`)}
              {/each}
              {#if entry.dhcp !== null}
                <span class="muted">{entry.dhcp ? "by DHCP" : "fixed"}</span>
              {/if}
              {#if entry.ipv4.some(selfAssigned)}
                <span class="note">
                  169.254: the PC gave itself an address, as no DHCP server answered. For a board wired here, give this card a fixed address, or run a DHCP server tab on it.
                </span>
              {/if}
            </dd>
          {/if}
          {#if entry.ipv6_networks.length > 0}
            <dt>IPv6</dt>
            <dd>
              {#each entry.ipv6_networks as network, at (network)}
                {@render address(network, entry.ipv6[at] ?? network, `Copy ${entry.ipv6[at] ?? network}`)}
              {/each}
            </dd>
          {/if}
          {#if entry.mac}
            <dt>MAC</dt>
            <dd>{@render address(entry.mac, entry.mac, "Copy the MAC address")}</dd>
          {/if}
          {#if entry.gateway.length > 0}
            <dt>Gateway</dt>
            <dd>
              {#each entry.gateway as gateway (gateway)}
                {@render address(gateway, gateway, "Copy the gateway's address")}
              {/each}
              {#if entry.gateway_mac}
                <span class="muted mono">{entry.gateway_mac}</span>
              {/if}
            </dd>
          {/if}
          {#if entry.dns.length > 0}
            <dt>DNS</dt>
            <dd>
              {#each entry.dns as server (server)}
                {@render address(server, server, "Copy the DNS server's address")}
              {/each}
            </dd>
          {/if}
          <dt>Link</dt>
          <dd>
            {[
              speedText(entry.transmit_speed, entry.receive_speed),
              entry.mtu === null ? "" : `MTU ${entry.mtu}`,
              entry.index ? `index ${entry.index}` : "",
            ]
              .filter(Boolean)
              .join(" · ") || "-"}
          </dd>
          {#if entry.received !== null && entry.sent !== null}
            <dt>Traffic</dt>
            <dd>
              {bytesText(entry.received)} in, {bytesText(entry.sent)} out
              {#if now && now.in !== null && now.out !== null}
                <span class="muted">· now {bytesText(Math.round(now.in))}/s in, {bytesText(Math.round(now.out))}/s out</span>
              {/if}
            </dd>
          {/if}
          {#if entry.id}
            <dt>Id</dt>
            <dd class="mono muted small">{entry.id}</dd>
          {/if}
        </dl>
      </section>
    {:else}
      <p class="dlg-hint">The OS lists no network card.</p>
    {/each}
    {#if hidden > 0}
      <label class="dlg-check">
        <input type="checkbox" bind:checked={all} />
        Show the other {hidden}: the loopback, and the virtual cards that are down
      </label>
    {/if}
  {/if}

  {#snippet buttons()}
    <button class="btn" onclick={() => void read()}>Read again</button>
    <button class="btn primary" onclick={onclose}>Close</button>
  {/snippet}
</Modal>

<style>
  .card {
    margin: 8px 0;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
  }

  .card.down {
    opacity: 0.75;
  }

  .head {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 8px;
    align-items: center;
  }

  .name {
    font-weight: 600;
  }

  .dot {
    width: 8px;
    height: 8px;
    background: var(--muted);
    border-radius: 50%;
  }

  .dot.up {
    background: var(--good, var(--accent));
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

  .spacer {
    flex: 1;
  }

  .small {
    height: 24px;
    padding: 0 10px;
    font-size: 12px;
  }

  .description {
    margin: 2px 0 0 16px;
    font-size: 12px;
  }

  .facts {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 4px 12px;
    margin: 6px 0 0;
    font-size: 12px;
  }

  .facts dt {
    color: var(--muted);
  }

  .facts dd {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 6px;
    align-items: baseline;
    margin: 0;
    overflow-wrap: anywhere;
  }

  .chip {
    padding: 0 6px;
    font-size: 12px;
    color: var(--text);
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 5px;
    cursor: default;
  }

  .chip:hover {
    border-color: var(--accent);
  }

  .note {
    flex-basis: 100%;
    color: var(--muted);
  }

  .muted {
    color: var(--muted);
  }
</style>
