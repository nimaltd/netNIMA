<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { writeText } from "@tauri-apps/plugin-clipboard-manager";
  import { open } from "@tauri-apps/plugin-dialog";
  import { revealItemInDir } from "@tauri-apps/plugin-opener";
  import Modal from "./Modal.svelte";
  import type { CertInfo } from "./net";

  // Tools > Certificates: netNIMA's own certificate, which its TLS servers
  // use when a tab chooses none, and test sets made for devices: a CA, and a
  // server's and a client's certificate it signed.
  let { onclose }: { onclose: () => void } = $props();

  type Own = { cert: string; key: string; info: CertInfo | null; problem: string | null };
  type MadeSet = { files: string[]; ca_sha256: string; server_sha256: string; client_sha256: string };

  let own: Own | null = $state(null);
  let folder = $state("");
  let serverNames = $state("");
  let clientName = $state("device");
  let years = $state(10);
  let made: MadeSet | null = $state(null);
  let error = $state("");
  let making = $state(false);
  let copied = $state("");

  onMount(() => {
    invoke<Own>("own_certificate")
      .then((found) => (own = found))
      .catch((problem) => (own = { cert: "", key: "", info: null, problem: String(problem) }));
    invoke<string[]>("local_names")
      .then((names) => (serverNames = names.join(", ")))
      .catch(() => (serverNames = "localhost, 127.0.0.1"));
  });

  async function chooseFolder() {
    const chosen = await open({ directory: true, multiple: false, defaultPath: folder || undefined });
    if (typeof chosen === "string") folder = chosen;
  }

  async function make() {
    error = "";
    made = null;
    making = true;
    try {
      made = await invoke<MadeSet>("make_certificates", {
        request: {
          folder,
          server_names: serverNames.split(/[,\s]+/).filter(Boolean),
          client_name: clientName,
          years: Number(years) || 10,
        },
      });
    } catch (problem) {
      error = String(problem);
    } finally {
      making = false;
    }
  }

  async function copy(what: string, text: string) {
    await writeText(text);
    copied = what;
    setTimeout(() => (copied = copied === what ? "" : copied), 1500);
  }
</script>

<Modal title="Certificates" {onclose} onsubmit={make}>
  <h2 class="dlg-section">netNIMA's own</h2>
  {#if own === null}
    <p class="dlg-hint">Looking...</p>
  {:else if own.problem}
    <p class="dlg-error">{own.problem}</p>
  {:else}
    <p class="dlg-hint">
      TLS server tabs with no certificate chosen use this one. It is self-signed, so a device must trust this file, or not check.
    </p>
    {#if own.info}
      <dl class="facts">
        <dt>For</dt>
        <dd class="mono">{own.info.names.join(", ")}</dd>
        <dt>Valid</dt>
        <dd>{own.info.not_before} to {own.info.not_after}</dd>
        <dt>Key</dt>
        <dd>{own.info.key}</dd>
        <dt>SHA-256</dt>
        <dd class="mono small">{own.info.sha256}</dd>
        <dt>File</dt>
        <dd class="mono small">{own.cert}</dd>
      </dl>
    {/if}
    <div class="actions">
      <button class="btn" onclick={() => void revealItemInDir(own?.cert ?? "")}>Show the file</button>
      {#if own.info}
        <button class="btn" onclick={() => void copy("sha", own?.info?.sha256 ?? "")}>{copied === "sha" ? "Copied" : "Copy SHA-256"}</button>
      {/if}
    </div>
  {/if}

  <h2 class="dlg-section">A test set for devices</h2>
  <p class="dlg-hint">
    A CA, and a server's and a client's certificate it signed, with ECDSA P-256 keys: PEM and DER files, and certs.h with
    them all as C arrays for firmware. For testing only.
  </p>
  <div class="dlg-grid">
    <label class="dlg-label wide">
      Folder
      <span class="row">
        <input class="field mono" placeholder="Where the files go" spellcheck="false" bind:value={folder} />
        <button class="btn" type="button" title="Choose the folder" onclick={chooseFolder}>...</button>
      </span>
    </label>
    <label class="dlg-label">
      Valid for, years
      <input class="field mono" type="number" min="1" max="100" bind:value={years} />
    </label>
    <label class="dlg-label wide">
      The server is
      <input class="field mono" placeholder="board.local, 192.168.1.50" spellcheck="false" bind:value={serverNames} />
    </label>
    <label class="dlg-label">
      The client is
      <input class="field mono" placeholder="device" spellcheck="false" bind:value={clientName} />
    </label>
  </div>

  {#if error}
    <p class="dlg-error">{error}</p>
  {/if}
  {#if made}
    <p class="dlg-hint">Made {made.files.length} files:</p>
    <ul class="files mono small">
      {#each made.files as file (file)}
        <li>{file.split(/[\\/]/).pop()}</li>
      {/each}
    </ul>
    <dl class="facts">
      <dt>CA</dt>
      <dd class="mono small">{made.ca_sha256}</dd>
      <dt>Server</dt>
      <dd class="mono small">{made.server_sha256}</dd>
      <dt>Client</dt>
      <dd class="mono small">{made.client_sha256}</dd>
    </dl>
    <div class="actions">
      <button class="btn" onclick={() => void revealItemInDir(made?.files[0] ?? "")}>Show them</button>
    </div>
  {/if}

  {#snippet buttons()}
    <button class="btn" onclick={onclose}>Close</button>
    <button class="btn primary" disabled={making} onclick={make}>{making ? "Making..." : "Make a set"}</button>
  {/snippet}
</Modal>

<style>
  .wide {
    grid-column: span 2;
  }

  .row {
    display: flex;
    gap: 6px;
  }

  .row input {
    flex: 1;
    min-width: 0;
  }

  .facts {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 4px 12px;
    margin: 8px 0;
    font-size: 12px;
  }

  .facts dt {
    color: var(--muted);
  }

  .facts dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .small {
    font-size: 11px;
  }

  .actions {
    display: flex;
    gap: 8px;
    margin-bottom: 6px;
  }

  .files {
    columns: 3;
    margin: 4px 0 8px;
    padding-left: 18px;
  }
</style>
