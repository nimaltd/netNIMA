<script lang="ts">
  import { open, save } from "@tauri-apps/plugin-dialog";

  // A file's path in a dialog, typed or chosen with the OS's file dialog: a
  // certificate, a key, or a key log to write.
  let {
    label,
    value = $bindable(),
    placeholder = "",
    saving = false,
    kinds = [],
    wide = false,
  }: {
    label: string;
    value: string;
    placeholder?: string;
    /** Chooses a file to write, such as a key log, rather than one to read. */
    saving?: boolean;
    /** The file types offered, such as [{ name: "Certificates", extensions: ["pem", "crt"] }]. */
    kinds?: { name: string; extensions: string[] }[];
    wide?: boolean;
  } = $props();

  async function choose() {
    const chosen = saving
      ? await save({ defaultPath: value || undefined, filters: kinds })
      : await open({ multiple: false, directory: false, defaultPath: value || undefined, filters: kinds });
    if (typeof chosen === "string") value = chosen;
  }
</script>

<label class="dlg-label" class:wide>
  {label}
  <span class="row">
    <input class="field mono" {placeholder} spellcheck="false" bind:value />
    <button class="btn" type="button" title="Choose the file" onclick={choose}>...</button>
  </span>
</label>

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
</style>
