// What the app knows of netnima-helper, the program beside it that will hold
// the rights the app never asks for. It has no imports, so its tests run in
// Node as they are.

/** The same fields as `HelperInfo` in src-tauri's helper.rs. */
export type HelperInfo = {
  /** Where the app looked for it. */
  path: string;
  /** Its version, such as "0.1.0"; empty when it was not found or did not run. */
  version: string;
  /** What is wrong with it, in words; empty when it is the helper of this very version. */
  problem: string;
};

/** The helper in a few words, for the welcome page and the About box; "..." while it is looked for. */
export function helperText(info: HelperInfo | null): string {
  if (!info) return "...";
  if (!info.problem) return `netnima-helper ${info.version}, beside the app`;
  if (info.version) return `netnima-helper ${info.version}: ${info.problem}`;
  return `netnima-helper ${info.problem}`;
}

/** Whether the helper is there and of this very version. */
export function helperIsGood(info: HelperInfo | null): boolean {
  return info !== null && info.version !== "" && info.problem === "";
}
