// Which of the tabs saved last time open again. It has no imports, so its
// tests run in Node as they are.

/** A saved tab, as far as this needs: its kind. */
export type Saved = { kind: string };

/**
 * The saved tabs that open, by their place in the list, in their order: the
 * ones of a kind this netNIMA knows. A tab a newer netNIMA saved, of a kind
 * this one does not know yet, is left out.
 */
export function reopened(saved: Saved[], known: (kind: string) => boolean): number[] {
  return saved.flatMap((tab, at) => (known(tab.kind) ? [at] : []));
}
