// MCUmgr (SMP) as its tabs' views see it: a board's images and threads out
// of the answers' bodies, and the lines the view gives the engine, as a
// person would type them. It has no imports, so its tests run in Node as
// they are.

/** One image slot, as image state lists it. */
export type Image = {
  image: number;
  slot: number;
  version: string;
  /** Its SHA-256, in hex. */
  hash: string;
  bootable: boolean;
  pending: boolean;
  confirmed: boolean;
  active: boolean;
  permanent: boolean;
};

/** One thread, as taskstat lists it. */
export type Task = {
  name: string;
  priority: number;
  state: number;
  stackUsed: number;
  stackSize: number;
  switches: number;
  runtime: number;
};

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
const number = (value: unknown) => (typeof value === "number" ? value : 0);

/** The images in an answer's body, from image state, test or confirm; empty when it has none. */
export function imagesOf(body: unknown): Image[] {
  const images = record(body).images;
  if (!Array.isArray(images)) return [];
  return images.map((each) => {
    const image = record(each);
    return {
      image: number(image.image),
      slot: number(image.slot),
      version: typeof image.version === "string" ? image.version : "",
      hash: typeof image.hash === "string" ? image.hash : "",
      bootable: image.bootable === true,
      pending: image.pending === true,
      confirmed: image.confirmed === true,
      active: image.active === true,
      permanent: image.permanent === true,
    };
  });
}

/** The threads in taskstat's answer, by their priority, as Zephyr runs them. */
export function tasksOf(body: unknown): Task[] {
  return Object.entries(record(record(body).tasks))
    .map(([name, each]) => {
      const task = record(each);
      return {
        name,
        priority: number(task.prio),
        state: number(task.state),
        stackUsed: number(task.stkuse),
        stackSize: number(task.stksiz),
        switches: number(task.cswcnt),
        runtime: number(task.runtime),
      };
    })
    .sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name));
}

/** What an image is, in words: "active, confirmed". */
export function flagsOf(image: Image): string[] {
  return (["active", "confirmed", "pending", "bootable", "permanent"] as const).filter((flag) => image[flag]);
}

/** A hash shortened to its first eight digits, as mcumgr's users name images. */
export function shortHash(hash: string): string {
  return hash.length > 8 ? `${hash.slice(0, 8)}…` : hash;
}

/** A word of the engine's line: in double quotes, its backslashes and quotes escaped, when it has a space, a quote or a backslash. */
export function word(text: string): string {
  return /[\s"\\]/.test(text) ? `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : text;
}

/** The line that uploads a file as an image; or why it cannot. */
export function uploadLine(file: string, image: number): { line: string; problem: string } {
  const name = file.trim();
  if (!name) return { line: "", problem: "Choose the image's file first, such as zephyr.signed.bin." };
  if (!Number.isInteger(image) || image < 0 || image > 255) return { line: "", problem: "The image number is 0 to 255." };
  return { line: `upload ${word(name)}${image ? ` ${image}` : ""}`, problem: "" };
}

/** The line that marks an image to run once at the next reset, or keeps it: by its hash. */
export function markLine(what: "test" | "confirm", hash: string): { line: string; problem: string } {
  const digits = hash.trim();
  if (what === "confirm" && digits === "") return { line: "confirm", problem: "" };
  if (!/^[0-9a-f]{2,128}$/i.test(digits) || digits.length % 2 !== 0) return { line: "", problem: "The hash is hex digits, as image state gives it." };
  return { line: `${what} ${digits}`, problem: "" };
}

/** A file's name without its folder. */
export function baseName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

/** Bytes as people read them: 512 B, 3.2 KB, 1.4 MB. */
export function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Number((bytes / 1024).toFixed(1))} KB`;
  return `${Number((bytes / 1024 / 1024).toFixed(2))} MB`;
}
