// LwM2M as its tabs' views see it: objects and resources by the names
// OMA's registry gives their numbers, what some values mean, and the lines
// the views give the engine, as a person would type them. It has no
// imports, so its tests run in Node as they are.

/** The objects a device may have, by number. */
export const OBJECTS: Record<number, string> = {
  0: "Security",
  1: "Server",
  2: "Access Control",
  3: "Device",
  4: "Connectivity Monitoring",
  5: "Firmware Update",
  6: "Location",
  7: "Connectivity Statistics",
  9: "Software Management",
  3200: "Digital Input",
  3201: "Digital Output",
  3202: "Analog Input",
  3203: "Analog Output",
  3300: "Generic Sensor",
  3301: "Illuminance",
  3303: "Temperature",
  3304: "Humidity",
  3306: "Actuation",
  3311: "Light Control",
  3313: "Accelerometer",
  3315: "Barometer",
  3323: "Pressure",
  3328: "Power",
  3336: "Location",
  3342: "On/Off Switch",
  3347: "Push Button",
};

/** Resources of one object, by number. */
const OBJECT_RESOURCES: Record<number, Record<number, string>> = {
  0: {
    0: "Server URI",
    1: "Bootstrap Server",
    2: "Security Mode",
    3: "Public Key or Identity",
    4: "Server Public Key",
    5: "Secret Key",
    10: "Short Server ID",
  },
  1: {
    0: "Short Server ID",
    1: "Lifetime",
    2: "Default Minimum Period",
    3: "Default Maximum Period",
    4: "Disable",
    5: "Disable Timeout",
    6: "Notification Storing",
    7: "Binding",
    8: "Registration Update Trigger",
    9: "Bootstrap-Request Trigger",
  },
  3: {
    0: "Manufacturer",
    1: "Model Number",
    2: "Serial Number",
    3: "Firmware Version",
    4: "Reboot",
    5: "Factory Reset",
    6: "Available Power Sources",
    7: "Power Source Voltage",
    8: "Power Source Current",
    9: "Battery Level",
    10: "Memory Free",
    11: "Error Code",
    12: "Reset Error Code",
    13: "Current Time",
    14: "UTC Offset",
    15: "Timezone",
    16: "Supported Binding and Modes",
    17: "Device Type",
    18: "Hardware Version",
    19: "Software Version",
    20: "Battery Status",
    21: "Memory Total",
  },
  4: {
    0: "Network Bearer",
    1: "Available Network Bearer",
    2: "Radio Signal Strength",
    3: "Link Quality",
    4: "IP Addresses",
    5: "Router IP Addresses",
    6: "Link Utilization",
    7: "APN",
    8: "Cell ID",
    9: "SMNC",
    10: "SMCC",
  },
  5: {
    0: "Package",
    1: "Package URI",
    2: "Update",
    3: "State",
    5: "Update Result",
    6: "Package Name",
    7: "Package Version",
    8: "Update Protocol Support",
    9: "Update Delivery Method",
  },
  6: { 0: "Latitude", 1: "Longitude", 2: "Altitude", 3: "Radius", 4: "Velocity", 5: "Timestamp", 6: "Speed" },
};

/** The IPSO resources the sensor and actuator objects share. */
const IPSO_RESOURCES: Record<number, string> = {
  5500: "Digital Input State",
  5501: "Digital Input Counter",
  5550: "Digital Output State",
  5600: "Analog Input Current Value",
  5601: "Min Measured Value",
  5602: "Max Measured Value",
  5603: "Min Range Value",
  5604: "Max Range Value",
  5605: "Reset Min and Max",
  5700: "Sensor Value",
  5701: "Sensor Units",
  5702: "X Value",
  5703: "Y Value",
  5704: "Z Value",
  5706: "Colour",
  5750: "Application Type",
  5805: "Cumulative Active Power",
  5820: "Power Factor",
  5850: "On/Off",
  5851: "Dimmer",
  5852: "On Time",
};

/** The resources a server executes rather than reads, by object, and IPSO's. */
const EXECUTABLE: Record<number, number[]> = { 1: [4, 8, 9], 3: [4, 5, 12], 5: [2] };
const IPSO_EXECUTABLE = [5605];

/** "/3/0/1" as its numbers; null when it is not an LwM2M path. */
export function parsePath(path: string): number[] | null {
  const trimmed = path.trim().replace(/^\/+|\/+$/g, "");
  if (!/^\d{1,5}(\/\d{1,5}){0,3}$/.test(trimmed)) return null;
  const parts = trimmed.split("/").map(Number);
  return parts.every((part) => part <= 65535) ? parts : null;
}

/** A path with one slash in front, as the engine shows paths. */
export function pathText(path: string): string {
  const parts = parsePath(path);
  return parts ? `/${parts.join("/")}` : path.trim();
}

export function objectName(object: number): string {
  return OBJECTS[object] ?? `Object ${object}`;
}

/** A resource's name, such as Manufacturer for /3/0/0; empty when unknown. */
export function resourceName(object: number, resource: number): string {
  return OBJECT_RESOURCES[object]?.[resource] ?? (object >= 3200 ? (IPSO_RESOURCES[resource] ?? "") : "");
}

/** Whether a resource is one a server executes, such as Reboot (/3/0/4). */
export function isExecutable(object: number, resource: number): boolean {
  return (EXECUTABLE[object] ?? []).includes(resource) || (object >= 3200 && IPSO_EXECUTABLE.includes(resource));
}

/** The resources a server executes on an object, such as Reboot on Device: offered before Discover lists them. */
export function executablesOf(object: number): number[] {
  return EXECUTABLE[object] ?? [];
}

const FIRMWARE_STATES = ["Idle", "Downloading", "Downloaded", "Updating"];
const UPDATE_RESULTS = [
  "Initial",
  "Success",
  "Not enough flash",
  "Out of RAM",
  "Connection lost",
  "Integrity check failure",
  "Unsupported package type",
  "Invalid URI",
  "Update failed",
  "Unsupported protocol",
];
const BINDINGS: Record<string, string> = { U: "UDP", T: "TCP", S: "SMS", N: "Non-IP", Q: "queue mode" };

/** What a value means, said beside it: a firmware state's name, a time as a date. Empty when it says itself. */
export function meaning(path: string, value: string): string {
  const parts = parsePath(path);
  if (!parts || parts.length < 3) return "";
  const [object, , resource] = parts;
  const number = Number(value);
  if (object === 5 && resource === 3) return FIRMWARE_STATES[number] ?? "";
  if (object === 5 && resource === 5) return UPDATE_RESULTS[number] ?? "";
  if (object === 5 && resource === 9) return ["pull", "push", "pull and push"][number] ?? "";
  if ((object === 3 && resource === 13) || (object === 6 && resource === 5)) {
    if (!/^\d{9,10}$/.test(value.trim())) return "";
    return new Date(number * 1000).toISOString().replace("T", " ").replace(/\.000Z$/, " UTC");
  }
  if ((object === 1 && resource === 7) || (object === 3 && resource === 16)) {
    return [...value.trim()]
      .map((letter) => BINDINGS[letter.toUpperCase()])
      .filter(Boolean)
      .join(", ");
  }
  return "";
}

/** A word of the engine's line: in double quotes, its backslashes and quotes escaped, when it has a space, a quote or a backslash. */
export function word(text: string): string {
  return /[\s"\\]/.test(text) ? `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : text;
}

/** The formats a read can ask for, by the engine's names; empty for the tab's own. */
export const READ_FORMATS: [string, string][] = [
  ["", "The tab's format"],
  ["tlv", "TLV"],
  ["senml", "SenML JSON"],
  ["senml-cbor", "SenML CBOR"],
  ["cbor", "CBOR (one resource)"],
  ["text", "Text (one resource)"],
];

/** A server's request of one device, as the line that asks it; or why it cannot. */
export type Ask =
  | { what: "read"; path: string; format?: string }
  | { what: "observe" | "cancel" | "discover" | "delete"; path: string }
  | { what: "write"; path: string; value: string }
  | { what: "execute"; path: string; args?: string }
  | { what: "attributes"; path: string; query: string }
  | { what: "firmware"; file: string }
  | { what: "firmware-uri"; uri: string };

export function askLine(location: string, ask: Ask): { line: string; problem: string } {
  const fail = (problem: string) => ({ line: "", problem });
  if (!location) return fail("Choose a device first.");
  if (ask.what === "firmware") {
    const file = ask.file.trim();
    return file ? { line: `firmware ${location} ${word(file)}`, problem: "" } : fail("Choose the firmware's file first.");
  }
  if (ask.what === "firmware-uri") {
    const uri = ask.uri.trim();
    return /^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(uri)
      ? { line: `firmware ${location} uri ${uri}`, problem: "" }
      : fail("The address is a URI, such as coap://192.168.1.10/fw.bin.");
  }
  const parts = parsePath(ask.path);
  if (!parts) return fail(`${ask.path.trim() || "The path"} is not an LwM2M path, such as /3/0 or /3303/0/5700.`);
  const path = `/${parts.join("/")}`;
  switch (ask.what) {
    case "read":
      return { line: `read ${location} ${path}${ask.format ? ` -f ${ask.format}` : ""}`, problem: "" };
    case "write":
      if (parts.length < 3) return fail("A write is of one resource, such as /3311/0/5850.");
      if (ask.value === "") return fail("Type the value to write.");
      return { line: `write ${location} ${path} ${ask.value}`, problem: "" };
    case "execute":
      if (parts.length < 3) return fail("Execute takes one resource, such as /3/0/4.");
      return { line: `execute ${location} ${path}${ask.args?.trim() ? ` ${ask.args.trim()}` : ""}`, problem: "" };
    case "attributes": {
      const query = ask.query.trim().replace(/^\?/, "");
      if (!/^[a-z]+(=[^&\s]*)?(&[a-z]+(=[^&\s]*)?)*$/i.test(query)) {
        return fail("Attributes are written as pmin=2&pmax=10.");
      }
      return { line: `attributes ${location} ${path} ${query}`, problem: "" };
    }
    default:
      return { line: `${ask.what} ${location} ${path}`, problem: "" };
  }
}

/** A device's command, as the line that does it: set a resource, so its observers are told. */
export function setLine(path: string, value: string): { line: string; problem: string } {
  const parts = parsePath(path);
  if (!parts || parts.length !== 3) return { line: "", problem: "Set takes one resource, such as /3303/0/5700." };
  return { line: `set /${parts.join("/")} ${value}`, problem: "" };
}

/** Resource paths in the order a person reads them: by object, instance, resource, as numbers. */
export function byPath(a: string, b: string): number {
  const left = parsePath(a) ?? [];
  const right = parsePath(b) ?? [];
  for (let at = 0; at < Math.max(left.length, right.length); at++) {
    const difference = (left[at] ?? -1) - (right[at] ?? -1);
    if (difference !== 0) return difference;
  }
  return 0;
}

/** An object instance's resources, from what is known of them: values read, paths discovered, and the ones a server executes. */
export function resourcesOf(instance: string, known: string[]): string[] {
  const parts = parsePath(instance);
  if (!parts || parts.length !== 2) return [];
  const prefix = `/${parts.join("/")}/`;
  const found = new Set(
    known
      .filter((path) => path.startsWith(prefix))
      .map((path) => path.split("/").slice(0, 4).join("/"))
      .filter((path) => parsePath(path)?.length === 3),
  );
  for (const resource of executablesOf(parts[0])) found.add(`${prefix}${resource}`);
  return [...found].sort(byPath);
}
