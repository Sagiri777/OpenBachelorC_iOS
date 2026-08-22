import fs from "node:fs";

const path = process.argv[2];
if (!path) throw new Error("usage: node patch-frida-exceptor.mjs PATH");

// Frida Gum 17.9.1 arm64, gum_exceptor_backend_attach(): do not use
// Interceptor to replace libc signal()/sigaction(). The backend has already
// installed its handlers through the original sigaction implementation.
const patches = [
  // gum_exceptor_reset(): branch directly to the return path instead of
  // constructing GumExceptorBackend and taking over process signals.
  { offset: 0x3627c, expected: "c8000037", replacement: "06000014" },
  { offset: 0x4ecb0, expected: "6f010094", replacement: "1f2003d5" },
  { offset: 0x4ecc0, expected: "6b010094", replacement: "1f2003d5" },
];

const payloadUuid = Buffer.from("4f424733455843338000000000000001", "hex");

const image = fs.readFileSync(path);
for (const patch of patches) {
  const expected = Buffer.from(patch.expected, "hex");
  const actual = image.subarray(patch.offset, patch.offset + expected.length);
  if (!actual.equals(expected)) {
    throw new Error(
      `unexpected Frida bytes at 0x${patch.offset.toString(16)}: ` +
      `${actual.toString("hex")} (expected ${patch.expected})`,
    );
  }
}
for (const patch of patches) {
  Buffer.from(patch.replacement, "hex").copy(image, patch.offset);
}

const magic = image.readUInt32LE(0);
if (magic !== 0xfeedfacf) throw new Error("Frida payload is not a little-endian Mach-O 64 image");
const commandCount = image.readUInt32LE(16);
let commandOffset = 32;
let uuidUpdated = false;
for (let index = 0; index < commandCount; index += 1) {
  if (commandOffset + 8 > image.length) throw new Error("truncated Mach-O load command");
  const command = image.readUInt32LE(commandOffset);
  const commandSize = image.readUInt32LE(commandOffset + 4);
  if (commandSize < 8 || commandOffset + commandSize > image.length)
    throw new Error("invalid Mach-O load command size");
  if (command === 0x1b) {
    if (commandSize < 24) throw new Error("invalid LC_UUID command");
    payloadUuid.copy(image, commandOffset + 8);
    uuidUpdated = true;
    break;
  }
  commandOffset += commandSize;
}
if (!uuidUpdated) throw new Error("Frida payload has no LC_UUID command");
fs.writeFileSync(path, image);

console.log("patched Frida Gum Exceptor: 3 sites; payload UUID: 4F424733-4558-4333-8000-000000000001");
