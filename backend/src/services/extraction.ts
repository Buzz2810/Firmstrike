import {
  mkdir,
  readdir,
  stat,
  writeFile,
  readFile,
  copyFile,
} from "node:fs/promises";

import path from "node:path";

import { unzipSync } from "fflate";

import {
  commandExists,
  runCommand,
} from "./shell.js";
export type ExtractedFileInfo = {
  path: string;
  type: string;
  size: number;
  permissions: string;
  isSuspicious: boolean;
};

export type ExtractionResult = {
  extractPath: string;
  files: ExtractedFileInfo[];
  architecture: string;
  vendor: string | null;
  version: string | null;
  components: string[];
};

const IOT_BINARIES = [
  "busybox",
  "httpd",
  "telnetd",
  "dropbear",
  "udhcpc",
  "dnsmasq",
  "lighttpd",
  "boa",
];

async function walkDir(
  dir: string,
  root: string,
  files: ExtractedFileInfo[],
): Promise<void> {
  let entries;

  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    const rel = path
  .relative(root, full)
  .replace(/\\/g, "/");
    if (entry.isDirectory()) {
      if (entry.name === ".git") continue;
      await walkDir(full, root, files);
      continue;
    }

    let info;

    try {
      info = await stat(full);
    } catch {
      continue;
    }

    const lower = entry.name.toLowerCase();

    const isElf =
      lower.endsWith(".so") ||
      lower.endsWith(".bin") ||
      !lower.includes(".");

    const isSuspicious =
      IOT_BINARIES.some((b) => lower.includes(b)) ||
      lower.includes("cgi") ||
      lower.includes("passwd") ||
      lower.includes("config");

    let type = "file";

    if (lower.endsWith(".cgi") || lower.endsWith(".sh")) {
      type = "script";
    } else if (lower.endsWith(".so")) {
      type = "Shared library";
    } else if (
      lower.endsWith(".conf") ||
      lower.includes("config") ||
      lower === "passwd"
    ) {
      type = "Configuration";
    } else if (isElf) {
      type = "ELF binary";
    }

    files.push({
      path: `/${rel}`,
      type,
      size: info.size,
      permissions: info.mode.toString(8).slice(-4),
      isSuspicious,
    });
  }
}

async function extractGzipChunks(
  firmwarePath: string,
  extractPath: string,
): Promise<number> {
  const { gunzipSync } = await import("node:zlib");
  const buf = await readFile(firmwarePath);

  let count = 0;

  for (let i = 0; i < buf.length - 2; i++) {
    if (buf[i] === 0x1f && buf[i + 1] === 0x8b) {
      try {
        const decompressed = gunzipSync(
          buf.subarray(i, Math.min(i + 1024 * 1024, buf.length)),
        );

        await writeFile(
          path.join(extractPath, `extracted_${count}.bin`),
          decompressed,
        );

        count++;
      } catch {
        
      }
    }
  }

  return count;
}

function architectureFromElfMachine(
  machine: number,
): string {
  switch (machine) {
    case 3:
      return "x86";

    case 8:
      return "MIPS";

    case 20:
      return "PowerPC";

    case 21:
      return "PowerPC64";

    case 40:
      return "ARM";

    case 42:
      return "SuperH";

    case 62:
      return "x86_64";

    case 183:
      return "ARM64";

    case 243:
      return "RISC-V";

    default:
      return `ELF (${machine})`;
  }
}

function detectElfArchitecture(
  buf: Buffer,
  offset = 0,
): string | null {
  if (offset + 20 > buf.length) {
    return null;
  }

  if (
    buf[offset] !== 0x7f ||
    buf[offset + 1] !== 0x45 ||
    buf[offset + 2] !== 0x4c ||
    buf[offset + 3] !== 0x46
  ) {
    return null;
  }

  const elfClass = buf[offset + 4];
  const endian = buf[offset + 5];

  if (
    (elfClass !== 1 && elfClass !== 2) ||
    (endian !== 1 && endian !== 2)
  ) {
    return null;
  }

  const machine =
    endian === 1
      ? buf.readUInt16LE(offset + 18)
      : buf.readUInt16BE(offset + 18);

  return architectureFromElfMachine(machine);
}

function detectArchitectureFromFilename(fileName: string): string | null {
  const normalized = fileName.toLowerCase();

  const patterns: Array<[RegExp, string]> = [
    [/\b(?:x86[_-]?64|amd64|x64)\b/, "x86_64"],
    [/\b(?:x86|i386|i686)\b/, "x86"],
    [/\b(?:mips(?:el|64el)?|mips64|mipsel)\b/, "MIPS"],
    [/\b(?:arm64|aarch64|armv8|armv8l)\b/, "ARM64"],
    [/\b(?:armv7|armv6|armv5|armv4|arm)\b/, "ARM"],
    [/\b(?:powerpc|ppc64|ppc)\b/, "PowerPC"],
    [/\b(?:risc[-_ ]?v|riscv64|riscv)\b/, "RISC-V"],
    [/\b(?:superh|sh4|sh3)\b/, "SuperH"],
  ];

  for (const [pattern, arch] of patterns) {
    if (pattern.test(normalized)) {
      return arch;
    }
  }

  return null;
}

function detectArchitectureFromStrings(stringsOutput: string): string | null {
  const haystack = stringsOutput.toLowerCase();

  const patterns: Array<[RegExp, string]> = [
    [/\b(?:x86[_-]?64|amd64|x64)\b/, "x86_64"],
    [/\b(?:x86|i386|i686)\b/, "x86"],
    [/\b(?:mips(?:el|64el)?|mips64|mipsel)\b/, "MIPS"],
    [/\b(?:arm64|aarch64|armv8|armv8l)\b/, "ARM64"],
    [/\b(?:armv7|armv6|armv5|armv4|arm)\b/, "ARM"],
    [/\b(?:powerpc|ppc64|ppc)\b/, "PowerPC"],
    [/\b(?:risc[-_ ]?v|riscv64|riscv)\b/, "RISC-V"],
    [/\b(?:superh|sh4|sh3)\b/, "SuperH"],
  ];

  for (const [pattern, arch] of patterns) {
    if (pattern.test(haystack)) {
      return arch;
    }
  }

  return null;
}
async function detectArchitectureFromFiles(
  extractPath: string,
  files: ExtractedFileInfo[],
): Promise<string> {
  for (const file of files) {
    const fullPath = path.join(
      extractPath,
      file.path.replace(/^[/\\]/, ""),
    );

    try {
      const buf = await readFile(fullPath);

      const architecture =
        detectElfArchitecture(buf) ??
        detectEmbeddedElfArchitecture(buf) ??
        detectUImageArchitecture(buf) ??
        detectPeArchitecture(buf);

      if (architecture) {
        return architecture;
      }
    } catch {
      // Ignore files that cannot be read.
    }
  }

  return "UNKNOWN";
}
function detectVendor(
  stringsOutput: string,
  files: ExtractedFileInfo[],
  firmwarePath: string,
): string | null {
  const fileName =
    path.basename(firmwarePath).toLowerCase();

  const filePaths = files
    .map((f) => f.path)
    .join("\n")
    .toLowerCase();

  const haystack = `
${stringsOutput}
${fileName}
${filePaths}
`.toLowerCase();

  const vendorRules: Array<{
    vendor: string;
    patterns: RegExp[];
  }> = [
    {
      vendor: "TP-Link",
      patterns: [
        /\btp[-_ ]?link\b/i,
        /\barcher[-_ ]?[a-z0-9-]+\b/i,
        /\btl-(?:wr|mr|er|sg|sf|r)[a-z0-9-]*\b/i,
        /\bomada\b/i,
      ],
    },

    {
      vendor: "D-Link",
      patterns: [
        /\bd[-_ ]?link\b/i,
        /\bdir[-_ ]?[a-z0-9-]+\b/i,
        /\bdsl[-_ ]?[a-z0-9-]+\b/i,
      ],
    },

    {
      vendor: "Netgear",
      patterns: [
        /\bnetgear\b/i,
        /\bnighthawk\b/i,
        /\br\d{3,4}\b/i,
      ],
    },

    {
      vendor: "ASUS",
      patterns: [
        /\basustek\b/i,
        /\basus\b/i,
        /\brog[-_ ]?router\b/i,
      ],
    },

    {
      vendor: "Linksys",
      patterns: [
        /\blinksys\b/i,
        /\bvelop\b/i,
      ],
    },

    {
      vendor: "Ubiquiti",
      patterns: [
        /\bubiquiti\b/i,
        /\bunifi\b/i,
        /\bedgerouter\b/i,
      ],
    },

    {
      vendor: "MikroTik",
      patterns: [
        /\bmikrotik\b/i,
        /\brouteros\b/i,
      ],
    },

    {
      vendor: "Zyxel",
      patterns: [
        /\bzyxel\b/i,
      ],
    },

    {
      vendor: "Huawei",
      patterns: [
        /\bhuawei\b/i,
        /\bhg\d{2,4}\b/i,
      ],
    },

    {
  vendor: "Netgear",
  patterns: [
    /\bnetgear\b/i,
    /\bnighthawk\b/i,
  ],
},

    {
      vendor: "Dahua",
      patterns: [
        /\bdahua\b/i,
      ],
    },

    {
      vendor: "Xiaomi",
      patterns: [
        /\bxiaomi\b/i,
        /\bmi[-_ ]?router\b/i,
      ],
    },

    {
      vendor: "Realtek",
      patterns: [
        /\brealtek\b/i,
        /\brtl\d{4,6}\b/i,
      ],
    },

    {
      vendor: "Broadcom",
      patterns: [
        /\bbroadcom\b/i,
        /\bbcm\d+\b/i,
      ],
    },

    {
      vendor: "MediaTek",
      patterns: [
        /\bmediatek\b/i,
        /\bmt\d{4,6}\b/i,
      ],
    },

    {
      vendor: "Qualcomm",
      patterns: [
        /\bqualcomm\b/i,
        /\batheros\b/i,
        /\bipq\d+\b/i,
      ],
    },

    {
      vendor: "Marvell",
      patterns: [
        /\bmarvell\b/i,
      ],
    },

    {
      vendor: "Synology",
      patterns: [
        /\bsynology\b/i,
      ],
    },

    {
      vendor: "QNAP",
      patterns: [
        /\bqnap\b/i,
      ],
    },

    {
      vendor: "OpenWrt",
      patterns: [
        /\bopenwrt\b/i,
        /\bopenwrt[-_ ]?\d+\.\d+/i,
      ],
    },
  ];

  for (const rule of vendorRules) {
    if (
      rule.patterns.some(
        (pattern) =>
          pattern.test(haystack),
      )
    ) {
      return rule.vendor;
    }
  }

  return null;
}

function detectVersion(stringsOutput: string): string | null {
  const patterns = [
    /\bfirmware[\s_-]?(?:version|ver|v)?\s*[:=]?\s*v?(\d+(?:\.\d+){1,4}(?:[-_.][A-Za-z0-9]+)*)/i,
    /\bversion\s*[:=]\s*v?(\d+(?:\.\d+){1,4}(?:[-_.][A-Za-z0-9]+)*)/i,
    /\bver(?:sion)?\s*[:=]\s*v?(\d+(?:\.\d+){1,4}(?:[-_.][A-Za-z0-9]+)*)/i,
    /\bv(\d+\.\d+(?:\.\d+){0,3})\b/i,
    /\bFW[_ -]?V?(\d+\.\d+(?:\.\d+){0,3})\b/i,
  ];

  for (const pattern of patterns) {
    const match = stringsOutput.match(pattern);

    if (match?.[1]) {
      return match[1];
    }
  }

  return null;
}

function detectComponents(
  files: ExtractedFileInfo[],
  stringsOutput: string,
): string[] {
  const found = new Set<string>();

  const haystack =
    `${files.map((f) => f.path).join(" ")} ${stringsOutput}`.toLowerCase();

  const patterns = [
    "openssl",
    "busybox",
    "openssh",
    "dropbear",
    "lighttpd",
    "boa",
    "uhttpd",
    "telnetd",
    "httpd",
    "libssl",
    "libcrypto",
    "zlib",
    "squashfs",
    "uboot",
  ];

  for (const p of patterns) {
    if (haystack.includes(p)) {
      found.add(p);
    }
  }

  const versionMatch = stringsOutput.match(
    /OpenSSL\s+[\d.]+[a-z]?/gi,
  );

  if (versionMatch) {
    versionMatch.forEach((v) => found.add(v));
  }

  return [...found];
}

export async function extractFirmware(
  firmwarePath: string,
  extractPath: string,
): Promise<ExtractionResult> {
  await mkdir(extractPath, { recursive: true });
const firmwareBuffer =
  await readFile(firmwarePath);

const format =
  detectFirmwareFormat(
    firmwareBuffer,
    path.basename(firmwarePath),
  );

console.log(
  "[Firmware Format]:",
  format,
);

if (format === "TRX") {
  await extractTrx(
    firmwarePath,
    extractPath,
  );
}

if (format === "ZIP") {
  await extractZip(
    firmwarePath,
    extractPath,
  );
}                                     

const hasBinwalk = await commandExists("binwalk");
  if (hasBinwalk) {
    try {
      await runCommand(
        "binwalk",
        ["-e", "-C", extractPath, "--run-as=root", firmwarePath],
        { timeoutMs: 300_000 },
      );
    } catch {
      // Fall through to built-in extraction.
    }
  }

  const rawCopy = path.join(extractPath, "firmware.bin");

  await copyFile(firmwarePath, rawCopy);
  await extractGzipChunks(firmwarePath, extractPath);

  let stringsOutput = "";

if (await commandExists("strings")) {
  try {
    const { stdout } = await runCommand(
      "strings",
      ["-a", firmwarePath],
      { timeoutMs: 60_000 },
    );

    stringsOutput = stdout;
  } catch {
    stringsOutput = "";
  }
}

if (!stringsOutput) {
  stringsOutput =
    extractAsciiStrings(firmwareBuffer);
}

await writeFile(
  path.join(
    extractPath,
    "_strings_dump.txt",
  ),
  stringsOutput,
);

  const files: ExtractedFileInfo[] = [];

  await walkDir(extractPath, extractPath, files);
let architecture = await detectArchitectureFromFiles(
  extractPath,
  files,
);

const filenameArchitecture =
  detectArchitectureFromFilename(
    path.basename(firmwarePath),
  );

if (architecture === "UNKNOWN") {
  architecture =
    detectArchitectureFromBuffer(
      firmwareBuffer,
    );
}

if (architecture === "UNKNOWN") {
  const stringArchitecture =
    detectArchitectureFromStrings(
      stringsOutput,
    );

  if (stringArchitecture) {
    architecture = stringArchitecture;
  }
}

if (
  architecture === "UNKNOWN" &&
  filenameArchitecture
) {
  architecture = filenameArchitecture;
}

  const vendor =
    detectVendor(stringsOutput, files, firmwarePath) ||
    null;
  const version = detectVersion(stringsOutput);
  const components = detectComponents(files, stringsOutput);

  console.log("[Firmware Detection]");
  console.log("Architecture:", architecture);
  console.log("Vendor:", vendor ?? "Unknown");
  console.log("Version:", version ?? "Unknown");

  return {
    extractPath,
    files,
    architecture,
    vendor,
    version,
    components,
  };
}
function detectEmbeddedElfArchitecture(
  buf: Buffer,
): string | null {
  const maxScan = buf.length;

  for (let i = 0; i < maxScan - 20; i++) {
    if (
      buf[i] === 0x7f &&
      buf[i + 1] === 0x45 &&
      buf[i + 2] === 0x4c &&
      buf[i + 3] === 0x46
    ) {
      const architecture = detectElfArchitecture(
        buf,
        i,
      );

      if (architecture) {
        return architecture;
      }
    }
  }

  return null;
}
function detectUImageArchitecture(
  buf: Buffer,
): string | null {
  const UIMAGE_MAGIC = 0x27051956;

  for (let i = 0; i <= buf.length - 64; i++) {
    const magic = buf.readUInt32BE(i);

    if (magic !== UIMAGE_MAGIC) {
      continue;
    }

    // uImage header:
    // +0  magic
    // +4  header CRC
    // +8  timestamp
    // +12 data size
    // +16 load address
    // +20 entry point
    // +24 data CRC
    // +28 operating system
    // +29 architecture
    // +30 image type
    // +31 compression

    const arch = buf[i + 29];

    switch (arch) {
      case 2:
        return "ARM";

      case 3:
        return "x86";

      case 5:
  return "MIPS";

case 6:
  return "MIPS64";

      case 7:
        return "PowerPC";

      case 8:
        return "S390";

      case 9:
        return "SuperH";

      case 10:
        return "SPARC";

      case 22:
        return "ARM64";

      case 24:
        return "x86_64";
    }
  }

  return null;
}
function detectPeArchitecture(
  buf: Buffer,
): string | null {
  for (let i = 0; i <= buf.length - 64; i++) {
    if (
      buf[i] !== 0x4d ||
      buf[i + 1] !== 0x5a
    ) {
      continue;
    }

    const peOffset = buf.readUInt32LE(i + 0x3c);

    if (
      peOffset < 0 ||
      i + peOffset + 6 > buf.length
    ) {
      continue;
    }

    const pe = i + peOffset;

    if (
      buf[pe] !== 0x50 ||
      buf[pe + 1] !== 0x45 ||
      buf[pe + 2] !== 0x00 ||
      buf[pe + 3] !== 0x00
    ) {
      continue;
    }

    const machine = buf.readUInt16LE(pe + 4);

    switch (machine) {
      case 0x014c:
        return "x86";

      case 0x8664:
        return "x86_64";

      case 0xaa64:
        return "ARM64";

      case 0x01c0:
        return "ARM";

      case 0x01c4:
        return "ARM";
    }
  }

  return null;
}
async function extractTrx(
  firmwarePath: string,
  extractPath: string,
): Promise<number> {
  const buf = await readFile(firmwarePath);

  if (buf.length < 28) {
    return 0;
  }

  const MAGIC = 0x30524448; // "HDR0"

  if (buf.readUInt32LE(0) !== MAGIC) {
    return 0;
  }

  const totalLength = buf.readUInt32LE(4);
  const imageLength =
  totalLength > 0 &&
  totalLength <= buf.length
    ? totalLength
    : buf.length;

  const offsets = [
    buf.readUInt32LE(16),
    buf.readUInt32LE(20),
    buf.readUInt32LE(24),
  ]
    .filter(
      (offset) =>
        offset > 0 &&
        offset < buf.length,
    )
    .sort((a, b) => a - b);

  let count = 0;

  for (let i = 0; i < offsets.length; i++) {
    const start = offsets[i];

    const end =
  offsets[i + 1] ?? imageLength;

    if (end <= start) {
      continue;
    }

    const payload = buf.subarray(

      start,
      end,
    );

    await writeFile(
      path.join(
        extractPath,
        `trx-part-${count}.bin`,
      ),
      payload,
    );

    count++;
  }

  return count;
}

function detectArchitectureFromBuffer(
  buf: Buffer,
): string {
  return (
    detectElfArchitecture(buf) ??
    detectEmbeddedElfArchitecture(buf) ??
    detectUImageArchitecture(buf) ??
    detectPeArchitecture(buf) ??
    "UNKNOWN"
  );
}
async function extractZip(
  firmwarePath: string,
  extractPath: string,
): Promise<number> {
  const buf = await readFile(firmwarePath);

  // ZIP local file / empty archive / central directory signatures
  const isZip =
    buf.length >= 4 &&
    (
      buf.subarray(0, 4).equals(
        Buffer.from([0x50, 0x4b, 0x03, 0x04]),
      ) ||
      buf.subarray(0, 4).equals(
        Buffer.from([0x50, 0x4b, 0x05, 0x06]),
      ) ||
      buf.subarray(0, 4).equals(
        Buffer.from([0x50, 0x4b, 0x07, 0x08]),
      )
    );

  if (!isZip) {
    return 0;
  }

  const entries = unzipSync(
    new Uint8Array(buf),
  );

  let count = 0;

  for (const [entryName, data] of Object.entries(
    entries,
  )) {
    if (!data || data.length === 0) {
      continue;
    }

    // Prevent ZIP path traversal.
    const safeName = entryName
  .replace(/\\/g, "/")
  .replace(/^\/+/, "")
  .split("/")
  .filter(
    (part) =>
      part !== ".." &&
      part !== ".",
  )
  .join("/");

    if (!safeName) {
      continue;
    }

    const outputPath = path.join(
      extractPath,
      "zip",
      safeName,
    );

    await mkdir(
      path.dirname(outputPath),
      { recursive: true },
    );
    
    await writeFile(
      outputPath,
      Buffer.from(data),
    );

    count++;
  }

  return count;
}
function detectFirmwareFormat(
  buf: Buffer,
  fileName: string,
): string {
  const lower = fileName.toLowerCase();

  if (
  buf.length >= 4 &&
  (
    buf.subarray(0, 4).equals(
      Buffer.from([0x50, 0x4b, 0x03, 0x04]),
    ) ||
    buf.subarray(0, 4).equals(
      Buffer.from([0x50, 0x4b, 0x05, 0x06]),
    ) ||
    buf.subarray(0, 4).equals(
      Buffer.from([0x50, 0x4b, 0x07, 0x08]),
    )
  )
) {
  return "ZIP";
}

  if (
    buf.length >= 4 &&
    buf.readUInt32LE(0) === 0x30524448
  ) {
    return "TRX";
  }

  if (
    buf.length >= 4 &&
    buf.readUInt32BE(0) === 0x27051956
  ) {
    return "uImage";
  }

  if (
    buf.length >= 4 &&
    buf.readUInt32LE(0) === 0x73717368
  ) {
    return "SquashFS";
  }

  if (
    buf.length >= 4 &&
    buf.readUInt32BE(0) === 0x28cd3d45
  ) {
    return "CramFS";
  }

  if (
    buf.length >= 4 &&
    buf.subarray(0, 4).toString("ascii") === "UBI#"
  ) {
    return "UBI";
  }

  if (lower.endsWith(".chk")) {
    return "CHK";
  }

  if (lower.endsWith(".img")) {
    return "Disk/Filesystem Image";
  }

  if (lower.endsWith(".bin")) {
    return "Firmware Binary";
  }

  return "Unknown";
}
function extractAsciiStrings(
  buf: Buffer,
  minimumLength = 4,
): string {
  const result: string[] = [];
  let current = "";

  for (const byte of buf) {
    if (
      byte >= 0x20 &&
      byte <= 0x7e
    ) {
      current += String.fromCharCode(byte);

      if (current.length >= 500) {
        result.push(current);
        current = "";
      }
    } else {
      if (
        current.length >= minimumLength
      ) {
        result.push(current);
      }

      current = "";
    }
  }

  if (
    current.length >= minimumLength
  ) {
    result.push(current);
  }

  return result.join("\n");
}
