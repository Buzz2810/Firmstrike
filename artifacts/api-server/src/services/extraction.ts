import { mkdir, readdir, stat, writeFile, readFile } from "node:fs/promises";
import path from "node:path";
import { commandExists, runCommand } from "./shell.js";

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
    const rel = path.relative(root, full).replace(/\\/g, "/");

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
        // Invalid gzip at this offset.
      }
    }
  }

  return count;
}

function detectArchitectureFromBuffer(buf: Buffer): string {
  if (buf.length < 20) return "UNKNOWN";

  if (
    buf[0] !== 0x7f ||
    buf[1] !== 0x45 ||
    buf[2] !== 0x4c ||
    buf[3] !== 0x46
  ) {
    return "UNKNOWN";
  }

  const littleEndian = buf[5] === 1;

  const machine = littleEndian
    ? buf.readUInt16LE(18)
    : buf.readUInt16BE(18);

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

async function detectArchitectureFromFiles(
  extractPath: string,
  files: ExtractedFileInfo[],
): Promise<string> {
  for (const file of files) {
    try {
      const fullPath = path.join(
        extractPath,
        file.path.replace(/^\/+/, ""),
      );

      const buf = await readFile(fullPath);
      const architecture = detectArchitectureFromBuffer(buf);

      if (architecture !== "UNKNOWN") {
        return architecture;
      }
    } catch {
      // Ignore unreadable files.
    }
  }

  return "UNKNOWN";
}

function detectVendor(
  stringsOutput: string,
  files: ExtractedFileInfo[],
): string | null {
  const haystack = `
${stringsOutput}
${files.map((f) => f.path).join("\n")}
`.toLowerCase();

  const vendors: Array<[string, RegExp]> = [
    ["TP-Link", /\btp[-_ ]?link\b/i],
    ["Netgear", /\bnetgear\b/i],
    ["D-Link", /\bd[-_ ]?link\b/i],
    ["ASUS", /\basus\b/i],
    ["Linksys", /\blinksys\b/i],
    ["Belkin", /\bbelkin\b/i],
    ["Zyxel", /\bzyxel\b/i],
    ["Ubiquiti", /\bubiquiti\b/i],
    ["MikroTik", /\bmikrotik\b/i],
    ["Huawei", /\bhuawei\b/i],
    ["Hikvision", /\bhikvision\b/i],
    ["Dahua", /\bdahua\b/i],
    ["Xiaomi", /\bxiaomi\b/i],
    ["Realtek", /\brealtek\b/i],
    ["Broadcom", /\bbroadcom\b/i],
    ["MediaTek", /\bmediatek\b/i],
    ["Qualcomm", /\bqualcomm\b/i],
    ["Marvell", /\bmarvell\b/i],
    ["Samsung", /\bsamsung\b/i],
    ["Synology", /\bsynology\b/i],
    ["QNAP", /\bqnap\b/i],
  ];

  for (const [vendor, pattern] of vendors) {
    if (pattern.test(haystack)) {
      return vendor;
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
  const { copyFile } = await import("node:fs/promises");

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

      await writeFile(
        path.join(extractPath, "_strings_dump.txt"),
        stringsOutput,
      );
    } catch {
      stringsOutput = "";
    }
  }

  const files: ExtractedFileInfo[] = [];

  await walkDir(extractPath, extractPath, files);

  let architecture = await detectArchitectureFromFiles(
    extractPath,
    files,
  );

  if (architecture === "UNKNOWN") {
    const firmwareBuffer = await readFile(firmwarePath);
    architecture = detectArchitectureFromBuffer(firmwareBuffer);
  }

  const vendor = detectVendor(stringsOutput, files);
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