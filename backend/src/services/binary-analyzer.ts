import path from "node:path";
import { commandExists, runCommand } from "./shell.js";

export type BinaryAnalysisResult = {
  firmwareId: number;
  filePath: string;
  strings: string[];
  urls: string[];
  credentials: string[];
  debugPaths: string[];
  iotBinaries: string[];
};

const IOT_SIGNATURES = ["busybox", "httpd", "telnetd", "dropbear", "udhcpc", "dnsmasq", "lighttpd", "boa", "uhttpd"];
const URL_REGEX = /https?:\/\/[^\s"'<>]+/gi;
const CRED_REGEX = /(?:admin|root|guest):[^\s"'<>]{2,}/gi;
const DEBUG_PATH_REGEX = /\/(?:var\/log|tmp\/debug|home\/developer)[^\s"'<>]*/gi;

export async function analyzeBinary(
  firmwareId: number,
  targetPath: string,
): Promise<BinaryAnalysisResult> {
  const strings: string[] = [];
  const urls = new Set<string>();
  const credentials = new Set<string>();
  const debugPaths = new Set<string>();
  const iotBinaries = new Set<string>();

  if (await commandExists("strings")) {
    try {
      const { stdout } = await runCommand("strings", ["-a", targetPath], { timeoutMs: 120_000 });
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.length < 3 || trimmed.length > 500) continue;
        strings.push(trimmed);

        for (const m of trimmed.matchAll(URL_REGEX)) urls.add(m[0]);
        for (const m of trimmed.matchAll(CRED_REGEX)) credentials.add(m[0]);
        for (const m of trimmed.matchAll(DEBUG_PATH_REGEX)) debugPaths.add(m[0]);

        const lower = trimmed.toLowerCase();
        for (const sig of IOT_SIGNATURES) {
          if (lower.includes(sig)) iotBinaries.add(sig);
        }
      }
    } catch {
      // empty result
    }
  }

  return {
    firmwareId,
    filePath: path.basename(targetPath),
    strings: strings.slice(0, 200),
    urls: [...urls].slice(0, 50),
    credentials: [...credentials].slice(0, 30),
    debugPaths: [...debugPaths].slice(0, 30),
    iotBinaries: [...iotBinaries],
  };
}

export function pickBinaryTarget(extractPath: string, files: string[]): string | null {
  const candidates = files.filter((f) =>
    f.endsWith(".bin") || f.includes("httpd") || f.includes("busybox") || !f.includes("."),
  );
  if (candidates.length === 0) return path.join(extractPath, "firmware.bin");
  const rel = candidates[0].replace(/^\//, "");
  return path.join(extractPath, rel);
}
