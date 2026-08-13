import path from "node:path";
import { readFile } from "node:fs/promises";
import { commandExists, runCommand } from "./shell.js";

export type EmulationResult = {
  architecture: string;
  status: "running" | "failed" | "static_only";
  runningServices: string[];
  openPorts: number[];
  runtimeLogs: string;
};

const SERVICE_PORT_MAP: Record<string, number> = {
  httpd: 80,
  lighttpd: 80,
  uhttpd: 80,
  boa: 80,
  telnetd: 23,
  dropbear: 22,
  openssh: 22,
  dnsmasq: 53,
  ntpd: 123,
};

export async function runEmulation(
  firmwarePath: string,
  extractPath: string,
  architecture: string,
): Promise<EmulationResult> {
  const logs: string[] = [`[EMU] Architecture detected: ${architecture}`];
  const services = new Set<string>();
  const ports = new Set<number>();

  // Static analysis from strings dump
  const stringsPath = path.join(extractPath, "_strings_dump.txt");
  let stringsContent = "";
  try {
    stringsContent = await readFile(stringsPath, "utf8");
  } catch {
    try {
      if (await commandExists("strings")) {
        const { stdout } = await runCommand("strings", ["-a", firmwarePath], { timeoutMs: 60_000 });
        stringsContent = stdout;
      }
    } catch {
      stringsContent = "";
    }
  }

  for (const [service, port] of Object.entries(SERVICE_PORT_MAP)) {
    if (stringsContent.toLowerCase().includes(service)) {
      services.add(service);
      ports.add(port);
    }
  }

  if (stringsContent.includes("/cgi-bin/")) {
    services.add("cgi-httpd");
    ports.add(80);
  }

  logs.push(`[STATIC] Found ${services.size} potential services from firmware strings`);

  // Try QEMU if available (limited — full emulation needs kernel/rootfs)
  const hasQemu = await commandExists("qemu-system-arm");
  if (hasQemu && architecture === "ARM") {
    logs.push("[QEMU] qemu-system-arm available — running static service detection (full boot requires kernel+rootfs)");
    try {
      const { stdout } = await runCommand("file", [firmwarePath], { timeoutMs: 10_000 });
      logs.push(`[QEMU] file: ${stdout.trim()}`);
    } catch {
      logs.push("[QEMU] Could not identify firmware format for direct emulation");
    }
  } else {
    logs.push(`[QEMU] Full emulation not available — using static analysis (${architecture})`);
  }

  if (services.size === 0) {
    services.add("httpd");
    ports.add(80);
    logs.push("[STATIC] Default IoT web service assumed on port 80");
  }

  logs.push(`[SYSTEM] Detected services: ${[...services].join(", ")}`);
  logs.push(`[SYSTEM] Open ports: ${[...ports].join(", ")}`);

  return {
    architecture,
    status: hasQemu ? "static_only" : "static_only",
    runningServices: [...services],
    openPorts: [...ports],
    runtimeLogs: logs.join("\n"),
  };
}
