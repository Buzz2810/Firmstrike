import { readFile } from "node:fs/promises";
import path from "node:path";

export type SecretFinding = {
  type: string;
  value: string;
  file: string;
  line: number;
  severity: "critical" | "high" | "medium" | "low";
};

export type DangerousFunctionFinding = {
  name: string;
  file: string;
  line: number;
  risk: "critical" | "high" | "medium" | "low";
  description: string;
};

export type VulnerabilityFinding = {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  affectedFile: string;
  description: string;
  recommendation: string;
  cvssScore: number;
};

const SECRET_PATTERNS: Array<{ type: string; regex: RegExp; severity: SecretFinding["severity"] }> = [
  { type: "password", regex: /(?:password|passwd|pwd)\s*[=:]\s*['"]?([^\s'";]{4,})/gi, severity: "critical" },
  { type: "api_key", regex: /(?:api[_-]?key|apikey)\s*[=:]\s*['"]?([^\s'";]{8,})/gi, severity: "critical" },
  { type: "token", regex: /(?:token|bearer)\s*[=:]\s*['"]?([^\s'";]{8,})/gi, severity: "high" },
  { type: "secret", regex: /(?:secret|SECRET)\s*[=:]\s*['"]?([^\s'";]{6,})/gi, severity: "critical" },
  { type: "private_key", regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, severity: "critical" },
  { type: "credential", regex: /(?:admin|root):([^\s'";]{3,})/gi, severity: "critical" },
];

const DANGEROUS_PATTERNS: Array<{ name: string; regex: RegExp; risk: DangerousFunctionFinding["risk"]; description: string }> = [
  { name: "system()", regex: /\bsystem\s*\(/g, risk: "critical", description: "Direct system() call — potential command injection" },
  { name: "popen()", regex: /\bpopen\s*\(/g, risk: "high", description: "Pipe open with potential command injection" },
  { name: "exec()", regex: /\bexec(?:ve|vp|v|l)?\s*\(/g, risk: "high", description: "Execute with potentially user-controlled arguments" },
  { name: "strcpy()", regex: /\bstrcpy\s*\(/g, risk: "high", description: "Unsafe string copy — buffer overflow risk" },
  { name: "gets()", regex: /\bgets\s*\(/g, risk: "critical", description: "Unsafe input with no bounds checking" },
  { name: "sprintf()", regex: /\bsprintf\s*\(/g, risk: "medium", description: "Unbounded string formatting" },
];

const WEB_PANEL_PATTERNS = [
  { regex: /\/cgi-bin\/[a-z0-9_-]+/gi, type: "Exposed CGI endpoint" },
  { regex: /\/admin(?:\/|$)/gi, type: "Admin panel path" },
  { regex: /\/debug(?:\/|$)/gi, type: "Debug endpoint" },
  { regex: /\/backup(?:\/|$)/gi, type: "Backup directory" },
];

const TEXT_EXTENSIONS = new Set([
  ".conf", ".cfg", ".ini", ".xml", ".json", ".js", ".sh", ".cgi", ".html", ".htm",
  ".txt", ".passwd", ".properties", ".env", ".yaml", ".yml",
]);

function redactValue(value: string): string {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}****${value.slice(-2)}`;
}

function isTextFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return TEXT_EXTENSIONS.has(ext) || !ext || filePath.includes("passwd") || filePath.includes("config");
}

async function scanFileContent(
  filePath: string,
  relPath: string,
  secrets: SecretFinding[],
  dangerous: DangerousFunctionFinding[],
  vulns: VulnerabilityFinding[],
): Promise<void> {
  let content: string;
  try {
    const buf = await readFile(filePath);
    if (buf.includes(0)) return;
    content = buf.toString("utf8");
  } catch {
    return;
  }

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const pat of SECRET_PATTERNS) {
      pat.regex.lastIndex = 0;
      let match;
      while ((match = pat.regex.exec(line)) !== null) {
        const raw = match[1] ?? match[0];
        secrets.push({
          type: pat.type,
          value: redactValue(raw),
          file: relPath,
          line: lineNum,
          severity: pat.severity,
        });
      }
    }

    for (const pat of DANGEROUS_PATTERNS) {
      pat.regex.lastIndex = 0;
      if (pat.regex.test(line)) {
        dangerous.push({
          name: pat.name,
          file: relPath,
          line: lineNum,
          risk: pat.risk,
          description: pat.description,
        });
      }
    }
  }

  if (/\btelnetd\b/i.test(content)) {
    vulns.push({
      type: "Insecure Service",
      severity: "high",
      affectedFile: relPath,
      description: "Telnet daemon reference found — unencrypted remote access",
      recommendation: "Disable telnet and use SSH with key-based authentication",
      cvssScore: 7.5,
    });
  }

  if (/DEBUG\s*=\s*1|debug\s*=\s*true/i.test(content)) {
    vulns.push({
      type: "Debug Interface Exposed",
      severity: "medium",
      affectedFile: relPath,
      description: "Debug mode enabled in configuration",
      recommendation: "Disable debug interfaces in production firmware",
      cvssScore: 5.0,
    });
  }

  for (const panel of WEB_PANEL_PATTERNS) {
    panel.regex.lastIndex = 0;
    if (panel.regex.test(content)) {
      vulns.push({
        type: "Web Panel Exposure",
        severity: "medium",
        affectedFile: relPath,
        description: `${panel.type} detected in firmware files`,
        recommendation: "Restrict access to administrative endpoints via authentication and firewall",
        cvssScore: 5.5,
      });
    }
  }
}

export async function analyzeStaticFiles(
  extractPath: string,
  filePaths: string[],
): Promise<{
  secrets: SecretFinding[];
  dangerous: DangerousFunctionFinding[];
  vulnerabilities: VulnerabilityFinding[];
}> {
  const secrets: SecretFinding[] = [];
  const dangerous: DangerousFunctionFinding[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  for (const rel of filePaths) {
    const full = path.join(extractPath, rel.replace(/^\//, ""));
    if (!isTextFile(rel)) continue;
    await scanFileContent(full, rel, secrets, dangerous, vulnerabilities);
  }

  // Also scan strings dump if present
  const stringsDump = path.join(extractPath, "_strings_dump.txt");
  try {
    await scanFileContent(stringsDump, "/_strings_dump.txt", secrets, dangerous, vulnerabilities);
  } catch {
    // optional
  }

  return { secrets, dangerous, vulnerabilities };
}
