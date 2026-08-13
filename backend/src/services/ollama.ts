import { logger } from "../lib/logger.js";

const OLLAMA_BASE = process.env.OLLAMA_BASE_URL ?? "http://localhost:11434";
const OLLAMA_MODEL = process.env.OLLAMA_MODEL ?? "qwen3:8b";

export type AiReportContent = {
  summary: string;
  riskLevel: "critical" | "high" | "medium" | "low";
  keyFindings: string[];
  recommendations: string[];
  exploitProbability: number;
};

export type ScanContext = {
  firmwareName: string;
  architecture: string;
  vulnerabilities: Array<{ type: string; severity: string; description: string; file: string }>;
  secrets: Array<{ type: string; file: string; severity: string }>;
  dangerousFunctions: Array<{ name: string; file: string; risk: string }>;
  cveIds: string[];
  malwareFindings: Array<{ fileName: string; threatScore: number; result: string }>;
  components: string[];
};

function buildPrompt(ctx: ScanContext): string {
  return `You are a firmware security analyst. Analyze this IoT/router firmware scan and respond ONLY with valid JSON (no markdown, no thinking tags).

Firmware: ${ctx.firmwareName}
Architecture: ${ctx.architecture}
Components detected: ${ctx.components.join(", ") || "unknown"}

Vulnerabilities (${ctx.vulnerabilities.length}):
${ctx.vulnerabilities.slice(0, 15).map((v) => `- [${v.severity}] ${v.type}: ${v.description} (${v.file})`).join("\n")}

Hardcoded secrets (${ctx.secrets.length}):
${ctx.secrets.slice(0, 10).map((s) => `- [${s.severity}] ${s.type} in ${s.file}`).join("\n")}

Dangerous functions (${ctx.dangerousFunctions.length}):
${ctx.dangerousFunctions.slice(0, 10).map((d) => `- [${d.risk}] ${d.name} in ${d.file}`).join("\n")}

CVE matches: ${ctx.cveIds.join(", ") || "none"}

Malware indicators:
${ctx.malwareFindings.slice(0, 5).map((m) => `- ${m.fileName}: score ${m.threatScore} (${m.result})`).join("\n") || "none"}

Respond with this exact JSON structure:
{
  "summary": "2-4 sentence executive summary of the firmware security posture",
  "riskLevel": "critical|high|medium|low",
  "keyFindings": ["finding 1", "finding 2", "finding 3", "finding 4", "finding 5", "finding 6"],
  "recommendations": ["recommendation 1", "recommendation 2", "recommendation 3", "recommendation 4", "recommendation 5", "recommendation 6"],
  "exploitProbability": 0.0 to 1.0
}`;
}

function parseJsonResponse(text: string): AiReportContent | null {
  const cleaned = text
    .replace(/[\s\S]*?<\/think>/gi, "")
    .replace(/```json\s*/gi, "")
    .replace(/```\s*/g, "")
    .trim();

  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end === -1) return null;

  try {
    const parsed = JSON.parse(cleaned.slice(start, end + 1)) as AiReportContent;
    if (!parsed.summary || !parsed.riskLevel) return null;
    return {
      summary: parsed.summary,
      riskLevel: parsed.riskLevel,
      keyFindings: Array.isArray(parsed.keyFindings) ? parsed.keyFindings : [],
      recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
      exploitProbability: typeof parsed.exploitProbability === "number" ? parsed.exploitProbability : 0.5,
    };
  } catch {
    return null;
  }
}

function fallbackReport(ctx: ScanContext): AiReportContent {
  const critical = ctx.vulnerabilities.filter((v) => v.severity === "critical").length;
  const riskLevel = critical > 0 ? "critical" : ctx.vulnerabilities.length > 3 ? "high" : ctx.vulnerabilities.length > 0 ? "medium" : "low";

  return {
    summary: `Analysis of ${ctx.firmwareName} (${ctx.architecture}) found ${ctx.vulnerabilities.length} vulnerabilities, ${ctx.secrets.length} hardcoded secrets, and ${ctx.cveIds.length} CVE matches. The firmware requires security hardening before deployment.`,
    riskLevel,
    keyFindings: [
      ...ctx.vulnerabilities.slice(0, 3).map((v) => `${v.type}: ${v.description}`),
      ...ctx.secrets.slice(0, 2).map((s) => `Hardcoded ${s.type} found in ${s.file}`),
      ...ctx.dangerousFunctions.slice(0, 2).map((d) => `Dangerous function ${d.name} in ${d.file}`),
    ].slice(0, 6),
    recommendations: [
      "Remove all hardcoded credentials and implement secure credential storage",
      "Upgrade outdated libraries (OpenSSL, BusyBox) to patched versions",
      "Disable insecure services like Telnet and enforce SSH authentication",
      "Apply vendor firmware patches for matched CVEs",
      "Audit SUID binaries and dangerous function usage",
      "Conduct full incident response if malware indicators are confirmed",
    ],
    exploitProbability: riskLevel === "critical" ? 0.85 : riskLevel === "high" ? 0.65 : 0.35,
  };
}

export async function generateAiReport(ctx: ScanContext): Promise<AiReportContent> {
  const prompt = buildPrompt(ctx);

  try {
    const response = await fetch(`${OLLAMA_BASE}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        prompt,
        stream: false,
        options: { temperature: 0.3, num_predict: 2048 },
      }),
      signal: AbortSignal.timeout(180_000),
    });

    if (!response.ok) {
      logger.warn({ status: response.status }, "Ollama request failed, using fallback");
      return fallbackReport(ctx);
    }

    const data = (await response.json()) as { response?: string };
    const parsed = data.response ? parseJsonResponse(data.response) : null;
    if (parsed) return parsed;

    logger.warn("Failed to parse Ollama JSON response, using fallback");
    return fallbackReport(ctx);
  } catch (err) {
    logger.warn({ err }, "Ollama unavailable, using fallback report");
    return fallbackReport(ctx);
  }
}

export async function checkOllamaHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${OLLAMA_BASE}/api/tags`, { signal: AbortSignal.timeout(5_000) });
    if (!res.ok) return false;
    const data = (await res.json()) as { models?: Array<{ name: string }> };
    return data.models?.some((m) => m.name.startsWith(OLLAMA_MODEL.split(":")[0])) ?? false;
  } catch {
    return false;
  }
}
