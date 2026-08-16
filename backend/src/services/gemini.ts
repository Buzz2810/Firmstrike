import { GoogleGenAI } from "@google/genai";
import { logger } from "../lib/logger.js";

/**
 * ============================================================
 * GEMINI CONFIGURATION
 * ============================================================
 */

const REQUEST_TIMEOUT = 120_000;
const MAX_RETRIES = 2;

function getAiClient(): {
  client: GoogleGenAI | null;
  model: string;
} {
  const apiKey = process.env.GEMINI_API_KEY?.trim();

  const model =
    process.env.GEMINI_MODEL?.trim() ||
    "gemini-2.5-flash";

  // Only reject missing/placeholder keys.
  // Do NOT reject keys based on their prefix.
  if (
    !apiKey ||
    apiKey === "your-api-key-here" ||
    apiKey.length < 10
  ) {
    return {
      client: null,
      model,
    };
  }

  try {
    return {
      client: new GoogleGenAI({
        apiKey,
      }),
      model,
    };
  } catch (error) {
    logger.error(
      { err: error },
      "Failed to initialize Gemini client",
    );

    return {
      client: null,
      model,
    };
  }
}

/**
 * ============================================================
 * TYPES
 * ============================================================
 */

export type AiReportContent = {
  summary: string;

  riskLevel:
    | "critical"
    | "high"
    | "medium"
    | "low";

  keyFindings: string[];

  recommendations: string[];

  exploitProbability: number;
};

export type ScanContext = {
  firmwareName: string;

  architecture: string;

  vulnerabilities: Array<{
    type: string;
    severity: string;
    description: string;
    file: string;
  }>;

  secrets: Array<{
    type: string;
    file: string;
    severity: string;
  }>;

  dangerousFunctions: Array<{
    name: string;
    file: string;
    risk: string;
  }>;

  cveIds: string[];

  malwareFindings: Array<{
    fileName: string;
    threatScore: number;
    result: string;
  }>;

  components: string[];
};

/**
 * ============================================================
 * PROMPT
 * ============================================================
 */

function buildPrompt(ctx: ScanContext): string {
  return `
You are a Senior Firmware Security Researcher,
Reverse Engineer, Malware Analyst, Threat Intelligence Expert,
CVE Researcher, Embedded Linux Security Specialist,
and IoT Security Consultant.

Analyze the firmware scan results below.

Return ONLY valid JSON.

Do not return Markdown.
Do not return code fences.
Do not return explanations outside JSON.

==================================================
FIRMWARE
==================================================

Name:
${ctx.firmwareName}

Architecture:
${ctx.architecture}

==================================================
COMPONENTS
==================================================

${
  ctx.components.length > 0
    ? ctx.components.join(", ")
    : "None detected"
}

==================================================
VULNERABILITIES
==================================================

Count:
${ctx.vulnerabilities.length}

${
  ctx.vulnerabilities.length > 0
    ? ctx.vulnerabilities
        .slice(0, 30)
        .map(
          (v, index) => `
${index + 1}.
Severity: ${v.severity}
Type: ${v.type}
Description: ${v.description}
File: ${v.file}
`,
        )
        .join("\n")
    : "None detected"
}

==================================================
HARDCODED SECRETS
==================================================

Count:
${ctx.secrets.length}

${
  ctx.secrets.length > 0
    ? ctx.secrets
        .slice(0, 30)
        .map(
          (s, index) => `
${index + 1}.
Type: ${s.type}
Severity: ${s.severity}
File: ${s.file}
`,
        )
        .join("\n")
    : "None detected"
}

==================================================
DANGEROUS FUNCTIONS
==================================================

Count:
${ctx.dangerousFunctions.length}

${
  ctx.dangerousFunctions.length > 0
    ? ctx.dangerousFunctions
        .slice(0, 30)
        .map(
          (d, index) => `
${index + 1}.
Function: ${d.name}
Risk: ${d.risk}
File: ${d.file}
`,
        )
        .join("\n")
    : "None detected"
}

==================================================
CVE MATCHES
==================================================

Count:
${ctx.cveIds.length}

${
  ctx.cveIds.length > 0
    ? ctx.cveIds.join(", ")
    : "None detected"
}

==================================================
MALWARE INDICATORS
==================================================

Count:
${ctx.malwareFindings.length}

${
  ctx.malwareFindings.length > 0
    ? ctx.malwareFindings
        .map(
          (m, index) => `
${index + 1}.
File: ${m.fileName}
Threat Score: ${m.threatScore}
Detection: ${m.result}
`,
        )
        .join("\n")
    : "None detected"
}

==================================================
SECURITY ASSESSMENT
==================================================

Evaluate:

- Authentication weaknesses
- Privilege escalation
- Command injection
- Buffer overflow
- Unsafe C/C++ functions
- Hardcoded credentials
- Hardcoded SSH keys
- Hardcoded certificates
- Weak cryptography
- Insecure update mechanisms
- Outdated libraries
- BusyBox vulnerabilities
- OpenSSL vulnerabilities
- Exposed services
- Malware indicators
- Known CVEs
- Overall attack surface

==================================================
OUTPUT
==================================================

Return exactly this JSON structure:

{
  "summary": "",
  "riskLevel": "critical",
  "keyFindings": [
    "",
    "",
    "",
    "",
    "",
    ""
  ],
  "recommendations": [
    "",
    "",
    "",
    "",
    "",
    ""
  ],
  "exploitProbability": 0.5
}

Rules:

summary:
3-5 professional sentences.

keyFindings:
Exactly 6 items.

recommendations:
Exactly 6 items.

exploitProbability:
Number between 0 and 1.

riskLevel:
Must be one of:
critical
high
medium
low

Return ONLY JSON.
`;
}

/**
 * ============================================================
 * JSON EXTRACTION
 * ============================================================
 */

function extractJson(text: string): string | null {
  if (!text) {
    return null;
  }

  const cleaned = text
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .replace(
      /<think>[\s\S]*?<\/think>/gi,
      "",
    )
    .replace(
      /<thinking>[\s\S]*?<\/thinking>/gi,
      "",
    )
    .trim();

  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");

  if (
    start === -1 ||
    end === -1 ||
    end <= start
  ) {
    return null;
  }

  return cleaned.substring(start, end + 1);
}

/**
 * ============================================================
 * NORMALIZATION
 * ============================================================
 */

function normalizeRiskLevel(
  risk: unknown,
): AiReportContent["riskLevel"] {
  switch (
    String(risk ?? "").toLowerCase()
  ) {
    case "critical":
      return "critical";

    case "high":
      return "high";

    case "medium":
      return "medium";

    default:
      return "low";
  }
}

function clampProbability(
  value: unknown,
): number {
  const number =
    typeof value === "number"
      ? value
      : Number(value);

  if (!Number.isFinite(number)) {
    return 0.5;
  }

  return Number(
    Math.max(
      0,
      Math.min(1, number),
    ).toFixed(2),
  );
}

/**
 * ============================================================
 * PARSE GEMINI RESPONSE
 * ============================================================
 */

function parseJsonResponse(
  text: string,
): AiReportContent | null {
  try {
    const json = extractJson(text);

    if (!json) {
      logger.warn(
        "Gemini response did not contain JSON.",
      );

      return null;
    }

    const parsed = JSON.parse(json);

    if (
      !parsed ||
      typeof parsed.summary !== "string"
    ) {
      logger.warn(
        "Gemini JSON missing valid summary.",
      );

      return null;
    }

    const findings =
      Array.isArray(
        parsed.keyFindings,
      )
        ? parsed.keyFindings
            .filter(Boolean)
            .map(String)
        : [];

    const recommendations =
      Array.isArray(
        parsed.recommendations,
      )
        ? parsed.recommendations
            .filter(Boolean)
            .map(String)
        : [];

    while (findings.length < 6) {
      findings.push(
        "No additional significant finding.",
      );
    }

    while (
      recommendations.length < 6
    ) {
      recommendations.push(
        "Further manual firmware security review is recommended.",
      );
    }

    return {
      summary:
        parsed.summary.trim(),

      riskLevel:
        normalizeRiskLevel(
          parsed.riskLevel,
        ),

      keyFindings:
        findings.slice(0, 6),

      recommendations:
        recommendations.slice(0, 6),

      exploitProbability:
        clampProbability(
          parsed.exploitProbability,
        ),
    };
  } catch (error) {
    logger.error(
      { err: error },
      "Failed to parse Gemini response.",
    );

    return null;
  }
}

/**
 * ============================================================
 * LOCAL RISK CALCULATION
 * ============================================================
 */

function calculateRisk(
  ctx: ScanContext,
): {
  score: number;
  level: AiReportContent["riskLevel"];
} {
  let score = 0;

  score +=
    ctx.vulnerabilities.filter(
      (v) =>
        v.severity.toLowerCase() ===
        "critical",
    ).length * 35;

  score +=
    ctx.vulnerabilities.filter(
      (v) =>
        v.severity.toLowerCase() ===
        "high",
    ).length * 20;

  score +=
    ctx.vulnerabilities.filter(
      (v) =>
        v.severity.toLowerCase() ===
        "medium",
    ).length * 10;

  score += ctx.secrets.length * 8;

  score +=
    ctx.dangerousFunctions.length * 6;

  score += ctx.cveIds.length * 10;

  score +=
    ctx.malwareFindings.reduce(
      (sum, malware) =>
        sum +
        Number(
          malware.threatScore || 0,
        ),
      0,
    );

  score = Math.min(100, score);

  let level:
    AiReportContent["riskLevel"];

  if (score >= 80) {
    level = "critical";
  } else if (score >= 60) {
    level = "high";
  } else if (score >= 30) {
    level = "medium";
  } else {
    level = "low";
  }

  return {
    score,
    level,
  };
}

/**
 * ============================================================
 * FALLBACK REPORT
 * ============================================================
 */

function fallbackReport(
  ctx: ScanContext,
): AiReportContent {
  const risk = calculateRisk(ctx);

  const findings: string[] = [];

  findings.push(
    ...ctx.vulnerabilities
      .slice(0, 3)
      .map(
        (v) =>
          `[${v.severity}] ${v.type}: ${v.description}`,
      ),
  );

  findings.push(
    ...ctx.secrets
      .slice(0, 2)
      .map(
        (s) =>
          `Hardcoded ${s.type} detected in ${s.file}`,
      ),
  );

  findings.push(
    ...ctx.dangerousFunctions
      .slice(0, 2)
      .map(
        (d) =>
          `Dangerous function ${d.name} found in ${d.file}`,
      ),
  );

  findings.push(
    ...ctx.cveIds
      .slice(0, 2)
      .map(
        (cve) =>
          `Known CVE match detected: ${cve}`,
      ),
  );

  findings.push(
    ...ctx.malwareFindings
      .slice(0, 2)
      .map(
        (malware) =>
          `Malware indicator detected in ${malware.fileName} with threat score ${malware.threatScore}`,
      ),
  );

  while (findings.length < 6) {
    findings.push(
      "No additional significant finding.",
    );
  }

  return {
    summary:
      `Firmware analysis identified ${ctx.vulnerabilities.length} vulnerabilities, ` +
      `${ctx.secrets.length} hardcoded secrets, ` +
      `${ctx.cveIds.length} CVE matches and ` +
      `${ctx.malwareFindings.length} malware indicators. ` +
      `Overall firmware security posture is assessed as ${risk.level.toUpperCase()}. ` +
      `Immediate remediation is recommended before deployment.`,

    riskLevel: risk.level,

    keyFindings:
      findings.slice(0, 6),

    recommendations: [
      "Remove all hardcoded credentials and replace them with secure secret storage.",

      "Patch all vulnerable components associated with detected CVEs.",

      "Replace unsafe APIs and dangerous functions with secure alternatives.",

      "Upgrade outdated libraries including BusyBox, OpenSSL and related dependencies.",

      "Perform manual firmware review and penetration testing before production deployment.",

      "Continuously monitor firmware integrity and deploy signed firmware updates.",
    ],

    exploitProbability:
      Number(
        (risk.score / 100).toFixed(2),
      ),
  };
}

/**
 * ============================================================
 * GEMINI REPORT GENERATION
 * ============================================================
 */

export async function generateAiReport(
  ctx: ScanContext,
): Promise<AiReportContent> {
  const {
    client,
    model,
  } = getAiClient();

  logger.info(
    {
      firmware: ctx.firmwareName,
      vulnerabilities:
        ctx.vulnerabilities.length,
      secrets:
        ctx.secrets.length,
      dangerousFunctions:
        ctx.dangerousFunctions.length,
      cves:
        ctx.cveIds.length,
      malware:
        ctx.malwareFindings.length,
      components:
        ctx.components.length,
      model,
    },
    "Preparing AI firmware security report",
  );

  if (!client) {
    logger.warn(
      {
        firmware:
          ctx.firmwareName,
        model,
      },
      "Gemini unavailable. Using local fallback report.",
    );

    return fallbackReport(ctx);
  }

  const prompt = buildPrompt(ctx);

  let lastError: unknown;

  for (
    let attempt = 1;
    attempt <= MAX_RETRIES;
    attempt++
  ) {
    try {
      logger.info(
        {
          firmware:
            ctx.firmwareName,
          attempt,
          model,
        },
        "Calling Gemini for firmware security report",
      );

      const response =
        await Promise.race([
          client.models.generateContent({
            model,
            contents: prompt,
            config: {
              temperature: 0.2,
              maxOutputTokens: 4096,
              responseMimeType:
                "application/json",
            },
          }),

          new Promise<never>(
            (_, reject) =>
              setTimeout(
                () =>
                  reject(
                    new Error(
                      "Gemini request timeout",
                    ),
                  ),
                REQUEST_TIMEOUT,
              ),
          ),
        ]);

      const text =
        typeof response ===
          "object" &&
        response &&
        "text" in response
          ? String(
              response.text,
            ).trim()
          : "";

      if (!text) {
        throw new Error(
          "Gemini returned an empty response.",
        );
      }

      const parsed =
        parseJsonResponse(text);

      if (!parsed) {
        throw new Error(
          "Gemini returned invalid JSON.",
        );
      }

      logger.info(
        {
          firmware:
            ctx.firmwareName,
          attempt,
          risk:
            parsed.riskLevel,
          exploitProbability:
            parsed.exploitProbability,
        },
        "Gemini AI report generated successfully",
      );

      return parsed;
    } catch (error) {
      lastError = error;

      logger.warn(
        {
          firmware:
            ctx.firmwareName,
          attempt,
          error:
            error instanceof Error
              ? error.message
              : error,
        },
        "Gemini report generation failed",
      );

      if (
        attempt < MAX_RETRIES
      ) {
        const delay =
          1000 *
          Math.pow(2, attempt);

        await new Promise(
          (resolve) =>
            setTimeout(
              resolve,
              delay,
            ),
        );
      }
    }
  }

  logger.error(
    {
      firmware:
        ctx.firmwareName,
      error: lastError,
    },
    "All Gemini attempts failed. Using local fallback report.",
  );

  return fallbackReport(ctx);
}

/**
 * ============================================================
 * GEMINI HEALTH CHECK
 * ============================================================
 */

export async function checkGeminiHealth(): Promise<boolean> {
  const {
    client,
    model,
  } = getAiClient();

  if (!client) {
    return false;
  }

  try {
    const response =
      await Promise.race([
        client.models.generateContent({
          model,
          contents:
            "Reply with OK only.",
          config: {
            temperature: 0,
            maxOutputTokens: 8,
          },
        }),

        new Promise<never>(
          (_, reject) =>
            setTimeout(
              () =>
                reject(
                  new Error(
                    "Gemini health check timeout",
                  ),
                ),
              30_000,
            ),
        ),
      ]);

    const text =
      typeof response ===
        "object" &&
      response &&
      "text" in response
        ? String(
            response.text,
          ).trim()
        : "";

    if (!text) {
      return false;
    }

    logger.info(
      {
        model,
      },
      "Gemini health check successful",
    );

    return true;
  } catch (error) {
    logger.warn(
      {
        err: error,
        model,
      },
      "Gemini health check failed",
    );

    return false;
  }
}

/**
 * ============================================================
 * FINALIZER
 * ============================================================
 */

export function finalizeReport(
  report: AiReportContent,
): AiReportContent {
  return {
    ...report,

    summary:
      report.summary.trim(),

    keyFindings:
      report.keyFindings
        .map((x) => x.trim())
        .filter(Boolean)
        .slice(0, 6),

    recommendations:
      report.recommendations
        .map((x) => x.trim())
        .filter(Boolean)
        .slice(0, 6),

    exploitProbability:
      Math.max(
        0,
        Math.min(
          1,
          report.exploitProbability,
        ),
      ),
  };
}

/**
 * ============================================================
 * DEFAULT EXPORT
 * ============================================================
 */

export default {
  generateAiReport,
  checkGeminiHealth,
  finalizeReport,
};