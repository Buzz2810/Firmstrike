import {
  db,
  scanResultsTable,
  firmwareTable,
  vulnerabilitiesTable,
  extractedFilesTable,
  hardcodedSecretsTable,
  dangerousFunctionsTable,
  activityTable,
  cveMatchesTable,
  malwareHashesTable,
  emulationLogsTable,
  aiReportsTable,
} from "@workspace/db";

import { eq } from "drizzle-orm";
import { logger } from "../lib/logger.js";
import { firmwareExtractPath } from "../lib/paths.js";
import { extractFirmware } from "./extraction.js";
import { analyzeStaticFiles } from "./static-analyzer.js";
import { matchCvesForComponents } from "./cve.js";
import { scanExtractedBinaries } from "./malware-analyzer.js";
import { runEmulation } from "./emulation.js";
import { generateAiReport } from "./gemini.js";
import { generateSbomReport } from "./sbom-generator.js";

function computeRiskLevel(
  vulnCount: number,
  criticalCount: number,
  malwareCount: number,
): "critical" | "high" | "medium" | "low" {
  if (criticalCount > 0 || malwareCount > 0) {
    return "critical";
  }

  if (vulnCount > 5) {
    return "high";
  }

  if (vulnCount > 0) {
    return "medium";
  }

  return "low";
}

export async function runScanPipeline(
  firmwareId: number,
  scanId: number,
): Promise<void> {
  const [fw] = await db
    .select()
    .from(firmwareTable)
    .where(eq(firmwareTable.id, firmwareId));

  if (!fw?.filePath) {
    await db
      .update(scanResultsTable)
      .set({
        status: "failed",
        progress: 100,
      })
      .where(eq(scanResultsTable.id, scanId));

    await db
      .update(firmwareTable)
      .set({
        status: "failed",
      })
      .where(eq(firmwareTable.id, firmwareId));

    return;
  }

  try {
    // ==========================================
    // 1. START
    // ==========================================

    await db
      .update(scanResultsTable)
      .set({
        progress: 10,
      })
      .where(eq(scanResultsTable.id, scanId));

    // ==========================================
    // 2. EXTRACTION
    // ==========================================

    const extractPath =
      fw.extractPath ?? firmwareExtractPath(firmwareId);

    const extraction = await extractFirmware(
      fw.filePath,
      extractPath,
    );

    // ==========================================
    // 3. DETECT ARCHITECTURE / VENDOR / VERSION
    // ==========================================

    const architecture = extraction.architecture;
    const vendor = extraction.vendor;
    const version = extraction.version;

    logger.info(
      {
        firmwareId,
        architecture,
        vendor,
        version,
      },
      "Firmware metadata detected",
    );

    console.log("");
    console.log("========================================");
    console.log("       FIRMWARE DETECTION");
    console.log("========================================");
    console.log("Architecture :", architecture);
    console.log("Vendor       :", vendor ?? "UNKNOWN");
    console.log("Version      :", version ?? "UNKNOWN");
    console.log("Components   :", extraction.components);
    console.log("========================================");
    console.log("");

    // ==========================================
    // 4. SAVE METADATA TO DATABASE
    // ==========================================

    await db
      .update(firmwareTable)
      .set({
        extractPath,
        architecture,
        vendor,
        version,
      })
      .where(eq(firmwareTable.id, firmwareId));

    await db
      .update(scanResultsTable)
      .set({
        progress: 30,
      })
      .where(eq(scanResultsTable.id, scanId));

    // ==========================================
    // 5. SAVE EXTRACTED FILES
    // ==========================================

    if (extraction.files.length > 0) {
      await db.insert(extractedFilesTable).values(
        extraction.files.map((file) => ({
          firmwareId,
          ...file,
        })),
      );
    }

    // ==========================================
    // 6. STATIC ANALYSIS
    // ==========================================

    const staticAnalysis = await analyzeStaticFiles(
      extractPath,
      extraction.files.map((file) => file.path),
    );

    await db
      .update(scanResultsTable)
      .set({
        progress: 50,
      })
      .where(eq(scanResultsTable.id, scanId));

    // ==========================================
    // 7. HARD-CODED SECRETS
    // ==========================================

    if (staticAnalysis.secrets.length > 0) {
      await db.insert(hardcodedSecretsTable).values(
        staticAnalysis.secrets.map((secret) => ({
          firmwareId,
          ...secret,
        })),
      );
    }

    // ==========================================
    // 8. DANGEROUS FUNCTIONS
    // ==========================================

    if (staticAnalysis.dangerous.length > 0) {
      await db.insert(dangerousFunctionsTable).values(
        staticAnalysis.dangerous.map((dangerous) => ({
          firmwareId,
          ...dangerous,
        })),
      );
    }

    // ==========================================
    // 9. VULNERABILITIES
    // ==========================================

    if (staticAnalysis.vulnerabilities.length > 0) {
      await db.insert(vulnerabilitiesTable).values(
        staticAnalysis.vulnerabilities.map((vulnerability) => ({
          firmwareId,
          ...vulnerability,
        })),
      );
    }

    // ==========================================
    // 10. CVE MATCHING
    // ==========================================

    const cveMatches = await matchCvesForComponents(
      extraction.components,
    );

    if (cveMatches.length > 0) {
      await db.insert(cveMatchesTable).values(
        cveMatches.map((cve) => ({
          firmwareId,
          ...cve,
        })),
      );
    }

    await db
      .update(scanResultsTable)
      .set({
        progress: 70,
      })
      .where(eq(scanResultsTable.id, scanId));

    // ==========================================
    // 11. MALWARE ANALYSIS
    // ==========================================

    const malwareResults = await scanExtractedBinaries(
      extractPath,
      extraction.files,
    );

    if (malwareResults.length > 0) {
      await db.insert(malwareHashesTable).values(
        malwareResults.map((malware) => ({
          firmwareId,
          sha256: malware.sha256,
          threatScore: malware.threatScore,
          virusTotalResult: malware.virusTotalResult,
          isMalicious: malware.isMalicious,
          detectionCount: malware.detectionCount,
          totalEngines: malware.totalEngines,
          fileName: malware.fileName,
        })),
      );
    }

    // ==========================================
    // 12. EMULATION
    // ==========================================

    const emulation = await runEmulation(
      fw.filePath,
      extractPath,
      architecture,
    );

    await db.insert(emulationLogsTable).values({
      firmwareId,
      status: "running",
      architecture: emulation.architecture,
      runningServices: JSON.stringify(
        emulation.runningServices,
      ),
      openPorts: JSON.stringify(
        emulation.openPorts,
      ),
      runtimeLogs: emulation.runtimeLogs,
    });

    await db
      .update(scanResultsTable)
      .set({
        progress: 85,
      })
      .where(eq(scanResultsTable.id, scanId));

    // ==========================================
    // 13. SBOM
    // ==========================================

    await generateSbomReport(
      firmwareId,
      extractPath,
    );

    // ==========================================
    // 14. AI REPORT
    // ==========================================

    const aiReport = await generateAiReport({
      firmwareName: fw.name,
      architecture,

      vulnerabilities:
        staticAnalysis.vulnerabilities.map(
          (vulnerability) => ({
            type: vulnerability.type,
            severity: vulnerability.severity,
            description: vulnerability.description,
            file: vulnerability.affectedFile,
          }),
        ),

      secrets: staticAnalysis.secrets.map(
        (secret) => ({
          type: secret.type,
          file: secret.file,
          severity: secret.severity,
        }),
      ),

      dangerousFunctions:
        staticAnalysis.dangerous.map(
          (dangerous) => ({
            name: dangerous.name,
            file: dangerous.file,
            risk: dangerous.risk,
          }),
        ),

      cveIds: cveMatches.map(
        (cve) => cve.cveId,
      ),

      malwareFindings:
        malwareResults.map((malware) => ({
          fileName: malware.fileName,
          threatScore: malware.threatScore,
          result: malware.virusTotalResult,
        })),

      components: extraction.components,
    });

    await db
      .insert(aiReportsTable)
      .values({
        firmwareId,
        summary: aiReport.summary,
        riskLevel: aiReport.riskLevel,
        keyFindings: JSON.stringify(
          aiReport.keyFindings,
        ),
        recommendations: JSON.stringify(
          aiReport.recommendations,
        ),
        exploitProbability:
          aiReport.exploitProbability,
      })
      .onConflictDoUpdate({
        target: aiReportsTable.firmwareId,
        set: {
          summary: aiReport.summary,
          riskLevel: aiReport.riskLevel,
          keyFindings: JSON.stringify(
            aiReport.keyFindings,
          ),
          recommendations: JSON.stringify(
            aiReport.recommendations,
          ),
          exploitProbability:
            aiReport.exploitProbability,
          generatedAt: new Date(),
        },
      });

    // ==========================================
    // 15. CALCULATE RISK
    // ==========================================

    const allVulnerabilities =
      staticAnalysis.vulnerabilities;

    const criticalCount =
      allVulnerabilities.filter(
        (vulnerability) =>
          vulnerability.severity === "critical",
      ).length;

    const malwareCount =
      malwareResults.filter(
        (malware) => malware.isMalicious,
      ).length;

    const riskLevel = computeRiskLevel(
      allVulnerabilities.length,
      criticalCount,
      malwareCount,
    );

    // ==========================================
    // 16. COMPLETE SCAN
    // ==========================================

    await db
      .update(scanResultsTable)
      .set({
        status: "completed",
        progress: 100,
        completedAt: new Date(),
        totalFiles: extraction.files.length,
        vulnerabilitiesFound:
          allVulnerabilities.length,
        riskLevel,
      })
      .where(eq(scanResultsTable.id, scanId));

    // ==========================================
    // 17. MARK FIRMWARE COMPLETED
    // ==========================================

    await db
      .update(firmwareTable)
      .set({
        status: "completed",
        architecture,
        vendor,
        version,
      })
      .where(eq(firmwareTable.id, firmwareId));

    // ==========================================
    // 18. ACTIVITY LOG
    // ==========================================

    await db.insert(activityTable).values({
      type: "scan_completed",
      message:
        `Scan completed: ${allVulnerabilities.length} vulnerabilities, ` +
        `${cveMatches.length} CVEs, risk ${riskLevel.toUpperCase()}`,
      severity:
        riskLevel === "critical"
          ? "critical"
          : riskLevel === "high"
            ? "high"
            : "info",
      firmwareId,
      firmwareName: fw.name,
    });

    // ==========================================
    // 19. MALWARE ACTIVITY
    // ==========================================

    if (malwareCount > 0) {
      await db.insert(activityTable).values({
        type: "malware_detected",
        message:
          `Malware indicators found in ${fw.name}`,
        severity: "critical",
        firmwareId,
        firmwareName: fw.name,
      });
    }

    console.log("");
    console.log("========================================");
    console.log("           SCAN COMPLETED");
    console.log("========================================");
    console.log("Firmware     :", fw.name);
    console.log("Architecture :", architecture);
    console.log("Vendor       :", vendor ?? "UNKNOWN");
    console.log("Version      :", version ?? "UNKNOWN");
    console.log("Vulnerabilities:", allVulnerabilities.length);
    console.log("CVEs         :", cveMatches.length);
    console.log("Risk         :", riskLevel.toUpperCase());
    console.log("========================================");
    console.log("");
  } catch (err) {
    logger.error(
      {
        err,
        firmwareId,
      },
      "Scan pipeline failed",
    );

    await db
      .update(scanResultsTable)
      .set({
        status: "failed",
        progress: 100,
      })
      .where(eq(scanResultsTable.id, scanId));

    await db
      .update(firmwareTable)
      .set({
        status: "failed",
      })
      .where(eq(firmwareTable.id, firmwareId));

    await db.insert(activityTable).values({
      type: "scan_completed",
      message:
        `Scan failed for firmware ID ${firmwareId}`,
      severity: "high",
      firmwareId,
    });
  }
}