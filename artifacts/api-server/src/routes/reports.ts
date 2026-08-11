import { Router, type IRouter } from "express";
import { createReadStream } from "node:fs";
import { db, aiReportsTable, scanResultsTable, firmwareTable, vulnerabilitiesTable, malwareHashesTable } from "@workspace/db";
import { eq, desc } from "drizzle-orm";
import { generatePdfReport } from "../services/pdf.js";
import { generateAiReport } from "../services/gemini.js";
import { generateSbomReport, getSbomReport } from "../services/sbom-generator.js";

const router: IRouter = Router();

router.get("/reports/pdf/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }

  const { size } = await generatePdfReport(firmwareId);
  const [scan] = await db.select().from(scanResultsTable).where(eq(scanResultsTable.firmwareId, firmwareId));

  res.json({
    firmwareId,
    generatedAt: new Date().toISOString(),
    downloadUrl: `/api/reports/pdf/${firmwareId}/download`,
    fileSize: size,
    scanId: scan?.id ?? null,
  });
});

router.get("/reports/pdf/:firmwareId/download", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }

  const { path: reportFilePath } = await generatePdfReport(firmwareId);
  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, firmwareId));

  const safeName = (fw?.name ?? `firmware-${firmwareId}`).replace(/[^a-zA-Z0-9._-]/g, "_");
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="viv-report-${safeName}.pdf"`);

  const fileStream = createReadStream(reportFilePath);
  fileStream.on("error", () => {
    if (!res.headersSent) res.status(500).json({ error: "Failed to stream report" });
  });
  fileStream.pipe(res);
});

router.get("/reports/ai-summary/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }

  let [report] = await db.select().from(aiReportsTable).where(eq(aiReportsTable.firmwareId, firmwareId));

  if (!report) {
    const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, firmwareId));
    const vulns = await db.select().from(vulnerabilitiesTable).where(eq(vulnerabilitiesTable.firmwareId, firmwareId));

    const ai = await generateAiReport({
      firmwareName: fw?.name ?? `Firmware #${firmwareId}`,
      architecture: fw?.architecture ?? "UNKNOWN",
      vulnerabilities: vulns.map((v) => ({
        type: v.type,
        severity: v.severity,
        description: v.description,
        file: v.affectedFile,
      })),
      secrets: [],
      dangerousFunctions: [],
      cveIds: [],
      malwareFindings: [],
      components: [],
    });

    const [inserted] = await db.insert(aiReportsTable).values({
      firmwareId,
      summary: ai.summary,
      riskLevel: ai.riskLevel,
      keyFindings: JSON.stringify(ai.keyFindings),
      recommendations: JSON.stringify(ai.recommendations),
      exploitProbability: ai.exploitProbability,
    }).returning();
    report = inserted;
  }

  res.json({
    firmwareId: report.firmwareId,
    summary: report.summary,
    riskLevel: report.riskLevel,
    keyFindings: JSON.parse(report.keyFindings),
    recommendations: JSON.parse(report.recommendations),
    generatedAt: report.generatedAt.toISOString(),
    exploitProbability: report.exploitProbability ?? null,
  });
});

router.get("/reports/sbom/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }

  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, firmwareId));
  if (!fw?.extractPath) { res.status(404).json({ error: "Firmware extraction path not available" }); return; }

  let sbom = await getSbomReport(firmwareId);
  if (!sbom) {
    await generateSbomReport(firmwareId, fw.extractPath);
    sbom = await getSbomReport(firmwareId);
  }

  if (!sbom) {
    res.status(500).json({ error: "Unable to generate SBOM" });
    return;
  }

  res.json({
    firmwareId,
    generatedAt: sbom.report.generatedAt.toISOString(),
    componentCount: sbom.report.componentCount,
    downloadUrls: {
      cyclonedx: `/api/reports/sbom/${firmwareId}/download/cyclonedx`,
      spdx: `/api/reports/sbom/${firmwareId}/download/spdx`,
      csv: `/api/reports/sbom/${firmwareId}/download/csv`,
    },
    components: sbom.components,
  });
});

router.get("/reports/sbom/:firmwareId/download/:format", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  const format = req.params.format;
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }
  if (!["cyclonedx", "spdx", "csv"].includes(format)) { res.status(400).json({ error: "Unsupported format" }); return; }
  const formatKey = format as "cyclonedx" | "spdx" | "csv";

  const sbom = await getSbomReport(firmwareId);
  if (!sbom) { res.status(404).json({ error: "SBOM report not found" }); return; }

  const filePath = formatKey === "cyclonedx" ? sbom.report.cyclonedxPath : formatKey === "spdx" ? sbom.report.spdxPath : sbom.report.csvPath;
  const types = { cyclonedx: "application/json", spdx: "application/json", csv: "text/csv" } as const;
  const names = { cyclonedx: "cyclonedx", spdx: "spdx", csv: "sbom" } as const;

  res.setHeader("Content-Type", types[formatKey]);
  res.setHeader("Content-Disposition", `attachment; filename="firmware-${firmwareId}-${names[formatKey]}.${formatKey === "csv" ? "csv" : "json"}"`);
  createReadStream(filePath).pipe(res);
});

router.get("/reports/history", async (_req, res): Promise<void> => {
  const scans = await db.select().from(scanResultsTable).orderBy(desc(scanResultsTable.startedAt)).limit(20);
  // Fetch all malware hashes to compute real threat scores
  const allHashes = await db.select().from(malwareHashesTable);
  const hashScoreByFirmware = new Map<number, number>();
  const hashGrouped = new Map<number, typeof allHashes>();
  for (const h of allHashes) {
    const existing = hashGrouped.get(h.firmwareId) ?? [];
    existing.push(h);
    hashGrouped.set(h.firmwareId, existing);
  }
  for (const [fwId, hashes] of hashGrouped.entries()) {
    const avg = hashes.reduce((s, h) => s + h.threatScore, 0) / hashes.length;
    hashScoreByFirmware.set(fwId, Math.round(avg));
  }

  const history = await Promise.all(scans.map(async (s) => {
    const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, s.firmwareId));
    // Prefer real malware-derived threat score; fall back to risk-level estimate
    const threatScore = hashScoreByFirmware.get(s.firmwareId) ??
      (s.riskLevel === "critical" ? 75 : s.riskLevel === "high" ? 50 : s.riskLevel === "medium" ? 25 : 5);
    return {
      id: s.id,
      firmwareId: s.firmwareId,
      firmwareName: fw?.name || `Firmware #${s.firmwareId}`,
      scannedAt: s.startedAt.toISOString(),
      status: s.status,
      riskLevel: s.riskLevel || "low",
      vulnerabilitiesFound: s.vulnerabilitiesFound || 0,
      threatScore,
    };
  }));
  res.json(history);
});

export default router;