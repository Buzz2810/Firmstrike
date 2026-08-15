import { Router, type IRouter } from "express";
import { createReadStream } from "node:fs";
import { db, aiReportsTable, scanResultsTable, firmwareTable, vulnerabilitiesTable, malwareHashesTable } from "@workspace/db";
import { eq, desc } from "drizzle-orm";
import { generatePdfReport } from "../services/pdf.js";
import { generateAiReport } from "../services/gemini.js";
import { generateSbomReport, getSbomReport } from "../services/sbom-generator.js";
import { resolveScanId } from "../lib/scans.js";

const router: IRouter = Router();

router.get("/reports/pdf/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const resolved = await resolveScanId(raw);
  if (!resolved) { res.status(400).json({ error: "Invalid scan/firmware ID" }); return; }

  const { size } = await generatePdfReport(resolved.scanId);
  const [scan] = await db.select().from(scanResultsTable).where(eq(scanResultsTable.id, resolved.scanId));

  res.json({
    scanId: resolved.scanId,
    firmwareId: resolved.firmwareId,
    generatedAt: new Date().toISOString(),
    downloadUrl: `/api/reports/pdf/${resolved.scanId}/download`,
    fileSize: size,
    scanIdNum: scan?.id ?? resolved.scanId,
  });
});

router.get("/reports/pdf/:id/download", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const resolved = await resolveScanId(raw);
  if (!resolved) { res.status(400).json({ error: "Invalid scan/firmware ID" }); return; }

  const { path: reportFilePath } = await generatePdfReport(resolved.scanId);
  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, resolved.firmwareId));

  const safeName = (fw?.name ?? `scan-${resolved.scanId}`).replace(/[^a-zA-Z0-9._-]/g, "_");
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="firmstrike-report-${safeName}-scan${resolved.scanId}.pdf"`);

  const fileStream = createReadStream(reportFilePath);
  fileStream.on("error", () => {
    if (!res.headersSent) res.status(500).json({ error: "Failed to stream report" });
  });
  fileStream.pipe(res);
});

router.get("/reports/ai-summary/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const resolved = await resolveScanId(raw);
  if (!resolved) { res.status(400).json({ error: "Invalid scan/firmware ID" }); return; }

  let [report] = await db.select().from(aiReportsTable).where(eq(aiReportsTable.scanId, resolved.scanId));

  if (!report) {
    const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, resolved.firmwareId));
    const vulns = await db.select().from(vulnerabilitiesTable).where(eq(vulnerabilitiesTable.scanId, resolved.scanId));

    const ai = await generateAiReport({
      firmwareName: fw?.name ?? `Firmware #${resolved.firmwareId}`,
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
      scanId: resolved.scanId,
      firmwareId: resolved.firmwareId,
      summary: ai.summary,
      riskLevel: ai.riskLevel,
      keyFindings: JSON.stringify(ai.keyFindings),
      recommendations: JSON.stringify(ai.recommendations),
      exploitProbability: ai.exploitProbability,
    }).returning();
    report = inserted;
  }

  res.json({
    scanId: report.scanId ?? resolved.scanId,
    firmwareId: report.firmwareId,
    summary: report.summary,
    riskLevel: report.riskLevel,
    keyFindings: JSON.parse(report.keyFindings),
    recommendations: JSON.parse(report.recommendations),
    generatedAt: report.generatedAt.toISOString(),
    exploitProbability: report.exploitProbability ?? null,
  });
});

router.get("/reports/sbom/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const resolved = await resolveScanId(raw);
  if (!resolved) { res.status(400).json({ error: "Invalid scan/firmware ID" }); return; }

  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, resolved.firmwareId));
  if (!fw?.extractPath) { res.status(404).json({ error: "Firmware extraction path not available" }); return; }

  let sbom = await getSbomReport(resolved.scanId);
  if (!sbom) {
    await generateSbomReport(resolved.scanId, resolved.firmwareId, fw.extractPath);
    sbom = await getSbomReport(resolved.scanId);
  }

  if (!sbom) {
    res.status(500).json({ error: "Unable to generate SBOM" });
    return;
  }

  res.json({
    scanId: resolved.scanId,
    firmwareId: resolved.firmwareId,
    generatedAt: sbom.report.generatedAt.toISOString(),
    componentCount: sbom.report.componentCount,
    downloadUrls: {
      cyclonedx: `/api/reports/sbom/${resolved.scanId}/download/cyclonedx`,
      spdx: `/api/reports/sbom/${resolved.scanId}/download/spdx`,
      csv: `/api/reports/sbom/${resolved.scanId}/download/csv`,
    },
    components: sbom.components,
  });
});

router.get("/reports/sbom/:id/download/:format", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const format = req.params.format;
  const resolved = await resolveScanId(raw);
  if (!resolved) { res.status(400).json({ error: "Invalid scan/firmware ID" }); return; }
  if (!["cyclonedx", "spdx", "csv"].includes(format)) { res.status(400).json({ error: "Unsupported format" }); return; }
  const formatKey = format as "cyclonedx" | "spdx" | "csv";

  const sbom = await getSbomReport(resolved.scanId);
  if (!sbom) { res.status(404).json({ error: "SBOM report not found" }); return; }

  const filePath = formatKey === "cyclonedx" ? sbom.report.cyclonedxPath : formatKey === "spdx" ? sbom.report.spdxPath : sbom.report.csvPath;
  const types = { cyclonedx: "application/json", spdx: "application/json", csv: "text/csv" } as const;
  const names = { cyclonedx: "cyclonedx", spdx: "spdx", csv: "sbom" } as const;

  res.setHeader("Content-Type", types[formatKey]);
  res.setHeader("Content-Disposition", `attachment; filename="scan-${resolved.scanId}-${names[formatKey]}.${formatKey === "csv" ? "csv" : "json"}"`);
  createReadStream(filePath).pipe(res);
});

router.get("/reports/history", async (_req, res): Promise<void> => {
  const scans = await db.select().from(scanResultsTable).orderBy(desc(scanResultsTable.startedAt)).limit(20);
  const allHashes = await db.select().from(malwareHashesTable);
  const hashScoreByScan = new Map<number, number>();
  const hashGrouped = new Map<number, typeof allHashes>();
  for (const h of allHashes) {
    if (h.scanId) {
      const existing = hashGrouped.get(h.scanId) ?? [];
      existing.push(h);
      hashGrouped.set(h.scanId, existing);
    }
  }
  for (const [sId, hashes] of hashGrouped.entries()) {
    const avg = hashes.reduce((s, h) => s + h.threatScore, 0) / hashes.length;
    hashScoreByScan.set(sId, Math.round(avg));
  }

  const history = await Promise.all(scans.map(async (s) => {
    const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, s.firmwareId));
    const threatScore = hashScoreByScan.get(s.id) ??
      (s.riskLevel === "critical" ? 75 : s.riskLevel === "high" ? 50 : s.riskLevel === "medium" ? 25 : 5);
    return {
      id: s.id,
      scanId: s.id,
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