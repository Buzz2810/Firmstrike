import { Router, type IRouter } from "express";
import { db, scanResultsTable, firmwareTable, activityTable, extractedFilesTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { runScanPipeline } from "../services/scan-pipeline.js";
import { analyzeBinary, pickBinaryTarget } from "../services/binary-analyzer.js";

const router: IRouter = Router();

router.post("/scanner/start", async (req, res): Promise<void> => {
  const { firmwareId } = req.body;
  if (!firmwareId) { res.status(400).json({ error: "Missing firmwareId" }); return; }

  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, firmwareId));
  if (!fw) { res.status(404).json({ error: "Firmware not found" }); return; }
  if (!fw.filePath) {
    res.status(400).json({ error: "Firmware file not uploaded. Use /firmware/upload with a binary file." });
    return;
  }

  await db.update(firmwareTable).set({ status: "scanning" }).where(eq(firmwareTable.id, firmwareId));

  const [scan] = await db.insert(scanResultsTable).values({
    firmwareId,
    status: "running",
    progress: 0,
  }).returning();

  await db.insert(activityTable).values({
    type: "scan_started",
    message: `Scan initiated for ${fw.name}`,
    severity: "info",
    firmwareId,
    firmwareName: fw.name,
  });

  // Run pipeline async — don't block response
  void runScanPipeline(firmwareId, scan.id);

  res.status(201).json({
    id: scan.id,
    firmwareId: scan.firmwareId,
    startedAt: scan.startedAt.toISOString(),
    completedAt: null,
    status: scan.status,
    progress: scan.progress,
    totalFiles: null,
    vulnerabilitiesFound: null,
    riskLevel: null,
  });
});

router.get("/scanner/results/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }
  const results = await db.select().from(scanResultsTable).where(eq(scanResultsTable.firmwareId, firmwareId));
  res.json(results.map(r => ({
    ...r,
    startedAt: r.startedAt.toISOString(),
    completedAt: r.completedAt ? r.completedAt.toISOString() : null,
  })));
});

router.get("/scanner/files/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }
  const files = await db.select().from(extractedFilesTable).where(eq(extractedFilesTable.firmwareId, firmwareId));
  res.json(files);
});

router.post("/scanner/binary/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }

  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, firmwareId));
  if (!fw?.filePath) { res.status(404).json({ error: "Firmware file not found" }); return; }

  const { filePath: reqPath } = req.body;
  const target = reqPath
    ? `${fw.extractPath ?? ""}${reqPath}`.replace(/\/\//g, "/")
    : pickBinaryTarget(fw.extractPath ?? "", [fw.filePath]) ?? fw.filePath;

  const result = await analyzeBinary(firmwareId, target);
  res.json(result);
});

export default router;
