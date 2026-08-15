import { Router, type IRouter } from "express";
import {
  db,
  scanResultsTable,
  firmwareTable,
  activityTable,
  extractedFilesTable,
} from "@workspace/db";
import { eq, desc } from "drizzle-orm";
import { runScanPipeline } from "../services/scan-pipeline.js";
import { analyzeBinary, pickBinaryTarget } from "../services/binary-analyzer.js";
import { resolveScanId } from "../lib/scans.js";

const router: IRouter = Router();

/*
 * ============================================================
 * START SCAN (Returns created Scan ID)
 * ============================================================
 */

router.post("/scanner/start", async (req, res): Promise<void> => {
  try {
    const { firmwareId } = req.body;
    const parsedFirmwareId = Number(firmwareId);

    if (!Number.isInteger(parsedFirmwareId) || parsedFirmwareId <= 0) {
      res.status(400).json({ error: "Invalid firmwareId" });
      return;
    }

    const [fw] = await db
      .select()
      .from(firmwareTable)
      .where(eq(firmwareTable.id, parsedFirmwareId));

    if (!fw) {
      res.status(404).json({ error: "Firmware not found" });
      return;
    }

    if (!fw.filePath) {
      res.status(400).json({ error: "Firmware file not uploaded. Use /firmware/upload first." });
      return;
    }

    const existingScans = await db
      .select()
      .from(scanResultsTable)
      .where(eq(scanResultsTable.firmwareId, parsedFirmwareId));

    const runningScan = existingScans.find(
      (scan) => scan.status === "running" || scan.status === "pending",
    );

    if (runningScan) {
      res.status(409).json({
        error: "A scan is already running for this firmware.",
        scanId: runningScan.id,
      });
      return;
    }

    await db
      .update(firmwareTable)
      .set({ status: "scanning" })
      .where(eq(firmwareTable.id, parsedFirmwareId));

    const [scan] = await db
      .insert(scanResultsTable)
      .values({
        firmwareId: parsedFirmwareId,
        status: "running",
        progress: 0,
      })
      .returning();

    try {
      await db.insert(activityTable).values({
        type: "scan_started",
        message: `Scan #${scan.id} initiated for ${fw.name}`,
        severity: "info",
        scanId: scan.id,
        firmwareId: parsedFirmwareId,
        firmwareName: fw.name,
      });
    } catch (err) {
      console.warn("[Activity Insert Warning] could not record activity", err);
    }

    // runScanPipeline expects (firmwareId, scanId)
    void runScanPipeline(parsedFirmwareId, scan.id).catch((error) => {
      console.error("[Scanner Pipeline Unhandled Error]", error);
    });

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
  } catch (error) {
    console.error("[Scanner Start Error]", error);
    res.status(500).json({
      error: "Failed to start scanner",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

/*
 * ============================================================
 * GET ALL SCANS FOR A FIRMWARE
 * ============================================================
 */

router.get("/scanner/scans/firmware/:firmwareId", async (req, res): Promise<void> => {
  try {
    const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
    const firmwareId = parseInt(raw, 10);
    if (isNaN(firmwareId)) {
      res.status(400).json({ error: "Invalid firmwareId" });
      return;
    }

    const scans = await db
      .select()
      .from(scanResultsTable)
      .where(eq(scanResultsTable.firmwareId, firmwareId))
      .orderBy(desc(scanResultsTable.id));

    res.json(
      scans.map((s) => ({
        ...s,
        startedAt: s.startedAt.toISOString(),
        completedAt: s.completedAt ? s.completedAt.toISOString() : null,
      })),
    );
  } catch (error) {
    console.error("[Fetch Firmware Scans Error]", error);
    res.status(500).json({ error: "Failed to fetch scan executions" });
  }
});

/*
 * ============================================================
 * GET SCAN RESULTS BY SCAN ID (OR FALLBACK FIRMWARE ID)
 * ============================================================
 */

router.get("/scanner/results/:id", async (req, res): Promise<void> => {
  try {
    const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const resolved = await resolveScanId(raw);

    if (!resolved) {
      res.json([]);
      return;
    }

    // Return the specific scan result
    const scans = await db
      .select()
      .from(scanResultsTable)
      .where(eq(scanResultsTable.id, resolved.scanId));

    res.json(
      scans.map((result) => ({
        ...result,
        startedAt: result.startedAt.toISOString(),
        completedAt: result.completedAt ? result.completedAt.toISOString() : null,
      })),
    );
  } catch (error) {
    console.error("[Scanner Results Error]", error);
    res.status(500).json({ error: "Failed to fetch scan results" });
  }
});

/*
 * ============================================================
 * GET EXTRACTED FILES BY SCAN ID (OR FALLBACK FIRMWARE ID)
 * ============================================================
 */

router.get("/scanner/files/:id", async (req, res): Promise<void> => {
  try {
    const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const resolved = await resolveScanId(raw);

    if (!resolved) {
      res.json([]);
      return;
    }

    const files = await db
      .select()
      .from(extractedFilesTable)
      .where(eq(extractedFilesTable.scanId, resolved.scanId));

    res.json(files);
  } catch (error) {
    console.error("[Scanner Files Error]", error);
    res.status(500).json({ error: "Failed to fetch extracted files" });
  }
});

/*
 * ============================================================
 * ANALYZE ONE BINARY BY SCAN ID (OR FIRMWARE ID)
 * ============================================================
 */

router.post("/scanner/binary/:id", async (req, res): Promise<void> => {
  try {
    const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const resolved = await resolveScanId(raw);

    if (!resolved) {
      res.status(404).json({ error: "Scan/Firmware not found" });
      return;
    }

    const [fw] = await db
      .select()
      .from(firmwareTable)
      .where(eq(firmwareTable.id, resolved.firmwareId));

    if (!fw?.filePath) {
      res.status(404).json({ error: "Firmware file not found" });
      return;
    }

    const { filePath: requestedPath } = req.body ?? {};
    let target: string;

    if (requestedPath) {
      const extractPath = fw.extractPath ?? "";
      target = `${extractPath}/${requestedPath}`.replace(/\\/g, "/").replace(/\/+/g, "/");
    } else {
      target = pickBinaryTarget(fw.extractPath ?? "", [fw.filePath]) ?? fw.filePath;
    }

    const result = await analyzeBinary(resolved.firmwareId, target);
    res.json(result);
  } catch (error) {
    console.error("[Binary Analysis Error]", error);
    res.status(500).json({
      error: "Binary analysis failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

export default router;