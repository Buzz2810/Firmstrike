import { Router, type IRouter } from "express";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { unlink } from "node:fs/promises";
import multer from "multer";
import { db, firmwareTable, activityTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { ensureDataDirs, firmwareUploadPath } from "../lib/paths.js";

const router: IRouter = Router();
const MAX_FIRMWARE_SIZE = 1 * 1024 * 1024 * 1024 * 1024;
const upload = multer({ dest: "/tmp/viv-uploads", limits: { fileSize: MAX_FIRMWARE_SIZE } });

function toFirmwareResponse(f: typeof firmwareTable.$inferSelect) {
  return {
    id: f.id,
    name: f.name,
    uploadedAt: f.uploadedAt.toISOString(),
    architecture: f.architecture,
    hashValue: f.hashValue,
    status: f.status,
    fileSize: f.fileSize,
    vendor: f.vendor ?? null,
    version: f.version ?? null,
  };
}

router.get("/firmware", async (_req, res): Promise<void> => {
  const all = await db.select().from(firmwareTable).orderBy(firmwareTable.uploadedAt);
  res.json(all.map(toFirmwareResponse));
});

router.post("/firmware", async (req, res): Promise<void> => {
  const { name, hashValue, fileSize, architecture, vendor, version } = req.body;
  if (!name || !hashValue || !fileSize) {
    res.status(400).json({ error: "Missing required fields" });
    return;
  }
  const [fw] = await db.insert(firmwareTable).values({
    name,
    hashValue,
    fileSize,
    architecture: architecture || "UNKNOWN",
    vendor: vendor || null,
    version: version || null,
    status: "pending",
  }).returning();

  await db.insert(activityTable).values({
    type: "scan_started",
    message: `Firmware "${fw.name}" uploaded and queued for analysis`,
    severity: "info",
    firmwareId: fw.id,
    firmwareName: fw.name,
  });

  res.status(201).json(toFirmwareResponse(fw));
});

router.post("/firmware/upload", upload.single("file"), async (req, res): Promise<void> => {
  if (!req.file) {
    res.status(400).json({ error: "No firmware file provided" });
    return;
  }

  try {
    await ensureDataDirs();

    const hash = createHash("sha256");
    await new Promise<void>((resolve, reject) => {
      createReadStream(req.file!.path)
        .on("data", (chunk: Buffer) => hash.update(chunk))
        .on("end", () => resolve())
        .on("error", reject);
    });
    const hashValue = hash.digest("hex");
    const originalName = req.file.originalname || `firmware_${Date.now()}.bin`;

    const [fw] = await db.insert(firmwareTable).values({
      name: originalName,
      hashValue,
      fileSize: req.file.size,
      architecture: "UNKNOWN",
      vendor: null,
      version: null,
      status: "pending",
    }).returning();

    const destPath = firmwareUploadPath(fw.id, originalName);
    const { rename } = await import("node:fs/promises");
    await rename(req.file.path, destPath);

    await db.update(firmwareTable).set({ filePath: destPath }).where(eq(firmwareTable.id, fw.id));

    await db.insert(activityTable).values({
      type: "scan_started",
      message: `Firmware "${originalName}" uploaded (${(req.file.size / 1024 / 1024).toFixed(1)} MB)`,
      severity: "info",
      firmwareId: fw.id,
      firmwareName: originalName,
    });

    res.status(201).json(toFirmwareResponse({ ...fw, filePath: destPath }));
  } catch (err) {
    await unlink(req.file.path).catch(() => undefined);
    const message = err instanceof Error ? err.message : "Unknown upload error";
    if (message.includes("Failed query") || message.includes("relation") || message.includes("column")) {
      res.status(503).json({ error: "Upload service is temporarily unavailable because the database schema is unavailable or out of date." });
      return;
    }
    res.status(500).json({ error: "Upload failed while saving the firmware file." });
  }
});

router.get("/firmware/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(raw, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }
  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, id));
  if (!fw) { res.status(404).json({ error: "Firmware not found" }); return; }
  res.json(toFirmwareResponse(fw));
});

router.delete("/firmware/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(raw, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, id));
  if (fw?.filePath) {
    try { await unlink(fw.filePath); } catch { /* ignore */ }
  }

  await db.delete(firmwareTable).where(eq(firmwareTable.id, id));
  res.sendStatus(204);
});

export default router;
