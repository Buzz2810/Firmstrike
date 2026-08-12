import { Router, type IRouter } from "express";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { unlink } from "node:fs/promises";
import multer from "multer";
import { db, firmwareTable, activityTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { ensureDataDirs, firmwareUploadPath, firmwareExtractPath } from "../lib/paths.js";
import { extractFirmware } from "../services/extraction.js";

const router: IRouter = Router();

/**
 * Firmware upload configuration
 *
 * Maximum file size: 2 GB
 *
 * No fileFilter is used intentionally.
 * This allows:
 * .bin
 * .img
 * .dd
 * .fw
 * .firmware
 * .efi
 * .rom
 * .iso
 * .gz
 * .tar
 * .zip
 * and any other firmware/image/archive file.
 */
const upload = multer({
  dest: "/tmp/viv-uploads",
  limits: {
    fileSize: 2 * 1024 * 1024 * 1024, // 2 GB
  },
});

function toFirmwareResponse(
  f: typeof firmwareTable.$inferSelect,
) {
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

/**
 * GET all firmware
 */
router.get("/firmware", async (_req, res): Promise<void> => {
  const all = await db
    .select()
    .from(firmwareTable)
    .orderBy(firmwareTable.uploadedAt);

  res.json(all.map(toFirmwareResponse));
});

/**
 * POST firmware metadata
 */
router.post("/firmware", async (req, res): Promise<void> => {
  const {
    name,
    hashValue,
    fileSize,
    architecture,
    vendor,
    version,
  } = req.body;

  if (!name || !hashValue || !fileSize) {
    res.status(400).json({
      error: "Missing required fields",
    });
    return;
  }

  const [fw] = await db
    .insert(firmwareTable)
    .values({
      name,
      hashValue,
      fileSize,
      architecture: architecture || "UNKNOWN",
      vendor: vendor || null,
      version: version || null,
      status: "pending",
    })
    .returning();

  await db.insert(activityTable).values({
    type: "scan_started",
    message: `Firmware "${fw.name}" uploaded and queued for analysis`,
    severity: "info",
    firmwareId: fw.id,
    firmwareName: fw.name,
  });

  res.status(201).json(toFirmwareResponse(fw));
});

router.post(
  "/firmware/upload",
  upload.single("file"),
  async (req, res): Promise<void> => {
    if (!req.file) {
      res.status(400).json({
        error: "No firmware file provided",
      });
      return;
    }

    try {
      await ensureDataDirs();

      const hash = createHash("sha256");

      await new Promise<void>((resolve, reject) => {
        const stream = createReadStream(req.file!.path);

        stream.on("data", (chunk: Buffer) => {
          hash.update(chunk);
        });

        stream.on("end", resolve);
        stream.on("error", reject);
      });

      const hashValue = hash.digest("hex");

      const originalName =
        req.file.originalname ||
        `firmware_${Date.now()}.bin`;

      /**
       * Create DB record.
       */
      const [fw] = await db
        .insert(firmwareTable)
        .values({
          name: originalName,
          hashValue,
          fileSize: req.file.size,
          architecture: "UNKNOWN",
          vendor: null,
          version: null,
          status: "pending",
        })
        .returning();

      /**
       * Move uploaded temporary file to permanent
       * firmware storage.
       */
      const destPath = firmwareUploadPath(
        fw.id,
        originalName,
      );

      const { rename } = await import("node:fs/promises");

      await rename(
        req.file.path,
        destPath,
      );

  const extractPath =
  firmwareExtractPath(fw.id);

await db
  .update(firmwareTable)
  .set({
    filePath: destPath,
    extractPath,
  })
  .where(
    eq(
      firmwareTable.id,
      fw.id,
    ),
  );
  const extractionResult = await extractFirmware(
  destPath,
  extractPath,
);

const {
  architecture,
  vendor,
  version,
} = extractionResult;
res.status(201).json(
  toFirmwareResponse({
    ...fw,
    filePath: destPath,
    extractPath,
    architecture: "UNKNOWN",
    vendor: null,
    version: null,
  }),
);

      await db
        .update(firmwareTable)
        .set({
          filePath: destPath,
          extractPath,
          architecture,
          vendor,
          version,
        })
        .where(eq(firmwareTable.id, fw.id));

      await db.insert(activityTable).values({
        type: "scan_started",
        message: `Firmware "${originalName}" uploaded (${(
          req.file.size /
          1024 /
          1024
        ).toFixed(1)} MB)`,
        severity: "info",
        firmwareId: fw.id,
        firmwareName: originalName,
      });
res
  .status(201)
  .json(
    toFirmwareResponse({
      ...fw,
      filePath: destPath,
      extractPath,
      architecture,
      vendor,
      version,
    }),
  );
    } catch (err) {
      console.error(
        "[Firmware Upload Error]",
        err,
      );

      /**
       * Remove temporary upload if something
       * failed after multer created it.
       */
      try {
        if (req.file?.path) {
          await unlink(req.file.path);
        }
      } catch {
        // ignore cleanup errors
      }

      res.status(500).json({
        error: "Firmware upload failed",
      });
    }
  },
);

/**
 * GET firmware by ID
 */
router.get(
  "/firmware/:id",
  async (req, res): Promise<void> => {
    const raw = Array.isArray(req.params.id)
      ? req.params.id[0]
      : req.params.id;

    const id = parseInt(raw, 10);

    if (isNaN(id)) {
      res.status(400).json({
        error: "Invalid id",
      });
      return;
    }

    const [fw] = await db
      .select()
      .from(firmwareTable)
      .where(eq(firmwareTable.id, id));

    if (!fw) {
      res.status(404).json({
        error: "Firmware not found",
      });
      return;
    }

    res.json(toFirmwareResponse(fw));
  },
);

/**
 * DELETE firmware
 */
router.delete(
  "/firmware/:id",
  async (req, res): Promise<void> => {
    const raw = Array.isArray(req.params.id)
      ? req.params.id[0]
      : req.params.id;

    const id = parseInt(raw, 10);

    if (isNaN(id)) {
      res.status(400).json({
        error: "Invalid id",
      });
      return;
    }

    const [fw] = await db
      .select()
      .from(firmwareTable)
      .where(eq(firmwareTable.id, id));

    if (fw?.filePath) {
      try {
        await unlink(fw.filePath);
      } catch {
        // ignore
      }
    }

    await db
      .delete(firmwareTable)
      .where(eq(firmwareTable.id, id));

    res.sendStatus(204);
  },
);

export default router;