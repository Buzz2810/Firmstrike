import { Router, type IRouter } from "express";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { unlink } from "node:fs/promises";
import multer from "multer";

import {
  db,
  firmwareTable,
  activityTable,
} from "@workspace/db";

import { eq } from "drizzle-orm";

import {
  ensureDataDirs,
  firmwareUploadPath,
} from "../lib/paths.js";

const router: IRouter = Router();

/**
 * Maximum firmware file size.
 *
 * 2 GB is enough for normal IoT/router firmware images
 * while preventing accidental extremely large uploads.
 */
const MAX_FIRMWARE_SIZE = 2 * 1024 * 1024 * 1024;

/**
 * Multer upload configuration.
 *
 * No fileFilter is intentionally used.
 *
 * This allows:
 * .bin
 * .img
 * .trx
 * .chk
 * .fw
 * .firmware
 * .rom
 * .iso
 * .gz
 * .tar
 * .zip
 * and other firmware/image/archive formats.
 */
const upload = multer({
  dest: "/tmp/viv-uploads",
  limits: {
    fileSize: MAX_FIRMWARE_SIZE,
  },
});

/**
 * Convert database firmware record into the API response format.
 */
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
 * GET /firmware
 *
 * Return all uploaded firmware files.
 */
router.get(
  "/firmware",
  async (_req, res): Promise<void> => {
    try {
      const all = await db
        .select()
        .from(firmwareTable)
        .orderBy(firmwareTable.uploadedAt);

      res.json(all.map(toFirmwareResponse));
    } catch (err) {
      console.error(
        "[Firmware List Error]",
        err,
      );

      res.status(500).json({
        error: "Failed to load firmware list",
      });
    }
  },
);

/**
 * POST /firmware
 *
 * Creates a firmware metadata record.
 *
 * This endpoint is kept for compatibility with existing
 * frontend/API code.
 */
router.post(
  "/firmware",
  async (req, res): Promise<void> => {
    try {
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
          architecture:
            architecture || "UNKNOWN",
          vendor: vendor || null,
          version: version || null,
          status: "pending",
        })
        .returning();

      await db.insert(activityTable).values({
        type: "scan_started",
        message:
          `Firmware "${fw.name}" uploaded and queued for analysis`,
        severity: "info",
        firmwareId: fw.id,
        firmwareName: fw.name,
      });

      res.status(201).json(
        toFirmwareResponse(fw),
      );
    } catch (err) {
      console.error(
        "[Firmware Metadata Error]",
        err,
      );

      res.status(500).json({
        error: "Failed to create firmware record",
      });
    }
  },
);

/**
 * POST /firmware/upload
 *
 * Upload firmware file.
 *
 * IMPORTANT:
 * This endpoint ONLY:
 *
 * 1. Receives the file
 * 2. Calculates SHA-256
 * 3. Creates the database record
 * 4. Moves the file to permanent storage
 * 5. Returns the firmware record
 *
 * It DOES NOT run extraction or scanning.
 *
 * Extraction is handled by scan-pipeline.ts when
 * /scanner/start is called.
 */
router.post(
  "/firmware/upload",
  upload.single("file"),
  async (req, res): Promise<void> => {
    /**
     * Multer did not receive a file.
     */
    if (!req.file) {
      res.status(400).json({
        error: "No firmware file provided",
      });

      return;
    }

    /**
     * Save this before entering try because the temporary
     * file may need to be deleted if something fails.
     */
    const temporaryFilePath = req.file.path;

    try {
      /**
       * Make sure permanent firmware directories exist.
       */
      await ensureDataDirs();

      /**
       * Calculate SHA-256 hash of uploaded firmware.
       */
      const hash = createHash("sha256");

      await new Promise<void>(
        (resolve, reject) => {
          const stream =
            createReadStream(
              temporaryFilePath,
            );

          stream.on(
            "data",
            (chunk: Buffer) => {
              hash.update(chunk);
            },
          );

          stream.on(
            "end",
            () => {
              resolve();
            },
          );

          stream.on(
            "error",
            reject,
          );
        },
      );

      const hashValue =
        hash.digest("hex");

      /**
       * Keep the original firmware filename.
       */
      const originalName =
        req.file.originalname?.trim() ||
        `firmware_${Date.now()}.bin`;

      /**
       * Create database record.
       *
       * Status remains "pending".
       *
       * The scanner will later change/update the status.
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
       * Determine permanent firmware path.
       */
      const destPath =
        firmwareUploadPath(
          fw.id,
          originalName,
        );

      /**
       * Move temporary upload into permanent
       * firmware storage.
       */
      const { rename } =
        await import(
          "node:fs/promises"
        );

      await rename(
        temporaryFilePath,
        destPath,
      );

      /**
       * Save permanent file path in database.
       */
      await db
        .update(firmwareTable)
        .set({
          filePath: destPath,
        })
        .where(
          eq(
            firmwareTable.id,
            fw.id,
          ),
        );

      /**
       * Record upload activity.
       *
       * Do NOT call this "scan completed".
       * Scanning has not happened yet.
       */
      await db.insert(
        activityTable,
      ).values({
        type: "scan_started",
        message:
          `Firmware "${originalName}" uploaded and queued for analysis`,
        severity: "info",
        firmwareId: fw.id,
        firmwareName: originalName,
      });

      /**
       * Return the newly created firmware record.
       *
       * The frontend needs the ID from this response
       * to start the scanner.
       */
      res.status(201).json(
        toFirmwareResponse({
          ...fw,
          filePath: destPath,
        }),
      );
    } catch (err) {
      console.error(
        "[Firmware Upload Error]",
        err,
      );

      /**
       * Remove temporary file if upload failed
       * before it was moved to permanent storage.
       */
      try {
        await unlink(
          temporaryFilePath,
        );
      } catch {
        // Ignore cleanup failure.
      }

      const message =
        err instanceof Error
          ? err.message
          : "Unknown upload error";

      /**
       * Database/schema errors.
       */
      if (
        message.includes("Failed query") ||
        message.includes("relation") ||
        message.includes("column") ||
        message.includes("database")
      ) {
        res.status(503).json({
          error:
            "Upload service is temporarily unavailable because the database schema is unavailable or out of date.",
        });

        return;
      }

      /**
       * File-size error.
       */
      if (
        message
          .toLowerCase()
          .includes("file too large")
      ) {
        res.status(413).json({
          error:
            "Firmware file is too large. Maximum allowed size is 2 GB.",
        });

        return;
      }

      res.status(500).json({
        error:
          "Upload failed while saving the firmware file.",
      });
    }
  },
);

/**
 * GET /firmware/:id
 *
 * Return one firmware record.
 */
router.get(
  "/firmware/:id",
  async (req, res): Promise<void> => {
    try {
      const raw =
        Array.isArray(req.params.id)
          ? req.params.id[0]
          : req.params.id;

      const id = parseInt(
        raw,
        10,
      );

      if (isNaN(id)) {
        res.status(400).json({
          error: "Invalid id",
        });

        return;
      }

      const [fw] = await db
        .select()
        .from(firmwareTable)
        .where(
          eq(
            firmwareTable.id,
            id,
          ),
        );

      if (!fw) {
        res.status(404).json({
          error: "Firmware not found",
        });

        return;
      }

      res.json(
        toFirmwareResponse(fw),
      );
    } catch (err) {
      console.error(
        "[Firmware Get Error]",
        err,
      );

      res.status(500).json({
        error: "Failed to load firmware",
      });
    }
  },
);

/**
 * DELETE /firmware/:id
 *
 * Delete firmware database record and
 * its uploaded file.
 */
router.delete(
  "/firmware/:id",
  async (req, res): Promise<void> => {
    try {
      const raw =
        Array.isArray(req.params.id)
          ? req.params.id[0]
          : req.params.id;

      const id = parseInt(
        raw,
        10,
      );

      if (isNaN(id)) {
        res.status(400).json({
          error: "Invalid id",
        });

        return;
      }

      const [fw] = await db
        .select()
        .from(firmwareTable)
        .where(
          eq(
            firmwareTable.id,
            id,
          ),
        );

      if (!fw) {
        res.status(404).json({
          error: "Firmware not found",
        });

        return;
      }

      /**
       * Delete physical firmware file.
       */
      if (fw.filePath) {
        try {
          await unlink(
            fw.filePath,
          );
        } catch {
          // File may already be deleted.
        }
      }

      /**
       * Delete database record.
       */
      await db
        .delete(firmwareTable)
        .where(
          eq(
            firmwareTable.id,
            id,
          ),
        );

      res.sendStatus(204);
    } catch (err) {
      console.error(
        "[Firmware Delete Error]",
        err,
      );

      res.status(500).json({
        error: "Failed to delete firmware",
      });
    }
  },
);

export default router;