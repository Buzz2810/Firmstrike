import { Router, type IRouter } from "express";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  unlink,
  rename,
  copyFile,
  mkdir,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
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
  firmwareExtractPath,
} from "../lib/paths.js";

const router: IRouter = Router();

/*
 * ============================================================
 * UPLOAD CONFIGURATION
 * ============================================================
 *
 * Maximum firmware size: 2 GB
 *
 * No fileFilter is intentionally used.
 *
 * Supported examples:
 * .bin
 * .img
 * .trx
 * .chk
 * .zip
 * .gz
 * .tar
 * .iso
 * .rom
 * .fw
 * .firmware
 * .dd
 *
 * and other firmware/image formats.
 */

const tempUploadDirectory = path.join(
  os.tmpdir(),
  "firmstrike-uploads",
);

const upload = multer({
  dest: tempUploadDirectory,

  limits: {
    fileSize:
      2 * 1024 * 1024 * 1024,
  },
});

/*
 * ============================================================
 * RESPONSE FORMAT
 * ============================================================
 */

function toFirmwareResponse(
  f: typeof firmwareTable.$inferSelect,
) {
  return {
    id: f.id,

    name: f.name,

    uploadedAt:
      f.uploadedAt.toISOString(),

    architecture:
      f.architecture,

    hashValue:
      f.hashValue,

    status:
      f.status,

    fileSize:
      f.fileSize,

    vendor:
      f.vendor ?? null,

    version:
      f.version ?? null,
  };
}

/*
 * ============================================================
 * SAFE FILE MOVE
 * ============================================================
 *
 * Windows can throw:
 *
 * EXDEV: cross-device link not permitted
 *
 * when rename() attempts to move a file from C:
 * to D:.
 *
 * Example:
 *
 * C:\Users\...\Temp\firmstrike-uploads\file
 *
 *          ->
 *
 * D:\Desktop\Number1\Firmstrike_final\data\firmware\...
 *
 * In that situation we copy the file instead and then
 * delete the temporary file.
 */

async function moveUploadedFile(
  sourcePath: string,
  destinationPath: string,
): Promise<void> {
  try {
    /*
     * First try rename().
     *
     * This is faster when source and destination are
     * located on the same filesystem.
     */
    await rename(
      sourcePath,
      destinationPath,
    );

    console.log(
      "[Firmware Upload] File moved using rename()",
    );

    return;
  } catch (error: any) {
    /*
     * EXDEV means source and destination are on
     * different filesystems/drives.
     */
    if (
      !error ||
      error.code !== "EXDEV"
    ) {
      throw error;
    }

    console.log(
      "[Firmware Upload] Cross-device move detected.",
    );

    console.log(
      "[Firmware Upload] Falling back to copyFile().",
    );
  }

  /*
   * Copy the file completely before deleting
   * the temporary upload.
   */
  await copyFile(
    sourcePath,
    destinationPath,
  );

  /*
   * Only delete the temporary file after
   * copyFile() succeeds.
   */
  await unlink(sourcePath);

  console.log(
    "[Firmware Upload] Cross-device copy completed.",
  );
}

/*
 * ============================================================
 * GET ALL FIRMWARE
 * ============================================================
 */

router.get(
  "/firmware",
  async (_req, res): Promise<void> => {
    try {
      const all = await db
        .select()
        .from(firmwareTable)
        .orderBy(
          firmwareTable.uploadedAt,
        );

      res.json(
        all.map(toFirmwareResponse),
      );
    } catch (error) {
      console.error(
        "[Firmware List Error]",
        error,
      );

      res.status(500).json({
        error:
          "Failed to fetch firmware",
      });
    }
  },
);

/*
 * ============================================================
 * POST FIRMWARE METADATA
 * ============================================================
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

      if (
        !name ||
        !hashValue ||
        !fileSize
      ) {
        res.status(400).json({
          error:
            "Missing required fields",
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
            architecture ||
            "UNKNOWN",

          vendor:
            vendor || null,

          version:
            version || null,

          status: "pending",
        })
        .returning();

      await db
        .insert(activityTable)
        .values({
          type: "scan_started",

          message:
            `Firmware "${fw.name}" uploaded and queued for analysis`,

          severity: "info",

          firmwareId:
            fw.id,

          firmwareName:
            fw.name,
        });

      res
        .status(201)
        .json(
          toFirmwareResponse(fw),
        );
    } catch (error) {
      console.error(
        "[Firmware Metadata Error]",
        error,
      );

      res.status(500).json({
        error:
          "Failed to create firmware record",
      });
    }
  },
);

/*
 * ============================================================
 * POST FIRMWARE FILE
 * ============================================================
 *
 * This endpoint:
 *
 * 1. Receives the uploaded firmware.
 * 2. Calculates SHA-256.
 * 3. Creates the firmware database record.
 * 4. Saves the permanent firmware file.
 * 5. Stores the extraction path.
 * 6. Returns the firmware record.
 *
 * The actual scan is started separately through:
 *
 * POST /scanner/start
 *
 * This prevents the upload request from blocking.
 */

router.post(
  "/firmware/upload",

  upload.single("file"),

  async (
    req,
    res,
  ): Promise<void> => {
    /*
     * Multer did not receive a file.
     */
    if (!req.file) {
      res.status(400).json({
        error:
          "No firmware file provided",
      });

      return;
    }

    /*
     * Keep track of the temporary file so that
     * it can be deleted if anything fails.
     */
    let tempPath =
      req.file.path;

    try {
      /*
       * ======================================================
       * ENSURE DATA DIRECTORIES
       * ======================================================
       */

      await ensureDataDirs();

      /*
       * ======================================================
       * SHA-256
       * ======================================================
       */

      const hash =
        createHash("sha256");

      await new Promise<void>(
        (
          resolve,
          reject,
        ) => {
          const stream =
            createReadStream(
              req.file!.path,
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
            (error) => {
              reject(error);
            },
          );
        },
      );

      const hashValue =
        hash.digest("hex");

      /*
       * ======================================================
       * ORIGINAL FILE NAME
       * ======================================================
       */

      const originalName =
        req.file.originalname ||
        `firmware_${Date.now()}.bin`;

      /*
       * ======================================================
       * CREATE FIRMWARE DATABASE RECORD
       * ======================================================
       */

      const [fw] = await db
        .insert(firmwareTable)
        .values({
          name:
            originalName,

          hashValue,

          fileSize:
            req.file.size,

          architecture:
            "UNKNOWN",

          vendor:
            null,

          version:
            null,

          status:
            "pending",
        })
        .returning();

      /*
       * ======================================================
       * PERMANENT FILE PATH
       * ======================================================
       */

      const destPath =
        firmwareUploadPath(
          fw.id,
          originalName,
        );

      /*
       * Extraction directory.
       *
       * Example:
       *
       * D:\Desktop\Number1\Firmstrike_final
       * \data\firmware\182\extracted
       */

      const extractPath =
        firmwareExtractPath(
          fw.id,
        );

      console.log("");
      console.log(
        "========================================",
      );
      console.log(
        "        FIRMWARE FILE STORAGE",
      );
      console.log(
        "========================================",
      );
      console.log(
        "Firmware ID :",
        fw.id,
      );
      console.log(
        "Original    :",
        originalName,
      );
      console.log(
        "Temporary   :",
        tempPath,
      );
      console.log(
        "Destination :",
        destPath,
      );
      console.log(
        "Extract     :",
        extractPath,
      );
      console.log(
        "========================================",
      );
      console.log("");

      /*
       * ======================================================
       * CREATE DESTINATION DIRECTORY
       * ======================================================
       */

      const destinationDirectory =
        path.dirname(
          destPath,
        );

      await mkdir(
        destinationDirectory,
        {
          recursive: true,
        },
      );

      /*
       * ======================================================
       * MOVE/COPY TEMP FILE
       * ======================================================
       *
       * This handles both:
       *
       * C: -> C:
       *
       * and:
       *
       * C: -> D:
       *
       * on Windows.
       */

      await moveUploadedFile(
        tempPath,
        destPath,
      );

      /*
       * The temporary file has now been moved
       * or copied and deleted.
       */
      tempPath = "";

      /*
       * ======================================================
       * UPDATE DATABASE WITH FILE PATH
       * ======================================================
       */

      const [updatedFirmware] =
        await db
          .update(
            firmwareTable,
          )
          .set({
            filePath:
              destPath,

            extractPath:
              extractPath,
          })
          .where(
            eq(
              firmwareTable.id,
              fw.id,
            ),
          )
          .returning();

      /*
       * ======================================================
       * ACTIVITY LOG
       * ======================================================
       */

      await db
        .insert(activityTable)
        .values({
          type:
            "scan_started",

          message:
            `Firmware "${originalName}" uploaded (${(
              req.file.size /
              1024 /
              1024
            ).toFixed(1)} MB)`,

          severity:
            "info",

          firmwareId:
            fw.id,

          firmwareName:
            originalName,
        });

      /*
       * ======================================================
       * RETURN SUCCESS
       * ======================================================
       */

      res
        .status(201)
        .json(
          toFirmwareResponse(
            updatedFirmware,
          ),
        );
    } catch (error) {
      /*
       * ======================================================
       * UPLOAD ERROR
       * ======================================================
       */

      console.error(
        "[Firmware Upload Error]",
        error,
      );

      /*
       * ======================================================
       * CLEANUP TEMPORARY FILE
       * ======================================================
       *
       * If the file was successfully moved/copied,
       * tempPath is "" and nothing happens.
       *
       * If something failed before that,
       * delete the temporary upload.
       */

      if (tempPath) {
        try {
          await unlink(
            tempPath,
          );
        } catch {
          /*
           * Ignore cleanup failure.
           */
        }
      }

      res.status(500).json({
        error:
          "Firmware upload failed",

        details:
          error instanceof Error
            ? error.message
            : String(error),
      });
    }
  },
);

/*
 * ============================================================
 * GET FIRMWARE BY ID
 * ============================================================
 */

router.get(
  "/firmware/:id",

  async (
    req,
    res,
  ): Promise<void> => {
    try {
      const raw =
        Array.isArray(
          req.params.id,
        )
          ? req.params.id[0]
          : req.params.id;

      const id =
        parseInt(
          raw,
          10,
        );

      if (
        Number.isNaN(id)
      ) {
        res.status(400).json({
          error:
            "Invalid id",
        });

        return;
      }

      const [fw] =
        await db
          .select()
          .from(
            firmwareTable,
          )
          .where(
            eq(
              firmwareTable.id,
              id,
            ),
          );

      if (!fw) {
        res.status(404).json({
          error:
            "Firmware not found",
        });

        return;
      }

      res.json(
        toFirmwareResponse(fw),
      );
    } catch (error) {
      console.error(
        "[Firmware Get Error]",
        error,
      );

      res.status(500).json({
        error:
          "Failed to fetch firmware",
      });
    }
  },
);

/*
 * ============================================================
 * DELETE FIRMWARE
 * ============================================================
 */

router.delete(
  "/firmware/:id",

  async (
    req,
    res,
  ): Promise<void> => {
    try {
      const raw =
        Array.isArray(
          req.params.id,
        )
          ? req.params.id[0]
          : req.params.id;

      const id =
        parseInt(
          raw,
          10,
        );

      if (
        Number.isNaN(id)
      ) {
        res.status(400).json({
          error:
            "Invalid id",
        });

        return;
      }

      const [fw] =
        await db
          .select()
          .from(
            firmwareTable,
          )
          .where(
            eq(
              firmwareTable.id,
              id,
            ),
          );

      if (!fw) {
        res.status(404).json({
          error:
            "Firmware not found",
        });

        return;
      }

      /*
       * Delete the physical firmware file.
       */

      if (fw.filePath) {
        try {
          await unlink(
            fw.filePath,
          );
        } catch {
          /*
           * Ignore missing file.
           */
        }
      }

      /*
       * Delete the database record.
       */

      await db
        .delete(
          firmwareTable,
        )
        .where(
          eq(
            firmwareTable.id,
            id,
          ),
        );

      res.sendStatus(204);
    } catch (error) {
      console.error(
        "[Firmware Delete Error]",
        error,
      );

      res.status(500).json({
        error:
          "Failed to delete firmware",
      });
    }
  },
);

export default router;