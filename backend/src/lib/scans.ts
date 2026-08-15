import { db, scanResultsTable } from "@workspace/db";
import { eq, desc } from "drizzle-orm";

export async function resolveScanId(rawId: string | number): Promise<{ scanId: number; firmwareId: number } | null> {
  const numericId = typeof rawId === "number" ? rawId : parseInt(rawId, 10);
  if (isNaN(numericId) || numericId <= 0) return null;

  // 1. Try fetching by scan ID first
  const [byScanId] = await db
    .select()
    .from(scanResultsTable)
    .where(eq(scanResultsTable.id, numericId));

  if (byScanId) {
    return { scanId: byScanId.id, firmwareId: byScanId.firmwareId };
  }

  // 2. Fallback: try fetching latest scan by firmware ID
  const [byFirmwareId] = await db
    .select()
    .from(scanResultsTable)
    .where(eq(scanResultsTable.firmwareId, numericId))
    .orderBy(desc(scanResultsTable.id))
    .limit(1);

  if (byFirmwareId) {
    return { scanId: byFirmwareId.id, firmwareId: byFirmwareId.firmwareId };
  }

  return null;
}
