import path from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir } from "node:fs/promises";

const artifactDir = path.dirname(fileURLToPath(import.meta.url));
export const workspaceRoot = path.resolve(artifactDir, "../../../..");
export const dataRoot = path.join(workspaceRoot, "data");
export const uploadsDir = path.join(dataRoot, "firmware");
export const extractsDir = path.join(dataRoot, "extracted");
export const reportsDir = path.join(dataRoot, "reports");

export async function ensureDataDirs(): Promise<void> {
  await mkdir(uploadsDir, { recursive: true });
  await mkdir(extractsDir, { recursive: true });
  await mkdir(reportsDir, { recursive: true });
}

export function firmwareUploadPath(id: number, filename: string): string {
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
  return path.join(uploadsDir, `${id}_${safe}`);
}

export function firmwareExtractPath(id: number): string {
  return path.join(extractsDir, String(id));
}

export function reportPath(firmwareId: number): string {
  return path.join(reportsDir, `firmware-${firmwareId}-report.txt`);
}

export function reportPdfPath(firmwareId: number): string {
  return path.join(reportsDir, `firmware-${firmwareId}-report.pdf`);
}