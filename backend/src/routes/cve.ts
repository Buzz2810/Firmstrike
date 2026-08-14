import { Router, type IRouter } from "express";
import { db, cveMatchesTable } from "@workspace/db";
import { eq } from "drizzle-orm";

const router: IRouter = Router();

function parseFirmwareId(raw: string | string[]): number | null {
  const value = Array.isArray(raw) ? raw[0] : raw;
  const firmwareId = parseInt(value, 10);
  if (isNaN(firmwareId) || firmwareId <= 0) return null;
  return firmwareId;
}

async function getMatchesForFirmware(firmwareId: number) {
  const rawMatches = await db
    .select()
    .from(cveMatchesTable)
    .where(eq(cveMatchesTable.firmwareId, firmwareId));

  const map = new Map<string, typeof rawMatches[0]>();
  for (const m of rawMatches) {
    if (!map.has(m.cveId)) {
      map.set(m.cveId, m);
    }
  }

  return Array.from(map.values());
}

router.get("/cve/matches/:firmwareId", async (req, res): Promise<void> => {
  try {
    const firmwareId = parseFirmwareId(req.params.firmwareId);
    if (firmwareId === null) {
      res.status(400).json({ error: "Invalid firmwareId" });
      return;
    }

    const matches = await getMatchesForFirmware(firmwareId);
    res.json(matches);
  } catch (err) {
    console.error("Error fetching CVE matches:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/cve/scores/:firmwareId", async (req, res): Promise<void> => {
  try {
    const firmwareId = parseFirmwareId(req.params.firmwareId);
    if (firmwareId === null) {
      res.status(400).json({ error: "Invalid firmwareId" });
      return;
    }
    const matches = await getMatchesForFirmware(firmwareId);

    const critical = matches.filter((m) => m.severity === "critical").length;
    const high = matches.filter((m) => m.severity === "high").length;
    const medium = matches.filter((m) => m.severity === "medium").length;
    const low = matches.filter((m) => m.severity === "low").length;
    const avgScore =
      matches.length > 0
        ? matches.reduce((sum, m) => sum + Number(m.cvssScore), 0) / matches.length
        : 0;

    res.json({
      firmwareId,
      critical,
      high,
      medium,
      low,
      averageScore: Math.round(avgScore * 10) / 10,
    });
  } catch (err) {
    console.error("Error fetching CVE scores:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;