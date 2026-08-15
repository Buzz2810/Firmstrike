import { Router, type IRouter } from "express";
import { db, cveMatchesTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { resolveScanId } from "../lib/scans.js";

const router: IRouter = Router();

async function getMatchesForScan(scanId: number) {
  const rawMatches = await db
    .select()
    .from(cveMatchesTable)
    .where(eq(cveMatchesTable.scanId, scanId));

  const map = new Map<string, typeof rawMatches[0]>();
  for (const m of rawMatches) {
    if (!map.has(m.cveId)) {
      map.set(m.cveId, m);
    }
  }

  return Array.from(map.values());
}

router.get("/cve/matches/:id", async (req, res): Promise<void> => {
  try {
    const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const resolved = await resolveScanId(raw);
    if (!resolved) {
      res.json([]);
      return;
    }

    const matches = await getMatchesForScan(resolved.scanId);
    res.json(matches);
  } catch (err) {
    console.error("Error fetching CVE matches:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/cve/scores/:id", async (req, res): Promise<void> => {
  try {
    const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const resolved = await resolveScanId(raw);
    if (!resolved) {
      res.json({ scanId: 0, critical: 0, high: 0, medium: 0, low: 0, averageScore: 0 });
      return;
    }

    const matches = await getMatchesForScan(resolved.scanId);

    const critical = matches.filter((m) => m.severity === "critical").length;
    const high = matches.filter((m) => m.severity === "high").length;
    const medium = matches.filter((m) => m.severity === "medium").length;
    const low = matches.filter((m) => m.severity === "low").length;
    const avgScore =
      matches.length > 0
        ? matches.reduce((sum, m) => sum + Number(m.cvssScore), 0) / matches.length
        : 0;

    res.json({
      scanId: resolved.scanId,
      firmwareId: resolved.firmwareId,
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