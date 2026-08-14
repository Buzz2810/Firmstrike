import { Router, type IRouter } from "express";
import { db, firmwareTable, scanResultsTable, vulnerabilitiesTable, malwareHashesTable, cveMatchesTable, activityTable } from "@workspace/db";
import { desc } from "drizzle-orm";

const router: IRouter = Router();

router.get("/dashboard/summary", async (_req, res): Promise<void> => {
  const allFirmware = await db.select().from(firmwareTable);
  const allScans = await db.select().from(scanResultsTable);
  const allVulns = await db.select().from(vulnerabilitiesTable);
  const rawHashes = await db.select().from(malwareHashesTable);
  const rawCves = await db.select().from(cveMatchesTable);

  const hashHashMap = new Map<string, typeof rawHashes[0]>();
  for (const h of rawHashes) {
    const key = `${h.firmwareId}:${h.sha256 || h.fileName}`;
    if (!hashHashMap.has(key)) hashHashMap.set(key, h);
  }
  const allHashes = Array.from(hashHashMap.values());

  const cveMap = new Map<string, typeof rawCves[0]>();
  for (const c of rawCves) {
    const key = `${c.firmwareId}:${c.cveId}`;
    if (!cveMap.has(key)) cveMap.set(key, c);
  }
  const allCves = Array.from(cveMap.values());

  const criticalVulns = allVulns.filter(v => v.severity === "critical").length + allCves.filter(c => c.severity === "critical").length;
  const highVulns = allVulns.filter(v => v.severity === "high").length + allCves.filter(c => c.severity === "high").length;
  const maliciousFiles = allHashes.filter(h => h.isMalicious || (h.threatScore ?? 0) >= 70).length;
  const avgScore = allHashes.length > 0 ? Math.round(allHashes.reduce((s, h) => s + (h.threatScore ?? 0), 0) / allHashes.length) : 0;
  const activeScans = allScans.filter(s => s.status === "running").length;

  res.json({
    totalFirmware: allFirmware.length,
    totalScans: allScans.length,
    criticalVulnerabilities: criticalVulns,
    highVulnerabilities: highVulns,
    averageThreatScore: avgScore,
    activeScan: activeScans > 0,
    recentScans: allScans.filter(s => {
      const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      return s.startedAt > dayAgo;
    }).length,
    maliciousFiles,
    cveMatches: allCves.length,
  });
});

router.get("/dashboard/activity", async (_req, res): Promise<void> => {
  const activities = await db.select().from(activityTable).orderBy(desc(activityTable.timestamp)).limit(20);
  res.json(activities.map(a => ({
    id: a.id,
    type: a.type,
    message: a.message,
    timestamp: a.timestamp.toISOString(),
    severity: a.severity,
    firmwareId: a.firmwareId ?? null,
    firmwareName: a.firmwareName ?? null,
  })));
});

router.get("/dashboard/risk-distribution", async (_req, res): Promise<void> => {
  const vulns = await db.select().from(vulnerabilitiesTable);
  const rawCves = await db.select().from(cveMatchesTable);
  const rawHashes = await db.select().from(malwareHashesTable);

  const cveMap = new Map<string, typeof rawCves[0]>();
  for (const c of rawCves) {
    const key = `${c.firmwareId}:${c.cveId}`;
    if (!cveMap.has(key)) cveMap.set(key, c);
  }
  const cves = Array.from(cveMap.values());

  const hashHashMap = new Map<string, typeof rawHashes[0]>();
  for (const h of rawHashes) {
    const key = `${h.firmwareId}:${h.sha256 || h.fileName}`;
    if (!hashHashMap.has(key)) hashHashMap.set(key, h);
  }
  const malware = Array.from(hashHashMap.values());

  const critical = vulns.filter(v => v.severity === "critical").length + cves.filter(c => c.severity === "critical").length + malware.filter(m => m.isMalicious || m.threatScore >= 70).length;
  const high = vulns.filter(v => v.severity === "high").length + cves.filter(c => c.severity === "high").length + malware.filter(m => !m.isMalicious && m.threatScore >= 50 && m.threatScore < 70).length;
  const medium = vulns.filter(v => v.severity === "medium").length + cves.filter(c => c.severity === "medium").length + malware.filter(m => m.threatScore >= 30 && m.threatScore < 50).length;
  const low = vulns.filter(v => v.severity === "low").length + cves.filter(c => c.severity === "low").length + malware.filter(m => m.threatScore > 0 && m.threatScore < 30).length;

  res.json({ critical, high, medium, low, total: critical + high + medium + low });
});

router.get("/dashboard/threat-trend", async (_req, res): Promise<void> => {
  const allScans = await db.select().from(scanResultsTable);

  function riskToScore(riskLevel: string | null, vulnCount: number | null): number {
    const base = riskLevel === "critical" ? 80 : riskLevel === "high" ? 55 : riskLevel === "medium" ? 35 : 10;
    const bonus = Math.min(20, Math.floor((vulnCount ?? 0) * 2));
    return Math.min(100, base + bonus);
  }

  const scansByDate = new Map<string, typeof allScans>();
  for (const s of allScans) {
    const dateStr = s.startedAt.toISOString().split("T")[0];
    const existing = scansByDate.get(dateStr) ?? [];
    existing.push(s);
    scansByDate.set(dateStr, existing);
  }

  const trend = [];
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split("T")[0];
    const dayScans = scansByDate.get(dateStr) ?? [];

    let dayScore = 0;
    if (dayScans.length > 0) {
      const totalScore = dayScans.reduce((sum, s) => sum + riskToScore(s.riskLevel, s.vulnerabilitiesFound), 0);
      dayScore = Math.round(totalScore / dayScans.length);
    }

    trend.push({ date: dateStr, score: dayScore, firmwareCount: dayScans.length });
  }

  res.json(trend);
});

export default router;
