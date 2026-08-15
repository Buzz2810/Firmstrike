import { Router, type IRouter } from "express";
import {
  db,
  vulnerabilitiesTable,
  hardcodedSecretsTable,
  dangerousFunctionsTable,
  cveMatchesTable,
  malwareHashesTable,
} from "@workspace/db";
import { eq } from "drizzle-orm";
import { resolveScanId } from "../lib/scans.js";

const router: IRouter = Router();

router.get("/security/vulnerabilities/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const resolved = await resolveScanId(raw);
  if (!resolved) { res.json([]); return; }

  const vulns = await db
    .select()
    .from(vulnerabilitiesTable)
    .where(eq(vulnerabilitiesTable.scanId, resolved.scanId));

  res.json(vulns.map(v => ({
    ...v,
    cvssScore: v.cvssScore ?? null,
    discoveredAt: v.discoveredAt.toISOString(),
  })));
});

router.get("/security/score/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const resolved = await resolveScanId(raw);
  if (!resolved) {
    res.json({ overallScore: 100, riskLevel: "low", totalFindings: 0 });
    return;
  }

  const [vulns, secrets, fns, cves, malware] = await Promise.all([
    db.select().from(vulnerabilitiesTable).where(eq(vulnerabilitiesTable.scanId, resolved.scanId)),
    db.select().from(hardcodedSecretsTable).where(eq(hardcodedSecretsTable.scanId, resolved.scanId)),
    db.select().from(dangerousFunctionsTable).where(eq(dangerousFunctionsTable.scanId, resolved.scanId)),
    db.select().from(cveMatchesTable).where(eq(cveMatchesTable.scanId, resolved.scanId)),
    db.select().from(malwareHashesTable).where(eq(malwareHashesTable.scanId, resolved.scanId)),
  ]);

  const criticalCount = vulns.filter(v => v.severity === "critical").length;
  const highCount = vulns.filter(v => v.severity === "high").length;
  const mediumCount = vulns.filter(v => v.severity === "medium").length;
  const lowCount = vulns.filter(v => v.severity === "low").length;

  const criticalSecrets = secrets.filter(s => s.severity === "critical").length;
  const otherSecrets = secrets.length - criticalSecrets;

  const cveCritical = cves.filter(c => c.severity === "critical").length;
  const cveHigh = cves.filter(c => c.severity === "high").length;
  const cveOther = cves.length - cveCritical - cveHigh;

  const maliciousCount = malware.filter(m => m.isMalicious || m.threatScore >= 70).length;

  const penalty =
    criticalCount * 20 + highCount * 10 + mediumCount * 5 + lowCount * 2 +
    criticalSecrets * 25 + otherSecrets * 10 +
    fns.length * 8 +
    cveCritical * 20 + cveHigh * 10 + cveOther * 3 +
    maliciousCount * 30;

  const overallScore = Math.max(0, 100 - penalty);

  const riskLevel =
    criticalCount > 0 || criticalSecrets > 0 || cveCritical > 0 || maliciousCount > 0
      ? "critical"
      : overallScore < 50
        ? "high"
        : overallScore < 70
          ? "medium"
          : "low";

  res.json({
    scanId: resolved.scanId,
    firmwareId: resolved.firmwareId,
    overallScore,
    riskLevel,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    hardcodedSecretsCount: secrets.length,
    criticalSecretsCount: criticalSecrets,
    dangerousFunctionsCount: fns.length,
    cveMatchesCount: cves.length,
    cveCriticalCount: cveCritical,
    cveHighCount: cveHigh,
    maliciousFilesCount: maliciousCount,
    totalFindings: vulns.length + secrets.length + fns.length + cves.length + maliciousCount,
  });
});

router.get("/security/secrets/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const resolved = await resolveScanId(raw);
  if (!resolved) { res.json([]); return; }

  const secrets = await db
    .select()
    .from(hardcodedSecretsTable)
    .where(eq(hardcodedSecretsTable.scanId, resolved.scanId));

  res.json(secrets);
});

router.get("/security/dangerous-functions/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const resolved = await resolveScanId(raw);
  if (!resolved) { res.json([]); return; }

  const fns = await db
    .select()
    .from(dangerousFunctionsTable)
    .where(eq(dangerousFunctionsTable.scanId, resolved.scanId));

  res.json(fns);
});

export default router;