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

const router: IRouter = Router();

router.get("/security/vulnerabilities/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }
  const vulns = await db.select().from(vulnerabilitiesTable).where(eq(vulnerabilitiesTable.firmwareId, firmwareId));
  res.json(vulns.map(v => ({
    ...v,
    cvssScore: v.cvssScore ?? null,
    discoveredAt: v.discoveredAt.toISOString(),
  })));
});

router.get("/security/score/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }

  const [vulns, secrets, fns, cves, malware] = await Promise.all([
    db.select().from(vulnerabilitiesTable).where(eq(vulnerabilitiesTable.firmwareId, firmwareId)),
    db.select().from(hardcodedSecretsTable).where(eq(hardcodedSecretsTable.firmwareId, firmwareId)),
    db.select().from(dangerousFunctionsTable).where(eq(dangerousFunctionsTable.firmwareId, firmwareId)),
    db.select().from(cveMatchesTable).where(eq(cveMatchesTable.firmwareId, firmwareId)),
    db.select().from(malwareHashesTable).where(eq(malwareHashesTable.firmwareId, firmwareId)),
  ]);

  // --- Vulnerabilities ---
  const criticalCount = vulns.filter(v => v.severity === "critical").length;
  const highCount = vulns.filter(v => v.severity === "high").length;
  const mediumCount = vulns.filter(v => v.severity === "medium").length;
  const lowCount = vulns.filter(v => v.severity === "low").length;

  // --- Secrets ---
  const criticalSecrets = secrets.filter(s => s.severity === "critical").length;
  const otherSecrets = secrets.length - criticalSecrets;

  // --- CVEs ---
  const cveCritical = cves.filter(c => c.severity === "critical").length;
  const cveHigh = cves.filter(c => c.severity === "high").length;
  const cveOther = cves.length - cveCritical - cveHigh;

  // --- Malware ---
  const maliciousCount = malware.filter(m => m.isMalicious || m.threatScore >= 70).length;

  // --- Weighted penalty across ALL finding categories ---
  const penalty =
    criticalCount * 20 + highCount * 10 + mediumCount * 5 + lowCount * 2 +
    criticalSecrets * 25 + otherSecrets * 10 +
    fns.length * 8 +
    cveCritical * 20 + cveHigh * 10 + cveOther * 3 +
    maliciousCount * 30;

  const overallScore = Math.max(0, 100 - penalty);

  // Any critical-severity finding or malware hit forces "critical",
  // regardless of the numeric score — mirrors the scan pipeline's
  // risk aggregation so this endpoint never contradicts the scan result.
  const riskLevel =
    criticalCount > 0 || criticalSecrets > 0 || cveCritical > 0 || maliciousCount > 0
      ? "critical"
      : overallScore < 50
        ? "high"
        : overallScore < 70
          ? "medium"
          : "low";

  res.json({
    firmwareId,
    overallScore,
    riskLevel,

    // Vulnerabilities
    criticalCount,
    highCount,
    mediumCount,
    lowCount,

    // Secrets
    hardcodedSecretsCount: secrets.length,
    criticalSecretsCount: criticalSecrets,

    // Dangerous functions
    dangerousFunctionsCount: fns.length,

    // CVEs
    cveMatchesCount: cves.length,
    cveCriticalCount: cveCritical,
    cveHighCount: cveHigh,

    // Malware
    maliciousFilesCount: maliciousCount,

    // Grand total across every finding category — use this instead
    // of vulnerabilitiesFound alone when displaying "total findings"
    totalFindings: vulns.length + secrets.length + fns.length + cves.length + maliciousCount,
  });
});

router.get("/security/secrets/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }
  const secrets = await db.select().from(hardcodedSecretsTable).where(eq(hardcodedSecretsTable.firmwareId, firmwareId));
  res.json(secrets);
});

router.get("/security/dangerous-functions/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }
  const fns = await db.select().from(dangerousFunctionsTable).where(eq(dangerousFunctionsTable.firmwareId, firmwareId));
  res.json(fns);
});

export default router;