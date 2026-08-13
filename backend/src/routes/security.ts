import { Router, type IRouter } from "express";
import { db, vulnerabilitiesTable, hardcodedSecretsTable, dangerousFunctionsTable } from "@workspace/db";
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

  const vulns = await db.select().from(vulnerabilitiesTable).where(eq(vulnerabilitiesTable.firmwareId, firmwareId));
  const secrets = await db.select().from(hardcodedSecretsTable).where(eq(hardcodedSecretsTable.firmwareId, firmwareId));
  const fns = await db.select().from(dangerousFunctionsTable).where(eq(dangerousFunctionsTable.firmwareId, firmwareId));

  const criticalCount = vulns.filter(v => v.severity === "critical").length;
  const highCount = vulns.filter(v => v.severity === "high").length;
  const mediumCount = vulns.filter(v => v.severity === "medium").length;
  const lowCount = vulns.filter(v => v.severity === "low").length;

  const penalty = criticalCount * 20 + highCount * 10 + mediumCount * 5 + lowCount * 2;
  const overallScore = Math.max(0, 100 - penalty);
  const riskLevel = overallScore < 30 ? "critical" : overallScore < 50 ? "high" : overallScore < 70 ? "medium" : "low";

  res.json({
    firmwareId,
    overallScore,
    riskLevel,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    hardcodedSecretsCount: secrets.length,
    dangerousFunctionsCount: fns.length,
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
