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

/**
 * GET /security/vulnerabilities/:id
 *
 * Returns:
 * - Static-analysis vulnerabilities
 * - CVE matches
 *
 * Both are presented in the same format so the
 * Security Analysis page can display them together.
 */
router.get(
  "/security/vulnerabilities/:id",
  async (req, res): Promise<void> => {
    const raw = Array.isArray(req.params.id)
      ? req.params.id[0]
      : req.params.id;

    const resolved = await resolveScanId(raw);

    if (!resolved) {
      res.json([]);
      return;
    }

    const [vulns, cves] = await Promise.all([
      db
        .select()
        .from(vulnerabilitiesTable)
        .where(
          eq(
            vulnerabilitiesTable.scanId,
            resolved.scanId,
          ),
        ),

      db
        .select()
        .from(cveMatchesTable)
        .where(
          eq(
            cveMatchesTable.scanId,
            resolved.scanId,
          ),
        ),
    ]);

    /*
     * Normal security vulnerabilities
     */
    const vulnerabilityResults = vulns.map((v) => ({
      ...v,
      cvssScore: v.cvssScore ?? null,
      discoveredAt: v.discoveredAt.toISOString(),
    }));

    /*
     * Convert CVE matches into the Vulnerability format
     * expected by the Security Analysis frontend.
     */
    const cveResults = cves.map((cve) => ({
      // Negative ID prevents collision with normal vulnerability IDs.
      id: -cve.id,

      firmwareId: cve.firmwareId,

      type: cve.cveId,

      severity: cve.severity,

      affectedFile: cve.affectedComponent,

      description: cve.description,

      recommendation: cve.patchAvailable
        ? "Apply the available security patch or update the affected component."
        : "Update or replace the affected component with a secure version.",

      cvssScore: cve.cvssScore,

      discoveredAt: undefined,
    }));

    /*
     * Return both normal vulnerabilities and CVEs.
     */
    res.json([
      ...vulnerabilityResults,
      ...cveResults,
    ]);
  },
);


/**
 * GET /security/score/:id
 *
 * Calculates the overall security score.
 *
 * CVEs are included in the displayed severity counts,
 * but are only penalized once.
 */
router.get(
  "/security/score/:id",
  async (req, res): Promise<void> => {
    const raw = Array.isArray(req.params.id)
      ? req.params.id[0]
      : req.params.id;

    const resolved = await resolveScanId(raw);

    if (!resolved) {
      res.json({
        overallScore: 100,
        riskLevel: "low",
        totalFindings: 0,
      });
      return;
    }

    const [
      vulns,
      secrets,
      fns,
      cves,
      malware,
    ] = await Promise.all([
      db
        .select()
        .from(vulnerabilitiesTable)
        .where(
          eq(
            vulnerabilitiesTable.scanId,
            resolved.scanId,
          ),
        ),

      db
        .select()
        .from(hardcodedSecretsTable)
        .where(
          eq(
            hardcodedSecretsTable.scanId,
            resolved.scanId,
          ),
        ),

      db
        .select()
        .from(dangerousFunctionsTable)
        .where(
          eq(
            dangerousFunctionsTable.scanId,
            resolved.scanId,
          ),
        ),

      db
        .select()
        .from(cveMatchesTable)
        .where(
          eq(
            cveMatchesTable.scanId,
            resolved.scanId,
          ),
        ),

      db
        .select()
        .from(malwareHashesTable)
        .where(
          eq(
            malwareHashesTable.scanId,
            resolved.scanId,
          ),
        ),
    ]);

    /*
     * --------------------------------------------------------
     * NORMAL VULNERABILITY COUNTS
     * --------------------------------------------------------
     */

    const vulnerabilityCritical = vulns.filter(
      (v) => v.severity === "critical",
    ).length;

    const vulnerabilityHigh = vulns.filter(
      (v) => v.severity === "high",
    ).length;

    const vulnerabilityMedium = vulns.filter(
      (v) => v.severity === "medium",
    ).length;

    const vulnerabilityLow = vulns.filter(
      (v) => v.severity === "low",
    ).length;


    /*
     * --------------------------------------------------------
     * CVE COUNTS
     * --------------------------------------------------------
     */

    const cveCritical = cves.filter(
      (c) => c.severity === "critical",
    ).length;

    const cveHigh = cves.filter(
      (c) => c.severity === "high",
    ).length;

    const cveMedium = cves.filter(
      (c) => c.severity === "medium",
    ).length;

    const cveLow = cves.filter(
      (c) => c.severity === "low",
    ).length;


    /*
     * --------------------------------------------------------
     * COMBINED COUNTS FOR THE SECURITY ANALYSIS UI
     * --------------------------------------------------------
     *
     * These are what the frontend displays in the
     * Vulnerability Breakdown.
     */

    const criticalCount =
      vulnerabilityCritical +
      cveCritical;

    const highCount =
      vulnerabilityHigh +
      cveHigh;

    const mediumCount =
      vulnerabilityMedium +
      cveMedium;

    const lowCount =
      vulnerabilityLow +
      cveLow;


    /*
     * --------------------------------------------------------
     * HARD-CODED SECRET COUNTS
     * --------------------------------------------------------
     */

    const criticalSecrets = secrets.filter(
      (s) => s.severity === "critical",
    ).length;

    const otherSecrets =
      secrets.length -
      criticalSecrets;


    /*
     * --------------------------------------------------------
     * MALWARE
     * --------------------------------------------------------
     */

    const maliciousCount = malware.filter(
      (m) =>
        m.isMalicious ||
        m.threatScore >= 70,
    ).length;


    /*
     * --------------------------------------------------------
     * SECURITY SCORE PENALTY
     *
     * Important:
     *
     * We use NORMAL vulnerability counts and CVE counts
     * separately here so CVEs are NOT double-counted.
     *
     * Each category uses diminishing returns (sqrt scaling)
     * plus a hard cap, instead of a flat linear penalty.
     * Real-world firmware routinely has 50-100+ hardcoded
     * secrets/dangerous function hits in normal embedded
     * Linux userspace (shell scripts, busybox applets,
     * config generators, etc) — a flat `count * weight`
     * penalty blows past 100 points almost immediately on
     * real firmware, so the score always floors at exactly
     * 0 and loses all ability to distinguish "quite bad"
     * from "catastrophically bad".
     *
     * The per-category caps below are sized so they can
     * only ever SUM to 100 in the worst case (25 + 25 + 15
     * + 25 + 10). Previously each cap was generous on its
     * own (35/40/25/35/30) but summed to 165 — meaning any
     * firmware bad enough to hit 3+ categories hard (which
     * intentionally-vulnerable test firmware like IoTGoat
     * always will) still floored at exactly 0 regardless of
     * how the categories differed. This keeps 0 reserved for
     * firmware that is simultaneously maxed out across every
     * category, and gives real differentiation everywhere else.
     * --------------------------------------------------------
     */

    const vulnPenalty = Math.min(
      25,
      vulnerabilityCritical * 12 +
        vulnerabilityHigh * 6 +
        vulnerabilityMedium * 3 +
        vulnerabilityLow * 1,
    );

    const secretsPenalty = Math.min(
      25,
      criticalSecrets * 8 +
        Math.sqrt(otherSecrets) * 4,
    );

    const dangerousPenalty = Math.min(
      15,
      Math.sqrt(fns.length) * 4,
    );

    const cvePenalty = Math.min(
      25,
      cveCritical * 12 +
        cveHigh * 6 +
        cveMedium * 3 +
        cveLow * 1,
    );

    const malwarePenalty = Math.min(
      10,
      maliciousCount * 10,
    );

    const penalty =
      vulnPenalty +
      secretsPenalty +
      dangerousPenalty +
      cvePenalty +
      malwarePenalty;


    const overallScore = Math.max(
      0,
      Math.round(100 - penalty),
    );


    /*
     * --------------------------------------------------------
     * RISK LEVEL
     * --------------------------------------------------------
     */

    const riskLevel =
      criticalCount > 0 ||
      criticalSecrets > 0 ||
      maliciousCount > 0
        ? "critical"
        : overallScore < 50
          ? "high"
          : overallScore < 70
            ? "medium"
            : "low";


    /*
     * --------------------------------------------------------
     * RESPONSE
     * --------------------------------------------------------
     */

    res.json({
      scanId: resolved.scanId,
      firmwareId: resolved.firmwareId,

      overallScore,
      riskLevel,

      criticalCount,
      highCount,
      mediumCount,
      lowCount,

      hardcodedSecretsCount:
        secrets.length,

      criticalSecretsCount:
        criticalSecrets,

      dangerousFunctionsCount:
        fns.length,

      cveMatchesCount:
        cves.length,

      cveCriticalCount:
        cveCritical,

      cveHighCount:
        cveHigh,

      maliciousFilesCount:
        maliciousCount,

      totalFindings:
        vulns.length +
        cves.length +
        secrets.length +
        fns.length +
        maliciousCount,
    });
  },
);


/**
 * GET /security/secrets/:id
 */
router.get(
  "/security/secrets/:id",
  async (req, res): Promise<void> => {
    const raw = Array.isArray(req.params.id)
      ? req.params.id[0]
      : req.params.id;

    const resolved = await resolveScanId(raw);

    if (!resolved) {
      res.json([]);
      return;
    }

    const secrets = await db
      .select()
      .from(hardcodedSecretsTable)
      .where(
        eq(
          hardcodedSecretsTable.scanId,
          resolved.scanId,
        ),
      );

    res.json(secrets);
  },
);


/**
 * GET /security/dangerous-functions/:id
 */
router.get(
  "/security/dangerous-functions/:id",
  async (req, res): Promise<void> => {
    const raw = Array.isArray(req.params.id)
      ? req.params.id[0]
      : req.params.id;

    const resolved = await resolveScanId(raw);

    if (!resolved) {
      res.json([]);
      return;
    }

    const fns = await db
      .select()
      .from(dangerousFunctionsTable)
      .where(
        eq(
          dangerousFunctionsTable.scanId,
          resolved.scanId,
        ),
      );

    res.json(fns);
  },
);


export default router;