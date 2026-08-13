import { Router, type IRouter } from "express";
import { db, emulationLogsTable, firmwareTable, activityTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { runEmulation } from "../services/emulation.js";

const router: IRouter = Router();

router.post("/qemu/start", async (req, res): Promise<void> => {
  const { firmwareId, architecture } = req.body;
  if (!firmwareId) { res.status(400).json({ error: "Missing firmwareId" }); return; }

  const [fw] = await db.select().from(firmwareTable).where(eq(firmwareTable.id, firmwareId));
  if (!fw?.filePath) { res.status(400).json({ error: "Firmware file not found" }); return; }

  const arch = architecture || fw.architecture || "ARM";
  const extractPath = fw.extractPath ?? "";

  const [log] = await db.insert(emulationLogsTable).values({
    firmwareId,
    status: "starting",
    architecture: arch,
    runningServices: JSON.stringify([]),
    openPorts: JSON.stringify([]),
  }).returning();

  await db.insert(activityTable).values({
    type: "emulation_started",
    message: `QEMU emulation started for ${fw.name} (${arch})`,
    severity: "info",
    firmwareId,
  });

  void (async () => {
    try {
      const result = await runEmulation(fw.filePath!, extractPath, arch);
      await db.update(emulationLogsTable).set({
        status: "running",
        runningServices: JSON.stringify(result.runningServices),
        openPorts: JSON.stringify(result.openPorts),
        runtimeLogs: result.runtimeLogs,
      }).where(eq(emulationLogsTable.id, log.id));
    } catch {
      await db.update(emulationLogsTable).set({ status: "failed" }).where(eq(emulationLogsTable.id, log.id));
    }
  })();

  res.status(201).json({
    id: log.id,
    firmwareId: log.firmwareId,
    status: log.status,
    architecture: log.architecture,
    startedAt: log.startedAt.toISOString(),
    stoppedAt: null,
    runningServices: [],
    openPorts: [],
    runtimeLogs: null,
  });
});

router.get("/qemu/services/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }

  const logs = await db.select().from(emulationLogsTable).where(eq(emulationLogsTable.firmwareId, firmwareId));
  res.json(logs.map(l => ({
    id: l.id,
    firmwareId: l.firmwareId,
    status: l.status,
    architecture: l.architecture,
    startedAt: l.startedAt.toISOString(),
    stoppedAt: l.stoppedAt ? l.stoppedAt.toISOString() : null,
    runningServices: JSON.parse(l.runningServices || "[]"),
    openPorts: JSON.parse(l.openPorts || "[]"),
    runtimeLogs: l.runtimeLogs ?? null,
  })));
});

router.get("/qemu/ports/:firmwareId", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.firmwareId) ? req.params.firmwareId[0] : req.params.firmwareId;
  const firmwareId = parseInt(raw, 10);
  if (isNaN(firmwareId)) { res.status(400).json({ error: "Invalid firmwareId" }); return; }

  const [log] = await db.select().from(emulationLogsTable).where(eq(emulationLogsTable.firmwareId, firmwareId));
  const rawPorts: number[] = log ? JSON.parse(log.openPorts || "[]") : [];

  const serviceMap: Record<number, { service: string; protocol: string }> = {
    80: { service: "HTTP", protocol: "TCP" },
    443: { service: "HTTPS", protocol: "TCP" },
    22: { service: "SSH/Dropbear", protocol: "TCP" },
    23: { service: "Telnet", protocol: "TCP" },
    8080: { service: "HTTP Alt", protocol: "TCP" },
    8443: { service: "HTTPS Alt", protocol: "TCP" },
    53: { service: "DNS", protocol: "UDP" },
  };

  const ports = rawPorts.map(p => ({
    port: p,
    protocol: serviceMap[p]?.protocol || "TCP",
    service: serviceMap[p]?.service || "Unknown",
    state: "open",
  }));

  res.json({ firmwareId, ports });
});

export default router;
