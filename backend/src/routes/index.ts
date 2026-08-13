import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import firmwareRouter from "./firmware";
import scannerRouter from "./scanner";
import securityRouter from "./security";
import cveRouter from "./cve";
import malwareRouter from "./malware";
import qemuRouter from "./qemu";
import reportsRouter from "./reports";
import dashboardRouter from "./dashboard";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(firmwareRouter);
router.use(scannerRouter);
router.use(securityRouter);
router.use(cveRouter);
router.use(malwareRouter);
router.use(qemuRouter);
router.use(reportsRouter);
router.use(dashboardRouter);

export default router;
