import { pgTable, serial, text, integer, boolean, timestamp, real } from "drizzle-orm/pg-core";

export const cveMatchesTable = pgTable("cve_matches", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  cveId: text("cve_id").notNull(),
  severity: text("severity").notNull(),
  cvssScore: real("cvss_score").notNull(),
  description: text("description").notNull(),
  affectedComponent: text("affected_component").notNull(),
  publishedDate: text("published_date").notNull(),
  patchAvailable: boolean("patch_available").notNull().default(false),
});

export const malwareHashesTable = pgTable("malware_hashes", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  sha256: text("sha256").notNull(),
  threatScore: integer("threat_score").notNull().default(0),
  virusTotalResult: text("virus_total_result").notNull().default("unknown"),
  isMalicious: boolean("is_malicious").notNull().default(false),
  detectionCount: integer("detection_count").notNull().default(0),
  totalEngines: integer("total_engines").notNull().default(72),
  fileName: text("file_name"),
});

export const emulationLogsTable = pgTable("emulation_logs", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  status: text("status").notNull().default("starting"),
  architecture: text("architecture").notNull(),
  startedAt: timestamp("started_at").notNull().defaultNow(),
  stoppedAt: timestamp("stopped_at"),
  runningServices: text("running_services").notNull().default("[]"),
  openPorts: text("open_ports").notNull().default("[]"),
  runtimeLogs: text("runtime_logs"),
});

export const aiReportsTable = pgTable("ai_reports", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull().unique(),
  summary: text("summary").notNull(),
  riskLevel: text("risk_level").notNull(),
  keyFindings: text("key_findings").notNull().default("[]"),
  recommendations: text("recommendations").notNull().default("[]"),
  generatedAt: timestamp("generated_at").notNull().defaultNow(),
  exploitProbability: real("exploit_probability"),
});

export const activityTable = pgTable("activity", {
  id: serial("id").primaryKey(),
  type: text("type").notNull(),
  message: text("message").notNull(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  severity: text("severity").notNull().default("info"),
  firmwareId: integer("firmware_id"),
  firmwareName: text("firmware_name"),
});
