import { pgTable, serial, text, timestamp, integer, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const scanResultsTable = pgTable("scan_results", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  startedAt: timestamp("started_at").notNull().defaultNow(),
  completedAt: timestamp("completed_at"),
  status: text("status").notNull().default("running"),
  progress: integer("progress").notNull().default(0),
  totalFiles: integer("total_files"),
  vulnerabilitiesFound: integer("vulnerabilities_found"),
  riskLevel: text("risk_level"),
});

export const vulnerabilitiesTable = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  type: text("type").notNull(),
  severity: text("severity").notNull(),
  affectedFile: text("affected_file").notNull(),
  description: text("description").notNull(),
  recommendation: text("recommendation").notNull(),
  cvssScore: integer("cvss_score"),
  discoveredAt: timestamp("discovered_at").notNull().defaultNow(),
});

export const hardcodedSecretsTable = pgTable("hardcoded_secrets", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  type: text("type").notNull(),
  value: text("value").notNull(),
  file: text("file").notNull(),
  line: integer("line").notNull(),
  severity: text("severity").notNull().default("high"),
});

export const dangerousFunctionsTable = pgTable("dangerous_functions", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  name: text("name").notNull(),
  file: text("file").notNull(),
  line: integer("line").notNull(),
  risk: text("risk").notNull().default("high"),
  description: text("description").notNull(),
});

export const extractedFilesTable = pgTable("extracted_files", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  path: text("path").notNull(),
  type: text("type").notNull(),
  size: integer("size").notNull(),
  permissions: text("permissions"),
  isSuspicious: boolean("is_suspicious").notNull().default(false),
});

export const insertScanResultSchema = createInsertSchema(scanResultsTable).omit({ id: true, startedAt: true });
export type InsertScanResult = z.infer<typeof insertScanResultSchema>;
export type ScanResult = typeof scanResultsTable.$inferSelect;
