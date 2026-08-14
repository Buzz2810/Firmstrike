import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const sbomReportsTable = pgTable("sbom_reports", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull().unique(),
  generatedAt: timestamp("generated_at").notNull().defaultNow(),
  cyclonedxPath: text("cyclonedx_path").notNull(),
  spdxPath: text("spdx_path").notNull(),
  csvPath: text("csv_path").notNull(),
  componentCount: integer("component_count").notNull().default(0),
});

export const sbomComponentsTable = pgTable("sbom_components", {
  id: serial("id").primaryKey(),
  firmwareId: integer("firmware_id").notNull(),
  name: text("name").notNull(),
  version: text("version").notNull().default("unknown"),
  type: text("type").notNull(),
  path: text("path").notNull(),
  source: text("source").notNull(),
});

export const insertSbomReportSchema = createInsertSchema(sbomReportsTable).omit({ id: true, generatedAt: true });
export type InsertSbomReport = z.infer<typeof insertSbomReportSchema>;
export type SbomReport = typeof sbomReportsTable.$inferSelect;

export const insertSbomComponentSchema = createInsertSchema(sbomComponentsTable).omit({ id: true });
export type InsertSbomComponent = z.infer<typeof insertSbomComponentSchema>;
export type SbomComponent = typeof sbomComponentsTable.$inferSelect;
