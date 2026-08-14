import { pgTable, serial, text, timestamp, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const firmwareTable = pgTable("firmware", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  uploadedAt: timestamp("uploaded_at").notNull().defaultNow(),
  architecture: text("architecture").notNull().default("UNKNOWN"),
  hashValue: text("hash_value").notNull(),
  status: text("status").notNull().default("pending"),
  fileSize: integer("file_size").notNull(),
  vendor: text("vendor"),
  version: text("version"),
  filePath: text("file_path"),
  extractPath: text("extract_path"),
});

export const insertFirmwareSchema = createInsertSchema(firmwareTable).omit({ id: true, uploadedAt: true });
export type InsertFirmware = z.infer<typeof insertFirmwareSchema>;
export type Firmware = typeof firmwareTable.$inferSelect;
