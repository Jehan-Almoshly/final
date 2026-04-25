import { pgTable, text, timestamp, integer } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export const scanResultsTable = pgTable("scan_results", {
  id: text("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  target: text("target").notNull(),
  tool: text("tool").notNull(),
  status: text("status").notNull().default("pending"),
  description: text("description"),
  options: text("options"),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  userId: text("user_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  mediumCount: integer("medium_count").notNull().default(0),
  lowCount: integer("low_count").notNull().default(0),
  totalFindings: integer("total_findings").notNull().default(0),
});

export type ScanResult = typeof scanResultsTable.$inferSelect;
export type InsertScanResult = typeof scanResultsTable.$inferInsert;
