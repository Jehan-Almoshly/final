import {
  pgTable,
  uuid,
  text,
  integer,
  jsonb,
  timestamp,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { scanResultsTable } from "./scan_results";

export type ScanTool = "NMAP" | "NIKTO" | "SQLMAP" | "FFUF" | "OTHER";
export type FindingStatus = "open" | "triaged" | "fixed" | "false_positive";

export type FindingMetadata = {
  vendor?: string;
  product?: string;
  version?: string | null;
  source?: string | null;
  cve_count?: number;
  exploit_count?: number;
  [key: string]: unknown;
};

export const scanFindingsTable = pgTable("scan_findings", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: uuid("scan_id")
    .notNull()
    .references(() => scanResultsTable.id, { onDelete: "cascade" }),
  tool: text("tool").$type<ScanTool>().notNull(),
  target: text("target").notNull(),
  title: text("title").notNull(),
  path: text("path"),
  httpStatus: integer("http_status"),
  service: text("service"),
  evidence: text("evidence"),
  metadata: jsonb("metadata").$type<FindingMetadata>().default(sql`'{}'::jsonb`),
  status: text("status").$type<FindingStatus>().notNull().default("open"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export type ScanFinding = typeof scanFindingsTable.$inferSelect;
export type InsertScanFinding = typeof scanFindingsTable.$inferInsert;
