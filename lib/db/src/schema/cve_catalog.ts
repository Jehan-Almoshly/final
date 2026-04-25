import {
  pgTable,
  text,
  numeric,
  date,
  jsonb,
  timestamp,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export type CvssSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export const cveCatalogTable = pgTable("cve_catalog", {
  cveId: text("cve_id").primaryKey(),
  description: text("description"),
  cvssV3Score: numeric("cvss_v3_score", { precision: 3, scale: 1 }),
  cvssV3Severity: text("cvss_v3_severity").$type<CvssSeverity>(),
  cvssV3Vector: text("cvss_v3_vector"),
  publishedDate: date("published_date"),
  affectedProducts: jsonb("affected_products")
    .$type<string[]>()
    .default(sql`'[]'::jsonb`),
  referencesUrls: jsonb("references_urls")
    .$type<string[]>()
    .default(sql`'[]'::jsonb`),
  importedAt: timestamp("imported_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export type CveCatalog = typeof cveCatalogTable.$inferSelect;
export type InsertCveCatalog = typeof cveCatalogTable.$inferInsert;
