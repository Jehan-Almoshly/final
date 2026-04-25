import { pgTable, uuid, text, timestamp, unique } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { scanFindingsTable } from "./scan_findings";
import { cveCatalogTable } from "./cve_catalog";

export type MatchConfidence = "exact" | "version" | "fingerprint" | "fuzzy";

export const findingCvesTable = pgTable(
  "finding_cves",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    findingId: uuid("finding_id")
      .notNull()
      .references(() => scanFindingsTable.id, { onDelete: "cascade" }),
    cveId: text("cve_id")
      .notNull()
      .references(() => cveCatalogTable.cveId, { onDelete: "cascade" }),
    matchConfidence: text("match_confidence")
      .$type<MatchConfidence>()
      .notNull(),
    matchEvidence: text("match_evidence"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    uniqFindingCve: unique("finding_cves_finding_id_cve_id_key").on(
      t.findingId,
      t.cveId,
    ),
  }),
);

export type FindingCve = typeof findingCvesTable.$inferSelect;
export type InsertFindingCve = typeof findingCvesTable.$inferInsert;
