import { pgTable, text, timestamp, integer } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export const systemLogsTable = pgTable("system_logs", {
  id: text("id").primaryKey().default(sql`gen_random_uuid()`),
  message: text("message").notNull(),
  level: text("level").default("info"),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull().defaultNow(),
  sort_order: integer("sort_order").notNull().default(0),
});

export type SystemLog = typeof systemLogsTable.$inferSelect;
export type InsertSystemLog = typeof systemLogsTable.$inferInsert;
