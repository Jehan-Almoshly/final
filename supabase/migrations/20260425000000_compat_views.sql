-- =============================================================
-- Compatibility Views
-- =============================================================
-- The frontend (VulnerabilitiesTab, ReportsTab, AdminPanel,
-- ScannedAssetsTable) was built against the old MOCK tables
-- `vulnerabilities` and `scanned_assets`. Rather than rewrite
-- the UI, we expose VIEWS with the exact same shape, computed
-- from the new real schema (scan_findings + finding_cves +
-- cve_catalog + exploits + scan_results).
--
-- One row per CVE in `vulnerabilities`.
-- One row per target host in `scanned_assets`.
--
-- Run in: Supabase Dashboard -> SQL Editor -> New Query
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1. Drop any prior version (could be table OR view)
-- -------------------------------------------------------------
DO $drop_compat$
DECLARE
  obj_name text;
  obj_kind char;
  names text[] := ARRAY['vulnerabilities', 'scanned_assets'];
BEGIN
  FOREACH obj_name IN ARRAY names LOOP
    SELECT c.relkind INTO obj_kind
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = obj_name;

    IF obj_kind IS NULL THEN
      CONTINUE;
    ELSIF obj_kind = 'v' THEN
      EXECUTE format('DROP VIEW IF EXISTS public.%I CASCADE', obj_name);
    ELSIF obj_kind = 'm' THEN
      EXECUTE format('DROP MATERIALIZED VIEW IF EXISTS public.%I CASCADE', obj_name);
    ELSIF obj_kind IN ('r','p') THEN
      EXECUTE format('DROP TABLE IF EXISTS public.%I CASCADE', obj_name);
    END IF;
  END LOOP;
END
$drop_compat$;

-- -------------------------------------------------------------
-- 2. vulnerabilities  (one row per CVE)
-- -------------------------------------------------------------
-- Fields the UI expects:
--   id, cve_id, cvss_severity, exprt_rating, description,
--   status, exploit_status, vulnerability_count, remediations,
--   created_at
-- =============================================================
CREATE OR REPLACE VIEW public.vulnerabilities AS
WITH cve_findings AS (
  -- For every CVE, aggregate over the findings that matched it
  SELECT
    fc.cve_id,
    COUNT(DISTINCT fc.finding_id)::int AS vulnerability_count,
    -- "open if any matched finding is still open"
    BOOL_OR(f.status = 'open')         AS any_open,
    BOOL_OR(f.status = 'triaged')      AS any_triaged,
    BOOL_OR(f.status = 'fixed')        AS any_fixed,
    MIN(f.created_at)                  AS first_seen
  FROM public.finding_cves fc
  JOIN public.scan_findings f ON f.id = fc.finding_id
  GROUP BY fc.cve_id
),
cve_exploits AS (
  -- Does this CVE have any exploit available locally?
  SELECT
    cve_id,
    COUNT(*)::int                     AS exploit_count,
    BOOL_OR(verified IS TRUE)         AS any_verified
  FROM public.exploits
  WHERE cve_id IS NOT NULL
  GROUP BY cve_id
)
SELECT
  md5('vuln|' || c.cve_id)::uuid          AS id,
  c.cve_id                                AS cve_id,

  -- "Critical" / "High" / "Medium" / "Low" / "Info"
  CASE UPPER(COALESCE(c.cvss_v3_severity, 'NONE'))
    WHEN 'CRITICAL' THEN 'Critical'
    WHEN 'HIGH'     THEN 'High'
    WHEN 'MEDIUM'   THEN 'Medium'
    WHEN 'LOW'      THEN 'Low'
    ELSE 'Info'
  END                                     AS cvss_severity,

  -- expert rating = same as cvss_severity (no separate ML model yet)
  CASE UPPER(COALESCE(c.cvss_v3_severity, 'NONE'))
    WHEN 'CRITICAL' THEN 'Critical'
    WHEN 'HIGH'     THEN 'High'
    WHEN 'MEDIUM'   THEN 'Medium'
    WHEN 'LOW'      THEN 'Low'
    ELSE 'Info'
  END                                     AS exprt_rating,

  c.description                           AS description,

  -- status: open if any matched finding still open, else triaged, else closed
  CASE
    WHEN cf.any_open    THEN 'Open'
    WHEN cf.any_triaged THEN 'In Progress'
    WHEN cf.any_fixed   THEN 'Closed'
    ELSE 'Open'
  END                                     AS status,

  -- exploit_status: real signal from local Exploit-DB
  CASE
    WHEN ce.any_verified THEN 'Actively Used'
    WHEN ce.exploit_count > 0 THEN 'Available'
    ELSE 'None'
  END                                     AS exploit_status,

  COALESCE(cf.vulnerability_count, 0)     AS vulnerability_count,

  -- remediations: number of CVEs with patches (proxy: has reference URLs)
  CASE
    WHEN c.references_urls IS NOT NULL
     AND jsonb_array_length(c.references_urls) > 0 THEN 1
    ELSE 0
  END                                     AS remediations,

  COALESCE(cf.first_seen, c.published_at, NOW()) AS created_at

FROM public.cve_catalog c
JOIN cve_findings cf ON cf.cve_id = c.cve_id
LEFT JOIN cve_exploits ce ON ce.cve_id = c.cve_id;

-- -------------------------------------------------------------
-- 3. scanned_assets  (one row per target host)
-- -------------------------------------------------------------
-- Fields the UI expects:
--   id, ip_address, hostname, os, open_ports, risk, last_scan,
--   created_at
-- =============================================================
CREATE OR REPLACE VIEW public.scanned_assets AS
WITH per_target AS (
  SELECT
    sr.target,
    -- last scan timestamp
    MAX(COALESCE(sr.completed_at, sr.started_at, sr.created_at))
                                       AS last_scan,
    MIN(sr.created_at)                 AS created_at,
    -- aggregate severity across all scans of this target
    SUM(sr.critical_count)::int        AS sum_critical,
    SUM(sr.high_count)::int            AS sum_high,
    SUM(sr.medium_count)::int          AS sum_medium,
    SUM(sr.low_count)::int             AS sum_low
  FROM public.scan_results sr
  GROUP BY sr.target
),
per_target_ports AS (
  -- comma-separated list of distinct ports we saw findings on
  SELECT
    f.target,
    string_agg(DISTINCT NULLIF(split_part(f.target, ':', 2), ''), ',')
      AS port_list
  FROM public.scan_findings f
  GROUP BY f.target
)
SELECT
  md5('asset|' || pt.target)::uuid       AS id,
  -- the "target" in scan_results is typically a URL or host:port.
  -- For the UI we strip scheme/port to get a usable IP/hostname.
  COALESCE(
    NULLIF(regexp_replace(pt.target, '^https?://', ''), ''),
    pt.target
  )                                       AS ip_address,
  COALESCE(
    NULLIF(split_part(
      regexp_replace(pt.target, '^https?://', ''),
      '/', 1), ''),
    pt.target
  )                                       AS hostname,
  'unknown'::text                         AS os,
  COALESCE(ptp.port_list, '')             AS open_ports,
  CASE
    WHEN pt.sum_critical > 0 THEN 'Critical'
    WHEN pt.sum_high     > 0 THEN 'High'
    WHEN pt.sum_medium   > 0 THEN 'Medium'
    WHEN pt.sum_low      > 0 THEN 'Low'
    ELSE 'Info'
  END                                     AS risk,
  pt.last_scan                            AS last_scan,
  pt.created_at                           AS created_at
FROM per_target pt
LEFT JOIN per_target_ports ptp ON ptp.target = pt.target;

-- -------------------------------------------------------------
-- 4. Grants
-- -------------------------------------------------------------
GRANT SELECT ON public.vulnerabilities,
                public.scanned_assets
  TO anon, authenticated;

COMMIT;

-- =============================================================
-- DONE.
-- The frontend will now see real data via these views.
-- They will return 0 rows until scan_findings is populated by
-- the Kali gateway pipeline.
-- =============================================================
