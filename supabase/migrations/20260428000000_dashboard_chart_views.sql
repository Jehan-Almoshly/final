-- =============================================================
-- Dashboard Chart Views — real data, no more mock seed tables
-- =============================================================
-- Run in: Supabase Dashboard → SQL Editor → New Query
--
-- 1. Drops legacy mock tables (chart_data, severity_stats,
--    review_status) that previously fed the dashboard with
--    hand-curated values.
-- 2. Adds any missing columns on the real tables (cve_catalog,
--    finding_cves, exploits, scan_findings) so the frontend
--    can run the new aggregation views even on partially
--    initialised projects.
-- 3. Creates SIX views — one per donut on the new dashboard:
--      chart_vulns_by_exprt          (ExPRT / CVSS rating)
--      chart_findings_by_type        (scan tool / finding type)
--      chart_exploitability_risk     (NVD ∪ ExploitDB)
--      chart_attack_vector           (parsed from CVSS v3 vector)
--      chart_exploit_types           (ExploitDB.type)
--      chart_top_vulnerable_products (scan_findings.metadata.product)
--
--    Every view returns the same shape:
--      segment_name TEXT, segment_value INT,
--      segment_color TEXT, sort_order INT
--
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1. Drop legacy mock seed objects (could be tables OR views)
-- -------------------------------------------------------------
-- These three objects might have been created as TABLEs in early
-- migrations, then later replaced by VIEWs in 20260425000000_compat_views.sql.
-- We must drop both shapes safely without erroring.
DO $$
DECLARE
  obj_name TEXT;
  obj_kind CHAR(1);
BEGIN
  FOREACH obj_name IN ARRAY ARRAY['chart_data', 'severity_stats', 'review_status']
  LOOP
    SELECT c.relkind INTO obj_kind
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname = obj_name
     LIMIT 1;

    IF obj_kind = 'v' THEN
      EXECUTE format('DROP VIEW IF EXISTS public.%I CASCADE', obj_name);
    ELSIF obj_kind = 'm' THEN
      EXECUTE format('DROP MATERIALIZED VIEW IF EXISTS public.%I CASCADE', obj_name);
    ELSIF obj_kind = 'r' THEN
      EXECUTE format('DROP TABLE IF EXISTS public.%I CASCADE', obj_name);
    END IF;
    -- if obj_kind IS NULL the object doesn't exist, nothing to do
  END LOOP;
END $$;


-- -------------------------------------------------------------
-- 2. Ensure the real schema exists / has the required columns
-- -------------------------------------------------------------

-- 2a. cve_catalog (created by the matcher pipeline)
CREATE TABLE IF NOT EXISTS public.cve_catalog (
  cve_id           TEXT PRIMARY KEY,
  description      TEXT,
  cvss_v3_score    REAL,
  cvss_v3_severity TEXT,
  cvss_v3_vector   TEXT,
  cvss_version     TEXT,
  published_at     TIMESTAMPTZ,
  references_urls  JSONB
);
ALTER TABLE public.cve_catalog ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anyone can read cve_catalog" ON public.cve_catalog;
CREATE POLICY "Anyone can read cve_catalog"
  ON public.cve_catalog FOR SELECT USING (true);

-- 2b. finding_cves (link table)
CREATE TABLE IF NOT EXISTS public.finding_cves (
  finding_id UUID NOT NULL,
  cve_id     TEXT NOT NULL,
  PRIMARY KEY (finding_id, cve_id)
);
ALTER TABLE public.finding_cves ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anyone can read finding_cves" ON public.finding_cves;
CREATE POLICY "Anyone can read finding_cves"
  ON public.finding_cves FOR SELECT USING (true);

-- 2c. exploits (extra columns we need for the donut)
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS type           TEXT;
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS platform       TEXT;
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS verified       BOOLEAN DEFAULT FALSE;
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS exploit_db_id  INTEGER;

-- 2d. scan_findings (metadata jsonb for vendor/product/version)
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS status   TEXT  DEFAULT 'open';

CREATE INDEX IF NOT EXISTS idx_finding_cves_cve_id        ON public.finding_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_catalog_severity       ON public.cve_catalog(cvss_v3_severity);
CREATE INDEX IF NOT EXISTS idx_exploits_type              ON public.exploits(type);


-- -------------------------------------------------------------
-- 3. Reusable colour palette (matches index.css :root chart-*)
-- -------------------------------------------------------------
--   --chart-critical   0  72% 55%   red
--   --chart-high      25  95% 55%   orange
--   --chart-medium   210  70% 55%   blue
--   --chart-low      150  70% 50%   green
--   --chart-cyan     180  70% 50%   cyan       (primary brand)
--   --chart-purple   270  60% 55%   purple
--   --chart-pink     340  70% 55%   pink
--   --chart-yellow    50  95% 55%   yellow
--   --chart-orange    30  90% 55%   orange-bright
--   --severity-very-low 210 15% 55% slate
-- -------------------------------------------------------------


-- -------------------------------------------------------------
-- View 1: chart_vulns_by_exprt
-- -------------------------------------------------------------
-- Vulnerabilities (CVEs that matched at least one finding)
-- bucketed by ExPRT / CVSS v3 severity.
-- =============================================================
CREATE OR REPLACE VIEW public.chart_vulns_by_exprt AS
WITH matched AS (
  SELECT DISTINCT c.cve_id, UPPER(COALESCE(c.cvss_v3_severity,'NONE')) AS sev
  FROM public.cve_catalog c
  JOIN public.finding_cves fc ON fc.cve_id = c.cve_id
)
SELECT
  CASE sev
    WHEN 'CRITICAL' THEN 'Critical'
    WHEN 'HIGH'     THEN 'High'
    WHEN 'MEDIUM'   THEN 'Medium'
    WHEN 'LOW'      THEN 'Low'
    ELSE                 'Info'
  END                                                       AS segment_name,
  COUNT(*)::int                                             AS segment_value,
  CASE sev
    WHEN 'CRITICAL' THEN 'hsl(0 72% 55%)'
    WHEN 'HIGH'     THEN 'hsl(25 95% 55%)'
    WHEN 'MEDIUM'   THEN 'hsl(210 70% 55%)'
    WHEN 'LOW'      THEN 'hsl(150 70% 50%)'
    ELSE                 'hsl(210 15% 55%)'
  END                                                       AS segment_color,
  CASE sev
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH'     THEN 2
    WHEN 'MEDIUM'   THEN 3
    WHEN 'LOW'      THEN 4
    ELSE                 5
  END                                                       AS sort_order
FROM matched
GROUP BY sev
ORDER BY sort_order;


-- -------------------------------------------------------------
-- View 2: chart_findings_by_type
-- -------------------------------------------------------------
-- Distribution of findings across the four scan tools we run
-- (Vuln scanners, Misconfiguration scanners, Web fuzzers, ...).
-- =============================================================
CREATE OR REPLACE VIEW public.chart_findings_by_type AS
WITH bucketed AS (
  SELECT
    CASE UPPER(COALESCE(f.tool,'OTHER'))
      WHEN 'NMAP'   THEN 'Vuln'
      WHEN 'SQLMAP' THEN 'Vuln'
      WHEN 'NIKTO'  THEN 'Misconf'
      WHEN 'FFUF'   THEN 'Misconf'
      ELSE               'Unknown'
    END AS bucket
  FROM public.scan_findings f
)
SELECT
  bucket                                                    AS segment_name,
  COUNT(*)::int                                             AS segment_value,
  CASE bucket
    WHEN 'Vuln'    THEN 'hsl(0 72% 55%)'
    WHEN 'Misconf' THEN 'hsl(30 90% 55%)'
    ELSE                'hsl(270 60% 55%)'
  END                                                       AS segment_color,
  CASE bucket
    WHEN 'Vuln'    THEN 1
    WHEN 'Misconf' THEN 2
    ELSE                3
  END                                                       AS sort_order
FROM bucketed
GROUP BY bucket
ORDER BY sort_order;


-- -------------------------------------------------------------
-- View 3: chart_exploitability_risk
-- -------------------------------------------------------------
-- For every CVE that matched a finding, classify how dangerous
-- it is RIGHT NOW based on local NVD ∪ ExploitDB knowledge.
--
--   "Weaponized"  → an exploit row marked verified = TRUE
--   "Public PoC"  → an exploit row exists but not verified
--   "Known CVE"   → in cve_catalog but no exploit
--   "Theoretical" → CVSS = NONE / blank
-- =============================================================
CREATE OR REPLACE VIEW public.chart_exploitability_risk AS
WITH per_cve AS (
  SELECT
    c.cve_id,
    UPPER(COALESCE(c.cvss_v3_severity,'NONE')) AS sev,
    COUNT(e.exploit_db_id) FILTER (WHERE e.verified IS TRUE) AS verified_count,
    COUNT(e.exploit_db_id)                                   AS total_exploits
  FROM public.cve_catalog c
  JOIN public.finding_cves fc ON fc.cve_id = c.cve_id
  LEFT JOIN public.exploits e ON e.cve_id = c.cve_id
  GROUP BY c.cve_id, c.cvss_v3_severity
),
classified AS (
  SELECT
    CASE
      WHEN verified_count > 0          THEN 'Weaponized'
      WHEN total_exploits > 0          THEN 'Public PoC'
      WHEN sev = 'NONE' OR sev = ''    THEN 'Theoretical'
      ELSE                                   'Known CVE'
    END AS bucket
  FROM per_cve
)
SELECT
  bucket                                                    AS segment_name,
  COUNT(*)::int                                             AS segment_value,
  CASE bucket
    WHEN 'Weaponized'  THEN 'hsl(0 72% 55%)'
    WHEN 'Public PoC'  THEN 'hsl(30 90% 55%)'
    WHEN 'Known CVE'   THEN 'hsl(50 95% 55%)'
    ELSE                    'hsl(210 15% 55%)'
  END                                                       AS segment_color,
  CASE bucket
    WHEN 'Weaponized'  THEN 1
    WHEN 'Public PoC'  THEN 2
    WHEN 'Known CVE'   THEN 3
    ELSE                    4
  END                                                       AS sort_order
FROM classified
GROUP BY bucket
ORDER BY sort_order;


-- -------------------------------------------------------------
-- View 4: chart_attack_vector
-- -------------------------------------------------------------
-- Parse the AV: component out of the CVSS v3 vector string
-- (e.g. "CVSS:3.1/AV:N/AC:L/...") for every CVE that matched a
-- finding. Buckets: Network / Adjacent / Local / Physical.
-- =============================================================
CREATE OR REPLACE VIEW public.chart_attack_vector AS
WITH parsed AS (
  SELECT
    CASE
      WHEN c.cvss_v3_vector ~* '/AV:N(/|$)' THEN 'Network'
      WHEN c.cvss_v3_vector ~* '/AV:A(/|$)' THEN 'Adjacent'
      WHEN c.cvss_v3_vector ~* '/AV:L(/|$)' THEN 'Local'
      WHEN c.cvss_v3_vector ~* '/AV:P(/|$)' THEN 'Physical'
      ELSE 'Unknown'
    END AS bucket
  FROM public.cve_catalog c
  JOIN public.finding_cves fc ON fc.cve_id = c.cve_id
)
SELECT
  bucket                                                    AS segment_name,
  COUNT(*)::int                                             AS segment_value,
  CASE bucket
    WHEN 'Network'  THEN 'hsl(0 72% 55%)'
    WHEN 'Adjacent' THEN 'hsl(30 90% 55%)'
    WHEN 'Local'    THEN 'hsl(210 70% 55%)'
    WHEN 'Physical' THEN 'hsl(270 60% 55%)'
    ELSE                 'hsl(210 15% 55%)'
  END                                                       AS segment_color,
  CASE bucket
    WHEN 'Network'  THEN 1
    WHEN 'Adjacent' THEN 2
    WHEN 'Local'    THEN 3
    WHEN 'Physical' THEN 4
    ELSE                 5
  END                                                       AS sort_order
FROM parsed
GROUP BY bucket
ORDER BY sort_order;


-- -------------------------------------------------------------
-- View 5: chart_exploit_types
-- -------------------------------------------------------------
-- Among the local ExploitDB rows that are linked (via cve_id)
-- to at least one finding-matched CVE, how are the exploits
-- distributed by `type` (remote / local / webapps / dos / ...).
-- =============================================================
CREATE OR REPLACE VIEW public.chart_exploit_types AS
WITH relevant AS (
  SELECT DISTINCT e.exploit_db_id,
         LOWER(COALESCE(NULLIF(e.type,''),'unknown')) AS t
  FROM public.exploits e
  JOIN public.finding_cves fc ON fc.cve_id = e.cve_id
),
labelled AS (
  SELECT
    CASE t
      WHEN 'remote'   THEN 'Remote'
      WHEN 'local'    THEN 'Local Privilege'
      WHEN 'webapps'  THEN 'Web App'
      WHEN 'dos'      THEN 'Denial of Service'
      WHEN 'shellcode' THEN 'Shellcode'
      WHEN 'hardware' THEN 'Hardware'
      ELSE                 INITCAP(t)
    END AS label
  FROM relevant
)
SELECT
  label                                                     AS segment_name,
  COUNT(*)::int                                             AS segment_value,
  CASE label
    WHEN 'Remote'            THEN 'hsl(0 72% 55%)'
    WHEN 'Web App'           THEN 'hsl(180 70% 50%)'
    WHEN 'Local Privilege'   THEN 'hsl(30 90% 55%)'
    WHEN 'Denial of Service' THEN 'hsl(50 95% 55%)'
    WHEN 'Shellcode'         THEN 'hsl(270 60% 55%)'
    WHEN 'Hardware'          THEN 'hsl(340 70% 55%)'
    ELSE                          'hsl(210 15% 55%)'
  END                                                       AS segment_color,
  CASE label
    WHEN 'Remote'            THEN 1
    WHEN 'Web App'           THEN 2
    WHEN 'Local Privilege'   THEN 3
    WHEN 'Denial of Service' THEN 4
    WHEN 'Shellcode'         THEN 5
    WHEN 'Hardware'          THEN 6
    ELSE                          9
  END                                                       AS sort_order
FROM labelled
GROUP BY label
ORDER BY sort_order, label;


-- -------------------------------------------------------------
-- View 6: chart_top_vulnerable_products
-- -------------------------------------------------------------
-- Top-7 product names (vendor + product) seen in
-- scan_findings.metadata, ranked by number of distinct CVEs.
-- =============================================================
CREATE OR REPLACE VIEW public.chart_top_vulnerable_products AS
WITH product_cves AS (
  SELECT
    NULLIF(TRIM(CONCAT_WS(
      ' ',
      INITCAP(NULLIF(f.metadata->>'vendor','')),
      INITCAP(NULLIF(f.metadata->>'product',''))
    )), '') AS product_label,
    fc.cve_id
  FROM public.scan_findings f
  JOIN public.finding_cves fc ON fc.finding_id = f.id
  WHERE f.metadata->>'product' IS NOT NULL
),
ranked AS (
  SELECT
    product_label,
    COUNT(DISTINCT cve_id)::int AS cve_count,
    ROW_NUMBER() OVER (ORDER BY COUNT(DISTINCT cve_id) DESC, product_label) AS rn
  FROM product_cves
  WHERE product_label IS NOT NULL
  GROUP BY product_label
),
palette(idx, color) AS (
  VALUES
    (1, 'hsl(0 72% 55%)'),
    (2, 'hsl(30 90% 55%)'),
    (3, 'hsl(50 95% 55%)'),
    (4, 'hsl(150 70% 50%)'),
    (5, 'hsl(180 70% 50%)'),
    (6, 'hsl(210 70% 55%)'),
    (7, 'hsl(270 60% 55%)')
)
SELECT
  r.product_label   AS segment_name,
  r.cve_count       AS segment_value,
  p.color           AS segment_color,
  r.rn::int         AS sort_order
FROM ranked r
JOIN palette p ON p.idx = LEAST(r.rn, 7)
WHERE r.rn <= 7
ORDER BY r.rn;


-- -------------------------------------------------------------
-- 4. Grants
-- -------------------------------------------------------------
GRANT SELECT ON
  public.chart_vulns_by_exprt,
  public.chart_findings_by_type,
  public.chart_exploitability_risk,
  public.chart_attack_vector,
  public.chart_exploit_types,
  public.chart_top_vulnerable_products
TO anon, authenticated;

COMMIT;

-- =============================================================
-- DONE.
-- The dashboard now reads from these six views. Each one will
-- return zero rows until your scan agent populates
-- scan_findings + cve_catalog + finding_cves + exploits, at
-- which point all donuts come alive automatically.
-- =============================================================
