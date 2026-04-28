-- =============================================================
-- Fix: scanned_assets.open_ports + RLS visibility
-- =============================================================
-- Problems found in production (2026-04-28):
--   1. scanned_assets.open_ports was always "—" because the view
--      tried split_part(target, ':', 2) on URLs like
--      "https://chat.deepseek.com/" — there is no ":port" segment,
--      so port_list was empty for every row.
--   2. scan_findings has no `port` column at all (the previous
--      attempt assumed one and silently failed). The real port
--      lives inside the `evidence` text (e.g. "80/tcp open http
--      Apache httpd 2.4.7"). We extract it with regex.
--   3. As a fallback we derive a default port from the URL scheme
--      of scan_results.target (https→443, http→80, ssh://→22 …).
--   4. scan_findings is RLS-protected for the anon role, so the
--      view returned 0 rows when called from the dashboard.
--      We add a permissive SELECT policy on scan_findings for
--      authenticated + anon roles (these rows are non-sensitive
--      scan output and the rest of the schema already exposes
--      them via finding_cves which IS readable by anon).
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 0. Make scan_findings readable by the dashboard
-- -------------------------------------------------------------
DO $grant_select$
BEGIN
  -- Drop any existing read policy with this name so re-running is safe
  IF EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename  = 'scan_findings'
      AND policyname = 'Public can read scan_findings'
  ) THEN
    DROP POLICY "Public can read scan_findings" ON public.scan_findings;
  END IF;
END
$grant_select$;

CREATE POLICY "Public can read scan_findings"
  ON public.scan_findings
  FOR SELECT
  TO anon, authenticated
  USING (true);

GRANT SELECT ON public.scan_findings TO anon, authenticated;

-- -------------------------------------------------------------
-- 1. Recreate the view with real port extraction
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.scanned_assets CASCADE;

CREATE VIEW public.scanned_assets AS
WITH per_target AS (
  SELECT
    sr.target,
    MAX(COALESCE(sr.completed_at, sr.started_at, sr.created_at)) AS last_scan,
    MIN(sr.created_at)                                            AS created_at,
    SUM(sr.critical_count)::int                                   AS sum_critical,
    SUM(sr.high_count)::int                                       AS sum_high,
    SUM(sr.medium_count)::int                                     AS sum_medium,
    SUM(sr.low_count)::int                                        AS sum_low
  FROM public.scan_results sr
  GROUP BY sr.target
),
-- 1a. Ports extracted from finding evidence (NMAP-style "80/tcp open http")
finding_ports AS (
  SELECT DISTINCT
    sr.target,
    (regexp_matches(f.evidence, '(\d{1,5})\s*/\s*(?:tcp|udp)', 'gi'))[1]::int AS port_num
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE f.evidence ~* '\d{1,5}\s*/\s*(?:tcp|udp)'
),
-- 1b. Ports embedded in target URL (e.g. "host:8080" or "https://host:8443/")
url_ports AS (
  SELECT DISTINCT
    sr.target,
    NULLIF(
      (regexp_match(
         regexp_replace(sr.target, '^[a-z]+://', ''),
         '^[^/]*?:(\d{2,5})(?:/|$)'
       ))[1],
      ''
    )::int AS port_num
  FROM public.scan_results sr
  WHERE regexp_replace(sr.target, '^[a-z]+://', '') ~ ':\d{2,5}(/|$)'
),
-- 1c. Default port inferred from URL scheme
scheme_ports AS (
  SELECT DISTINCT
    sr.target,
    CASE
      WHEN sr.target ILIKE 'https://%' THEN 443
      WHEN sr.target ILIKE 'http://%'  THEN 80
      WHEN sr.target ILIKE 'ssh://%'   THEN 22
      WHEN sr.target ILIKE 'ftp://%'   THEN 21
      WHEN sr.target ILIKE 'smb://%'   THEN 445
      ELSE NULL
    END AS port_num
  FROM public.scan_results sr
),
all_ports AS (
  SELECT target, port_num FROM finding_ports WHERE port_num IS NOT NULL
  UNION
  SELECT target, port_num FROM url_ports     WHERE port_num IS NOT NULL
  UNION
  SELECT target, port_num FROM scheme_ports  WHERE port_num IS NOT NULL
),
target_ports AS (
  SELECT
    target,
    string_agg(port_num::text, ', ' ORDER BY port_num) AS port_list
  FROM (SELECT DISTINCT target, port_num FROM all_ports) d
  GROUP BY target
),
target_os AS (
  SELECT
    sr.target,
    CASE
      WHEN BOOL_OR(
             LOWER(f.service) LIKE 'microsoft%'
          OR LOWER(f.service) LIKE 'ms-%'
          OR LOWER(f.service) LIKE '%windows%'
          OR LOWER(f.service) IN ('smb','netbios-ssn','netbios-ns','rdp')
        ) THEN 'Windows'
      WHEN BOOL_OR(
             LOWER(f.service) LIKE '%apache%'
          OR LOWER(f.service) LIKE '%nginx%'
          OR LOWER(f.service) LIKE '%ubuntu%'
          OR LOWER(f.service) LIKE '%debian%'
          OR LOWER(f.service) LIKE '%centos%'
          OR LOWER(f.service) IN ('ssh','telnet','http','https','vsftpd','postfix')
        ) THEN 'Linux/Unix'
      ELSE NULL
    END AS os
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE f.service IS NOT NULL
  GROUP BY sr.target
)
SELECT
  md5('asset|' || pt.target)::uuid       AS id,
  COALESCE(
    NULLIF(regexp_replace(
      regexp_replace(pt.target, '^https?://', ''),
      '/.*$', ''
    ), ''),
    pt.target
  )                                       AS ip_address,
  COALESCE(
    NULLIF(split_part(
      regexp_replace(pt.target, '^https?://', ''),
      '/', 1), ''),
    pt.target
  )                                       AS hostname,
  COALESCE(tos.os, '—')                   AS os,
  COALESCE(tp.port_list, '—')             AS open_ports,
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
LEFT JOIN target_ports tp  ON tp.target  = pt.target
LEFT JOIN target_os    tos ON tos.target = pt.target;

-- -------------------------------------------------------------
-- 2. Grants
-- -------------------------------------------------------------
GRANT SELECT ON public.scanned_assets TO anon, authenticated;

COMMIT;
