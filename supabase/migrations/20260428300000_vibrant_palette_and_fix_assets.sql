-- =============================================================
-- 1) Vibrant per-chart palette (per user request)
-- 2) Fix scanned_assets view: real OPEN PORTS + smarter OS
-- =============================================================

-- -------------------------------------------------------------
-- View 1: Vulnerabilities by ExPRT rating  →  red / orange / yellow
-- -------------------------------------------------------------
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
    WHEN 'CRITICAL' THEN 'hsl(0 85% 58%)'      -- vivid red
    WHEN 'HIGH'     THEN 'hsl(20 95% 60%)'     -- vivid orange
    WHEN 'MEDIUM'   THEN 'hsl(45 95% 58%)'     -- vivid yellow
    WHEN 'LOW'      THEN 'hsl(35 90% 65%)'     -- light orange
    ELSE                 'hsl(55 80% 65%)'     -- light yellow
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
-- View 2: Vulnerabilities by type  →  red for Vuln / purple for Misconf
-- -------------------------------------------------------------
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
    WHEN 'Vuln'    THEN 'hsl(0 85% 58%)'      -- vivid red
    WHEN 'Misconf' THEN 'hsl(275 75% 65%)'    -- vivid purple
    ELSE                'hsl(195 90% 55%)'    -- vivid cyan
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
-- View 3: Exploitability risk  →  shades of green
-- -------------------------------------------------------------
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
    WHEN 'Weaponized'  THEN 'hsl(140 75% 45%)'   -- deep emerald
    WHEN 'Public PoC'  THEN 'hsl(155 70% 50%)'   -- vibrant green
    WHEN 'Known CVE'   THEN 'hsl(120 60% 55%)'   -- mid green
    ELSE                    'hsl(95 60% 60%)'    -- yellow-green
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
-- View 4: Attack vector  →  pinks / roses
-- -------------------------------------------------------------
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
    WHEN 'Network'  THEN 'hsl(335 85% 60%)'   -- hot pink
    WHEN 'Adjacent' THEN 'hsl(350 85% 65%)'   -- coral pink
    WHEN 'Local'    THEN 'hsl(315 80% 65%)'   -- magenta
    WHEN 'Physical' THEN 'hsl(290 70% 65%)'   -- violet pink
    ELSE                 'hsl(300 50% 65%)'   -- mauve
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
-- View 5: Exploit types  →  vibrant mixed palette
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.chart_exploit_types AS
WITH typed AS (
  SELECT LOWER(COALESCE(NULLIF(TRIM(e.type), ''), 'unknown')) AS t
  FROM public.exploits e
),
labelled AS (
  SELECT
    CASE t
      WHEN 'remote'    THEN 'Remote'
      WHEN 'local'     THEN 'Local Privilege'
      WHEN 'webapps'   THEN 'Web App'
      WHEN 'dos'       THEN 'Denial of Service'
      WHEN 'shellcode' THEN 'Shellcode'
      WHEN 'hardware'  THEN 'Hardware'
      WHEN 'unknown'   THEN 'Other'
      ELSE                  INITCAP(t)
    END AS label
  FROM typed
)
SELECT
  label                                                     AS segment_name,
  COUNT(*)::int                                             AS segment_value,
  CASE label
    WHEN 'Remote'            THEN 'hsl(0 85% 58%)'     -- red
    WHEN 'Web App'           THEN 'hsl(195 90% 55%)'   -- cyan
    WHEN 'Local Privilege'   THEN 'hsl(20 95% 60%)'    -- orange
    WHEN 'Denial of Service' THEN 'hsl(45 95% 58%)'    -- yellow
    WHEN 'Shellcode'         THEN 'hsl(275 75% 65%)'   -- purple
    WHEN 'Hardware'          THEN 'hsl(335 85% 60%)'   -- pink
    WHEN 'Other'             THEN 'hsl(160 70% 50%)'   -- emerald
    ELSE                          'hsl(140 75% 50%)'   -- green
  END                                                       AS segment_color,
  CASE label
    WHEN 'Remote'            THEN 1
    WHEN 'Web App'           THEN 2
    WHEN 'Local Privilege'   THEN 3
    WHEN 'Denial of Service' THEN 4
    WHEN 'Shellcode'         THEN 5
    WHEN 'Hardware'          THEN 6
    WHEN 'Other'             THEN 9
    ELSE                          7
  END                                                       AS sort_order
FROM labelled
GROUP BY label
ORDER BY sort_order, label;


-- -------------------------------------------------------------
-- View 6: Top vulnerable products  →  vibrant cyan palette
-- -------------------------------------------------------------
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
    (1, 'hsl(185 95% 55%)'),   -- vivid cyan
    (2, 'hsl(195 90% 60%)'),   -- sky cyan
    (3, 'hsl(175 85% 50%)'),   -- teal
    (4, 'hsl(205 90% 65%)'),   -- sky blue
    (5, 'hsl(165 80% 50%)'),   -- minty teal
    (6, 'hsl(215 85% 65%)'),   -- blue
    (7, 'hsl(190 70% 70%)')    -- pale cyan
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


-- =============================================================
-- 7) FIX scanned_assets view
-- =============================================================
-- Old behavior:
--   * OS column was hard-coded to 'unknown' (literal string)
--   * OPEN PORTS was parsed from `scan_findings.target` — a column
--     that doesn't exist on scan_findings, so the value was always
--     NULL/empty.
--
-- New behavior:
--   * OS column is inferred from observed `scan_findings.service`:
--       Windows: microsoft-*, ms-*, smb, netbios-*, rdp
--       Linux/Unix: ssh, telnet, http(s), nginx, apache, vsftp
--       fallback: '—'  (instead of literal 'unknown')
--   * OPEN PORTS column is now a comma-separated, sorted, distinct
--     list of real ports from `scan_findings.port` (the actual
--     INTEGER column populated by the Kali agent).
-- =============================================================

DROP VIEW IF EXISTS public.scanned_assets CASCADE;

CREATE OR REPLACE VIEW public.scanned_assets AS
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
target_ports AS (
  SELECT
    target,
    string_agg(port_text, ', ' ORDER BY port_num) AS port_list
  FROM (
    SELECT DISTINCT
      sr.target,
      f.port           AS port_num,
      f.port::text     AS port_text
    FROM public.scan_findings f
    JOIN public.scan_results sr ON sr.id = f.scan_result_id
    WHERE f.port IS NOT NULL
  ) deduped
  GROUP BY target
),
target_os AS (
  SELECT
    sr.target,
    CASE
      WHEN BOOL_OR(
             LOWER(f.service) LIKE 'microsoft-%'
          OR LOWER(f.service) LIKE 'ms-%'
          OR LOWER(f.service) IN ('smb','netbios-ssn','netbios-ns','rdp')
        ) THEN 'Windows'
      WHEN BOOL_OR(
             LOWER(f.service) IN ('ssh','telnet','http','https','nginx','apache','vsftpd','postfix')
        ) THEN 'Linux/Unix'
      ELSE NULL
    END AS os
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_result_id
  WHERE f.service IS NOT NULL
  GROUP BY sr.target
)
SELECT
  md5('asset|' || pt.target)::uuid       AS id,
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
LEFT JOIN target_ports tp ON tp.target = pt.target
LEFT JOIN target_os    tos ON tos.target = pt.target;


-- -------------------------------------------------------------
-- Grants
-- -------------------------------------------------------------
GRANT SELECT ON
  public.chart_vulns_by_exprt,
  public.chart_findings_by_type,
  public.chart_exploitability_risk,
  public.chart_attack_vector,
  public.chart_exploit_types,
  public.chart_top_vulnerable_products,
  public.scanned_assets
TO anon, authenticated;
