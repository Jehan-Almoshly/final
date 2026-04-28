-- =============================================================
-- Softer, multi-hue palette for the dashboard donuts
-- =============================================================
-- Replaces the saturated red/orange/yellow heavy palette with a
-- calmer mix that uses cyan, teal, green, purple and pink in
-- addition to the warning hues. All colors stay within the dark
-- theme aesthetic (saturation 50-75%, lightness 55-65%).
-- =============================================================

-- View 1: Vulnerabilities by ExPRT rating
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
    WHEN 'CRITICAL' THEN 'hsl(355 70% 62%)'   -- soft coral red
    WHEN 'HIGH'     THEN 'hsl(25 78% 62%)'    -- soft orange
    WHEN 'MEDIUM'   THEN 'hsl(45 75% 62%)'    -- soft amber
    WHEN 'LOW'      THEN 'hsl(155 50% 55%)'   -- soft green
    ELSE                 'hsl(190 65% 58%)'   -- soft cyan
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


-- View 2: Vulnerabilities by type
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
    WHEN 'Vuln'    THEN 'hsl(355 70% 62%)'    -- soft coral
    WHEN 'Misconf' THEN 'hsl(45 75% 62%)'     -- soft amber
    ELSE                'hsl(265 55% 68%)'    -- soft purple
  END                                                       AS segment_color,
  CASE bucket
    WHEN 'Vuln'    THEN 1
    WHEN 'Misconf' THEN 2
    ELSE                3
  END                                                       AS sort_order
FROM bucketed
GROUP BY bucket
ORDER BY sort_order;


-- View 3: Exploitability risk
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
    WHEN 'Weaponized'  THEN 'hsl(355 70% 62%)'   -- soft coral
    WHEN 'Public PoC'  THEN 'hsl(25 78% 62%)'    -- soft orange
    WHEN 'Known CVE'   THEN 'hsl(45 75% 62%)'    -- soft amber
    ELSE                    'hsl(190 65% 58%)'   -- soft cyan
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


-- View 4: Attack vector
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
    WHEN 'Network'  THEN 'hsl(355 70% 62%)'   -- soft coral
    WHEN 'Adjacent' THEN 'hsl(25 78% 62%)'    -- soft orange
    WHEN 'Local'    THEN 'hsl(190 65% 58%)'   -- soft cyan
    WHEN 'Physical' THEN 'hsl(265 55% 68%)'   -- soft purple
    ELSE                 'hsl(170 45% 55%)'   -- soft teal
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


-- View 5: Exploit types  (no finding-cves join — show all indexed)
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
    WHEN 'Remote'            THEN 'hsl(355 70% 62%)'   -- soft coral
    WHEN 'Web App'           THEN 'hsl(190 65% 58%)'   -- soft cyan
    WHEN 'Local Privilege'   THEN 'hsl(25 78% 62%)'    -- soft orange
    WHEN 'Denial of Service' THEN 'hsl(45 75% 62%)'    -- soft amber
    WHEN 'Shellcode'         THEN 'hsl(265 55% 68%)'   -- soft purple
    WHEN 'Hardware'          THEN 'hsl(335 65% 68%)'   -- soft pink
    WHEN 'Other'             THEN 'hsl(170 45% 55%)'   -- soft teal
    ELSE                          'hsl(155 50% 55%)'   -- soft green
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


-- View 6: Top vulnerable products (soft 7-color palette)
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
    (1, 'hsl(355 70% 62%)'),   -- soft coral
    (2, 'hsl(25 78% 62%)'),    -- soft orange
    (3, 'hsl(45 75% 62%)'),    -- soft amber
    (4, 'hsl(155 50% 55%)'),   -- soft green
    (5, 'hsl(190 65% 58%)'),   -- soft cyan
    (6, 'hsl(265 55% 68%)'),   -- soft purple
    (7, 'hsl(335 65% 68%)')    -- soft pink
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


GRANT SELECT ON
  public.chart_vulns_by_exprt,
  public.chart_findings_by_type,
  public.chart_exploitability_risk,
  public.chart_attack_vector,
  public.chart_exploit_types,
  public.chart_top_vulnerable_products
TO anon, authenticated;
