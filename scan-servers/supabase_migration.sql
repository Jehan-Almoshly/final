-- =============================================================
-- Scan System Migration
-- Run this in Supabase SQL Editor
-- =============================================================


-- 1. Add raw_output column to scan_results
ALTER TABLE scan_results
ADD COLUMN IF NOT EXISTS raw_output TEXT;

-- 2. Add user_id column to scan_results (as TEXT to avoid uuid/text conflicts)
ALTER TABLE scan_results
ADD COLUMN IF NOT EXISTS user_id TEXT;


-- =============================================================
-- Row Level Security
-- =============================================================

ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;

-- Drop old policies first to avoid conflicts
DROP POLICY IF EXISTS "Admins can manage all scans" ON scan_results;
DROP POLICY IF EXISTS "Users can read own scans" ON scan_results;

-- Admins can do everything
-- Uses email comparison (TEXT = TEXT, no casting issues)
CREATE POLICY "Admins can manage all scans"
ON scan_results
FOR ALL
TO authenticated
USING (
  EXISTS (
    SELECT 1
    FROM admin_users
    WHERE admin_users.email = (auth.jwt() ->> 'email')
      AND admin_users.role = 'admin'
  )
);

-- Users can read their own scans
-- Cast both sides to TEXT to avoid uuid vs text mismatch
CREATE POLICY "Users can read own scans"
ON scan_results
FOR SELECT
TO authenticated
USING (
  user_id::text = auth.uid()::text
);


-- =============================================================
-- Function: get_scan_status
-- Cast id to TEXT to avoid uuid vs text mismatch
-- =============================================================
DROP FUNCTION IF EXISTS get_scan_status(TEXT);

CREATE FUNCTION get_scan_status(p_scan_id TEXT)
RETURNS TABLE(
  id        TEXT,
  name      TEXT,
  target    TEXT,
  tool      TEXT,
  status    TEXT,
  raw_output TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  total_findings INTEGER
)
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
  SELECT
    s.id::text,
    s.name,
    s.target,
    s.tool,
    s.status,
    s.raw_output,
    s.started_at,
    s.completed_at,
    s.total_findings
  FROM scan_results s
  WHERE s.id::text = p_scan_id;
$$;


-- =============================================================
-- View: running_scans
-- Cast id and user_id to TEXT for safety
-- =============================================================
DROP VIEW IF EXISTS running_scans;

CREATE VIEW running_scans AS
SELECT
  id::text    AS id,
  name,
  target,
  tool,
  status,
  started_at,
  user_id::text AS user_id
FROM scan_results
WHERE status = 'running'
ORDER BY started_at DESC;


-- =============================================================
-- 6. get_user_emails RPC for AdminPanel
-- Returns auth.users.email for a list of auth user_ids.
-- Admin-only (checked via has_role).
-- =============================================================
CREATE OR REPLACE FUNCTION public.get_user_emails(user_ids text[])
RETURNS TABLE(user_id text, email text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
  IF NOT public.has_role(auth.uid(), 'admin') THEN
    RAISE EXCEPTION 'Admin access required';
  END IF;

  RETURN QUERY
    SELECT u.id::text, u.email::text
    FROM auth.users u
    WHERE u.id::text = ANY(user_ids);
END;
$$;

REVOKE ALL ON FUNCTION public.get_user_emails(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_user_emails(text[]) TO authenticated;


-- =============================================================
-- Done!
-- =============================================================
