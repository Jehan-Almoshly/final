-- ================================================
-- DELTA MIGRATION - Backend Tables (New Only)
-- Run this ONCE in Supabase SQL Editor
-- These are the ONLY things missing from your DB
-- ================================================


-- 1. Add missing columns to existing tables
-- ================================================

-- Add user_id to scan_results (missing from frontend migration)
ALTER TABLE public.scan_results
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL;

-- Add level column to system_logs (missing from frontend migration)
ALTER TABLE public.system_logs
  ADD COLUMN IF NOT EXISTS level TEXT DEFAULT 'info';


-- 2. Create nvd_cves table (brand new - not in frontend)
-- ================================================
CREATE TABLE IF NOT EXISTS public.nvd_cves (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL UNIQUE,
  description TEXT,
  cvss_score REAL,
  severity TEXT,
  published_date TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.nvd_cves ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public can read CVEs"
  ON public.nvd_cves FOR SELECT USING (true);

CREATE POLICY "Authenticated can insert CVEs"
  ON public.nvd_cves FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated can update CVEs"
  ON public.nvd_cves FOR UPDATE TO authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_nvd_cves_cve_id ON public.nvd_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_nvd_cves_severity ON public.nvd_cves(severity);


-- 3. Create exploits table (brand new - not in frontend)
-- ================================================
CREATE TABLE IF NOT EXISTS public.exploits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  exploit_id TEXT NOT NULL UNIQUE,
  description TEXT,
  cve_id TEXT,
  file_path TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.exploits ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public can read exploits"
  ON public.exploits FOR SELECT USING (true);

CREATE POLICY "Authenticated can manage exploits"
  ON public.exploits FOR ALL TO authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON public.exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_exploit_id ON public.exploits(exploit_id);

-- Add index on scan_results user_id
CREATE INDEX IF NOT EXISTS idx_scan_results_user_id ON public.scan_results(user_id);


-- ================================================
-- DONE! Only these 4 things were added:
-- 1. user_id column in scan_results
-- 2. level column in system_logs
-- 3. nvd_cves table (new)
-- 4. exploits table (new)
-- ================================================
