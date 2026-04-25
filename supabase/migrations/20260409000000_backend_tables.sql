-- Backend Tables Migration for Vulnerability Manager
-- ============================================

-- 1. Create ENUMS
-- ============================================

CREATE TYPE IF NOT EXISTS public.severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE IF NOT EXISTS public.vuln_status AS ENUM ('open', 'in_progress', 'resolved', 'accepted');
CREATE TYPE IF NOT EXISTS public.scan_status AS ENUM ('pending', 'running', 'completed', 'failed');
CREATE TYPE IF NOT EXISTS public.scan_tool AS ENUM ('nmap', 'sqlmap', 'nikto', 'ffuf', 'other');


-- 2. Create NVD CVEs Table
-- ============================================
CREATE TABLE IF NOT EXISTS public.nvd_cves (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL UNIQUE,
  description TEXT,
  cvss_score REAL,
  severity TEXT,
  published_date TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);


-- 3. Create Scan Results Table (with all required columns)
-- ============================================
CREATE TABLE IF NOT EXISTS public.scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  target TEXT NOT NULL,
  tool TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  description TEXT,
  options TEXT,
  started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  critical_count INTEGER NOT NULL DEFAULT 0,
  high_count INTEGER NOT NULL DEFAULT 0,
  medium_count INTEGER NOT NULL DEFAULT 0,
  low_count INTEGER NOT NULL DEFAULT 0,
  total_findings INTEGER NOT NULL DEFAULT 0
);


-- 4. Create Vulnerabilities Table (matching Drizzle schema)
-- ============================================
CREATE TABLE IF NOT EXISTS public.vulnerabilities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL,
  cvss_severity TEXT NOT NULL DEFAULT 'medium',
  status TEXT NOT NULL DEFAULT 'open',
  exploit_status TEXT NOT NULL DEFAULT 'none',
  exprt_rating TEXT NOT NULL DEFAULT 'low',
  remediations INTEGER NOT NULL DEFAULT 0,
  vulnerability_count INTEGER NOT NULL DEFAULT 1,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);


-- 5. Create Exploits Table
-- ============================================
CREATE TABLE IF NOT EXISTS public.exploits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  exploit_id TEXT NOT NULL UNIQUE,
  description TEXT,
  cve_id TEXT,
  file_path TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);


-- 6. Create System Logs Table
-- ============================================
CREATE TABLE IF NOT EXISTS public.system_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message TEXT NOT NULL,
  level TEXT DEFAULT 'info',
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  sort_order INTEGER NOT NULL DEFAULT 0
);


-- ============================================
-- 7. Enable Row Level Security (RLS)
-- ============================================

ALTER TABLE public.nvd_cves ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exploits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_logs ENABLE ROW LEVEL SECURITY;


-- ============================================
-- 8. RLS Policies - NVD CVEs (Public Read)
-- ============================================

CREATE POLICY "Public can read CVEs"
  ON public.nvd_cves FOR SELECT USING (true);

CREATE POLICY "Authenticated can insert CVEs"
  ON public.nvd_cves FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Authenticated can update CVEs"
  ON public.nvd_cves FOR UPDATE TO authenticated USING (true);


-- ============================================
-- 9. RLS Policies - Scan Results
-- ============================================

CREATE POLICY "Authenticated can view scan_results"
  ON public.scan_results FOR SELECT TO authenticated USING (true);

CREATE POLICY "Admins can create scan_results"
  ON public.scan_results FOR INSERT TO authenticated
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can update scan_results"
  ON public.scan_results FOR UPDATE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can delete scan_results"
  ON public.scan_results FOR DELETE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));


-- ============================================
-- 10. RLS Policies - Vulnerabilities
-- ============================================

CREATE POLICY "Users can view vulnerabilities"
  ON public.vulnerabilities FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated can create vulnerabilities"
  ON public.vulnerabilities FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Users can update vulnerabilities"
  ON public.vulnerabilities FOR UPDATE TO authenticated USING (true);

CREATE POLICY "Admins can delete vulnerabilities"
  ON public.vulnerabilities FOR DELETE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));


-- ============================================
-- 11. RLS Policies - Exploits (Public Read)
-- ============================================

CREATE POLICY "Public can read exploits"
  ON public.exploits FOR SELECT USING (true);

CREATE POLICY "Authenticated can manage exploits"
  ON public.exploits FOR ALL TO authenticated USING (true);


-- ============================================
-- 12. RLS Policies - System Logs (Admin Only)
-- ============================================

CREATE POLICY "Admins can read logs"
  ON public.system_logs FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Service can insert logs"
  ON public.system_logs FOR INSERT TO service_role WITH CHECK (true);


-- ============================================
-- 13. Create Indexes for Performance
-- ============================================

CREATE INDEX IF NOT EXISTS idx_nvd_cves_cve_id ON public.nvd_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_nvd_cves_severity ON public.nvd_cves(severity);

CREATE INDEX IF NOT EXISTS idx_scan_results_user_id ON public.scan_results(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_status ON public.scan_results(status);
CREATE INDEX IF NOT EXISTS idx_scan_results_started_at ON public.scan_results(started_at DESC);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON public.vulnerabilities(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON public.vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON public.vulnerabilities(cve_id);

CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON public.exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_exploit_id ON public.exploits(exploit_id);

CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON public.system_logs(timestamp DESC);


-- ============================================
-- 14. Triggers and Functions
-- ============================================

CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;
