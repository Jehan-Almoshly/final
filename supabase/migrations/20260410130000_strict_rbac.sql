-- RBAC Policies تحديث سياسات الصلاحيات
-- =============================================

-- حذف السياسات القديمة لـ user_roles
DROP POLICY IF EXISTS "Users can view own roles" ON public.user_roles;
DROP POLICY IF EXISTS "Users can view all scans" ON public.scan_results;
DROP POLICY IF EXISTS "Users can create own scans" ON public.scan_results;
DROP POLICY IF EXISTS "Users can update own scans" ON public.scan_results;
DROP POLICY IF EXISTS "Users can delete own scans" ON public.scan_results;
DROP POLICY IF EXISTS "Admins can update any scan" ON public.scan_results;

-- =============================================
-- سياسات user_roles
-- =============================================

CREATE POLICY "Users can view own role"
  ON public.user_roles FOR SELECT TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Admins can manage all roles"
  ON public.user_roles FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- =============================================
-- سياسات admin_users
-- =============================================

DROP POLICY IF EXISTS "Users can view admin_users" ON public.admin_users;
DROP POLICY IF EXISTS "Admins can manage admin_users" ON public.admin_users;

CREATE POLICY "Authenticated can view admin_users"
  ON public.admin_users FOR SELECT TO authenticated USING (true);

CREATE POLICY "Admins can insert admin_users"
  ON public.admin_users FOR INSERT TO authenticated
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can update admin_users"
  ON public.admin_users FOR UPDATE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can delete admin_users"
  ON public.admin_users FOR DELETE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

-- =============================================
-- إضافة سياسة admins يرون كل الأدوار
-- =============================================

DROP POLICY IF EXISTS "Admins can view all roles" ON public.user_roles;
CREATE POLICY "Admins can view all roles"
  ON public.user_roles FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));
