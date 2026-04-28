-- =============================================================
-- get_user_emails(user_ids)
-- Returns the auth.users.email for a list of auth user_ids.
-- Used by the admin panel to display the creator name of each
-- scan (scan_results.user_id is auth.users.id, but admin_users
-- is keyed by email — so we need this bridge function).
--
-- Restricted to admins via has_role check.
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
