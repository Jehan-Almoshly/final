-- جدول روابط الدعوة
CREATE TABLE IF NOT EXISTS public.invitation_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token text NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(32), 'hex'),
  created_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  max_uses integer DEFAULT 1,
  uses_count integer DEFAULT 0,
  expires_at timestamp with time zone,
  is_active boolean DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE public.invitation_links ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins can manage invitation links"
  ON public.invitation_links FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));


-- جدول لتتبع من استخدم الرابط
CREATE TABLE IF NOT EXISTS public.invitation_usages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  invitation_id uuid NOT NULL REFERENCES public.invitation_links(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  used_at timestamp with time zone NOT NULL DEFAULT now(),
  UNIQUE(invitation_id, user_id)
);

ALTER TABLE public.invitation_usages ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins can view invitation usages"
  ON public.invitation_usages FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));


-- دالة للتحقق من صلاحية الرابط
CREATE OR REPLACE FUNCTION public.validate_invitation_token(token_param text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  invitation_record RECORD;
BEGIN
  SELECT * INTO invitation_record
  FROM public.invitation_links
  WHERE token = token_param
    AND is_active = true
    AND (expires_at IS NULL OR expires_at > now())
    AND (max_uses IS NULL OR uses_count < max_uses);

  IF invitation_record IS NULL THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Invalid or expired invitation link');
  END IF;

  RETURN jsonb_build_object('valid', true, 'invitation_id', invitation_record.id);
END;
$$;


-- دالة لتسجيل استخدام الرابط
CREATE OR REPLACE FUNCTION public.use_invitation_token(token_param text, user_id_param uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  invitation_record RECORD;
BEGIN
  SELECT * INTO invitation_record
  FROM public.invitation_links
  WHERE token = token_param
    AND is_active = true
    AND (expires_at IS NULL OR expires_at > now())
    AND (max_uses IS NULL OR uses_count < max_uses);

  IF invitation_record IS NULL THEN
    RETURN false;
  END IF;

  INSERT INTO public.invitation_usages (invitation_id, user_id)
  VALUES (invitation_record.id, user_id_param)
  ON CONFLICT DO NOTHING;

  UPDATE public.invitation_links
  SET uses_count = uses_count + 1
  WHERE id = invitation_record.id;

  INSERT INTO public.user_roles (user_id, role)
  VALUES (user_id_param, 'user')
  ON CONFLICT (user_id) DO NOTHING;

  RETURN true;
END;
$$;
