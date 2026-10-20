-- =====================================================================
-- MY VOICE, MY FUTURE — Supabase schema
-- Run this whole file once in Supabase → SQL Editor → New query → Run.
--
-- Design:
--   * voices          → the card content (name, LGA, ward, priority, message)
--   * voice_contacts  → phone + email + consent record, kept in a SEPARATE
--                       table so nothing public can ever expose them
--   * admins          → allow-list of Supabase users who may read the data
--
-- The public website (anon key) has NO direct table access at all.
-- It can only call three functions:
--   submit_voice()    → saves one submission (validated, de-duplicated by phone)
--   public_stats()    → totals by LGA, top wards and priority (counts only, no personal data)
--   public_gallery()  → approved messages (first name + LGA only)
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- TABLES
-- ---------------------------------------------------------------------
create table if not exists public.voices (
  id               uuid primary key default gen_random_uuid(),
  full_name        text not null check (char_length(full_name) between 2 and 60),
  lga              text not null check (char_length(lga) between 2 and 40),
  ward             text not null check (char_length(ward) between 1 and 60),
  priority         text not null check (priority in
                     ('education','health','agriculture','jobs','infrastructure','security','water','women_youth')),
  message          text not null check (char_length(message) between 3 and 180),
  lang             text not null default 'en' check (lang in ('en','ha')),
  show_in_gallery  boolean not null default false,   -- supporter opted in
  approved         boolean not null default false,   -- admin approved for gallery
  created_at       timestamptz not null default now()
);

create table if not exists public.voice_contacts (
  voice_id         uuid primary key references public.voices(id) on delete cascade,
  phone            text not null unique check (phone ~ '^\+234[789][01][0-9]{8}$'),
  email            text check (email is null or email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  consent_contact  boolean not null check (consent_contact = true),
  consent_text     text not null,
  consent_at       timestamptz not null default now(),
  opted_out        boolean not null default false,
  opted_out_at     timestamptz
);

create table if not exists public.admins (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  added_at   timestamptz not null default now()
);

create index if not exists voices_lga_idx      on public.voices (lga);
create index if not exists voices_priority_idx on public.voices (priority);
create index if not exists voices_created_idx  on public.voices (created_at desc);
create index if not exists voices_lga_ward_idx on public.voices (lga, ward);
create index if not exists voices_gallery_idx  on public.voices (created_at desc)
  where approved and show_in_gallery;

-- ---------------------------------------------------------------------
-- ROW LEVEL SECURITY — everything locked by default
-- ---------------------------------------------------------------------
alter table public.voices         enable row level security;
alter table public.voice_contacts enable row level security;
alter table public.admins         enable row level security;

create or replace function public.is_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

-- Admins (and only admins) can read and moderate.
drop policy if exists voices_admin_select on public.voices;
create policy voices_admin_select on public.voices
  for select to authenticated using (public.is_admin());

drop policy if exists voices_admin_update on public.voices;
create policy voices_admin_update on public.voices
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists voices_admin_delete on public.voices;
create policy voices_admin_delete on public.voices
  for delete to authenticated using (public.is_admin());

drop policy if exists contacts_admin_select on public.voice_contacts;
create policy contacts_admin_select on public.voice_contacts
  for select to authenticated using (public.is_admin());

drop policy if exists contacts_admin_update on public.voice_contacts;
create policy contacts_admin_update on public.voice_contacts
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists admins_self_select on public.admins;
create policy admins_self_select on public.admins
  for select to authenticated using (user_id = auth.uid());

-- No insert policies for anon: the website can only write through submit_voice().
revoke all on public.voices, public.voice_contacts, public.admins from anon;

-- ---------------------------------------------------------------------
-- SUBMIT (called by the public website)
-- Returns: { status: 'created' | 'exists', total: <int> }
-- ---------------------------------------------------------------------
create or replace function public.submit_voice(
  p_full_name        text,
  p_phone            text,
  p_email            text,
  p_lga              text,
  p_ward             text,
  p_priority         text,
  p_message          text,
  p_lang             text,
  p_show_in_gallery  boolean,
  p_consent_contact  boolean,
  p_consent_text     text
)
returns json
language plpgsql security definer
set search_path = public
as $$
declare
  v_phone  text;
  v_email  text;
  v_id     uuid;
  v_total  bigint;
begin
  if coalesce(p_consent_contact, false) is not true then
    raise exception 'consent_required' using errcode = '22023';
  end if;

  -- Normalise Nigerian phone numbers to +234XXXXXXXXXX
  v_phone := regexp_replace(coalesce(p_phone, ''), '[^0-9+]', '', 'g');
  if v_phone ~ '^0[789][01][0-9]{8}$' then
    v_phone := '+234' || substr(v_phone, 2);
  elsif v_phone ~ '^234[789][01][0-9]{8}$' then
    v_phone := '+' || v_phone;
  end if;
  if v_phone !~ '^\+234[789][01][0-9]{8}$' then
    raise exception 'invalid_phone' using errcode = '22023';
  end if;

  v_email := nullif(lower(trim(coalesce(p_email, ''))), '');

  -- One submission per phone number
  if exists (select 1 from voice_contacts where phone = v_phone) then
    select count(*) into v_total from voices;
    return json_build_object('status', 'exists', 'total', v_total);
  end if;

  begin
    insert into voices (full_name, lga, ward, priority, message, lang, show_in_gallery)
    values (trim(p_full_name), trim(p_lga), trim(p_ward), p_priority,
            trim(p_message), coalesce(p_lang, 'en'), coalesce(p_show_in_gallery, false))
    returning id into v_id;

    insert into voice_contacts (voice_id, phone, email, consent_contact, consent_text)
    values (v_id, v_phone, v_email, true, left(coalesce(p_consent_text, ''), 1000));
  exception when unique_violation then
    -- Two submissions with the same number at the same moment
    select count(*) into v_total from voices;
    return json_build_object('status', 'exists', 'total', v_total);
  end;

  select count(*) into v_total from voices;
  return json_build_object('status', 'created', 'total', v_total);
end;
$$;

-- ---------------------------------------------------------------------
-- PUBLIC STATS (counts only — no personal data)
-- ---------------------------------------------------------------------
create or replace function public.public_stats()
returns json
language sql stable security definer
set search_path = public
as $$
  select json_build_object(
    'total', (select count(*) from voices),
    'by_lga', coalesce((
      select json_agg(x order by x.n desc)
      from (select lga, count(*) as n from voices group by lga) x), '[]'::json),
    'by_priority', coalesce((
      select json_agg(y order by y.n desc)
      from (select priority, count(*) as n from voices group by priority) y), '[]'::json),
    -- Top 10 wards. Ward names can repeat across LGAs, so each ward is ranked with its LGA,
    -- and typed ward names are matched regardless of case or extra spaces.
    'top_wards', coalesce((
      select json_agg(w order by w.n desc)
      from (select min(trim(ward)) as ward, lga, count(*) as n
            from voices group by lga, lower(regexp_replace(trim(ward), '\s+', ' ', 'g'))
            order by n desc limit 10) w), '[]'::json)
  );
$$;

-- ---------------------------------------------------------------------
-- PUBLIC GALLERY (approved + opted-in only; first name and LGA only)
-- ---------------------------------------------------------------------
create or replace function public.public_gallery(p_limit int default 24, p_lga text default null)
returns table (first_name text, lga text, priority text, message text, lang text, created_at timestamptz)
language sql stable security definer
set search_path = public
as $$
  select split_part(trim(full_name), ' ', 1), lga, priority, message, lang, created_at
  from voices
  where approved and show_in_gallery
    and (p_lga is null or lga = p_lga)
  order by created_at desc
  limit least(greatest(coalesce(p_limit, 24), 1), 100);
$$;

-- ---------------------------------------------------------------------
-- ADMIN REPORT: what each LGA cares about (admins only)
-- ---------------------------------------------------------------------
create or replace function public.admin_lga_priority()
returns table (lga text, priority text, n bigint)
language plpgsql stable security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  return query select v.lga, v.priority, count(*)::bigint from voices v group by v.lga, v.priority;
end;
$$;

revoke all on function public.submit_voice(text,text,text,text,text,text,text,text,boolean,boolean,text) from public;
revoke all on function public.public_stats() from public;
revoke all on function public.public_gallery(int, text) from public;
grant execute on function public.submit_voice(text,text,text,text,text,text,text,text,boolean,boolean,text) to anon, authenticated;
grant execute on function public.public_stats() to anon, authenticated;
grant execute on function public.public_gallery(int, text) to anon, authenticated;
grant execute on function public.is_admin() to authenticated;
revoke all on function public.admin_lga_priority() from public;
grant execute on function public.admin_lga_priority() to authenticated;

-- ---------------------------------------------------------------------
-- MAKE YOURSELF AN ADMIN
-- 1. Supabase → Authentication → Users → Add user (email + password)
-- 2. Run the line below with that email:
--
--   insert into public.admins (user_id)
--   select id from auth.users where email = 'you@example.com';
-- ---------------------------------------------------------------------
