-- Multi-tenant foundation for Jam Digital Masjid.
-- Run this file in Supabase SQL Editor before connecting the web app.
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.mosques (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.mosque_members (
  mosque_id uuid not null references public.mosques(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'admin' check (role in ('owner','admin','editor')),
  created_at timestamptz not null default now(),
  primary key (mosque_id, user_id)
);

create table if not exists public.mosque_settings (
  mosque_id uuid primary key references public.mosques(id) on delete cascade,
  settings jsonb not null default '{}'::jsonb,
  background_path text,
  updated_at timestamptz not null default now()
);

create table if not exists public.tv_pairing_codes (
  id uuid primary key default gen_random_uuid(),
  mosque_id uuid not null references public.mosques(id) on delete cascade,
  code_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.tv_devices (
  id uuid primary key default gen_random_uuid(),
  mosque_id uuid not null references public.mosques(id) on delete cascade,
  name text not null default 'Layar masjid',
  token_hash text not null unique,
  last_seen_at timestamptz,
  created_at timestamptz not null default now()
);

create or replace function public.create_tv_pairing_code(target_mosque uuid)
returns text language plpgsql security definer set search_path = '' as $$
declare plain_code text; random_bytes bytea;
begin
  if not exists(select 1 from public.mosque_members m where m.mosque_id = target_mosque and m.user_id = (select auth.uid()) and m.role in ('owner','admin')) then
    raise exception 'Admin access required';
  end if;
  random_bytes := extensions.gen_random_bytes(4);
  plain_code := lpad((mod(get_byte(random_bytes, 0)::bigint * 16777216 + get_byte(random_bytes, 1)::bigint * 65536 + get_byte(random_bytes, 2)::bigint * 256 + get_byte(random_bytes, 3)::bigint, 100000000))::text, 8, '0');
  insert into public.tv_pairing_codes(mosque_id, code_hash, expires_at, created_by)
    values(target_mosque, encode(extensions.digest(plain_code, 'sha256'), 'hex'), now() + interval '10 minutes', (select auth.uid()));
  return plain_code;
end $$;

create or replace function public.is_mosque_member(target_mosque uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists(select 1 from public.mosque_members m where m.mosque_id = target_mosque and m.user_id = (select auth.uid()))
$$;

alter table public.mosques enable row level security;
alter table public.mosque_members enable row level security;
alter table public.mosque_settings enable row level security;
alter table public.tv_pairing_codes enable row level security;
alter table public.tv_devices enable row level security;

drop policy if exists "Members can view their mosque" on public.mosques;
create policy "Members can view their mosque" on public.mosques for select to authenticated using (public.is_mosque_member(id));
drop policy if exists "Members can view membership" on public.mosque_members;
create policy "Members can view membership" on public.mosque_members for select to authenticated using (public.is_mosque_member(mosque_id));
drop policy if exists "Members can read settings" on public.mosque_settings;
create policy "Members can read settings" on public.mosque_settings for select to authenticated using (public.is_mosque_member(mosque_id));
drop policy if exists "Admins can update settings" on public.mosque_settings;
create policy "Admins can update settings" on public.mosque_settings for all to authenticated using (exists(select 1 from public.mosque_members m where m.mosque_id = mosque_settings.mosque_id and m.user_id = (select auth.uid()) and m.role in ('owner','admin'))) with check (exists(select 1 from public.mosque_members m where m.mosque_id = mosque_settings.mosque_id and m.user_id = (select auth.uid()) and m.role in ('owner','admin')));
drop policy if exists "Admins manage pairing codes" on public.tv_pairing_codes;
create policy "Admins manage pairing codes" on public.tv_pairing_codes for all to authenticated using (exists(select 1 from public.mosque_members m where m.mosque_id = tv_pairing_codes.mosque_id and m.user_id = (select auth.uid()) and m.role in ('owner','admin'))) with check (exists(select 1 from public.mosque_members m where m.mosque_id = tv_pairing_codes.mosque_id and m.user_id = (select auth.uid()) and m.role in ('owner','admin')));
drop policy if exists "Admins view devices" on public.tv_devices;
create policy "Admins view devices" on public.tv_devices for select to authenticated using (exists(select 1 from public.mosque_members m where m.mosque_id = tv_devices.mosque_id and m.user_id = (select auth.uid()) and m.role in ('owner','admin')));

-- One-time TV pairing. The TV stores the returned token locally; only its hash is stored.
create or replace function public.pair_tv_device(pair_code text, device_name text default 'Layar masjid')
returns jsonb language plpgsql security definer set search_path = '' as $$
declare pairing public.tv_pairing_codes%rowtype; raw_token text; new_device public.tv_devices%rowtype;
begin
  update public.tv_pairing_codes
    set used_at = now()
    where code_hash = encode(extensions.digest(upper(regexp_replace(pair_code, '[^A-Za-z0-9]', '', 'g')), 'sha256'), 'hex')
      and used_at is null and expires_at > now()
    returning * into pairing;
  if pairing.id is null then raise exception 'Pairing code is invalid, expired, or already used'; end if;
  raw_token := encode(extensions.gen_random_bytes(32), 'hex');
  insert into public.tv_devices(mosque_id, name, token_hash)
    values(pairing.mosque_id, coalesce(nullif(trim(device_name), ''), 'Layar masjid'), encode(extensions.digest(raw_token, 'sha256'), 'hex'))
    returning * into new_device;
  return jsonb_build_object('device_id', new_device.id, 'device_token', raw_token, 'mosque_id', new_device.mosque_id);
end $$;

-- Settings can be fetched by a paired screen without exposing other tenants' rows.
create or replace function public.get_tv_settings(device_token text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare result jsonb;
begin
  update public.tv_devices set last_seen_at = now()
    where token_hash = encode(extensions.digest(device_token, 'sha256'), 'hex');
  if not found then raise exception 'Device is not paired'; end if;
  select jsonb_build_object('settings', s.settings, 'background_path', s.background_path)
    into result from public.tv_devices d left join public.mosque_settings s on s.mosque_id = d.mosque_id
    where d.token_hash = encode(extensions.digest(device_token, 'sha256'), 'hex');
  return coalesce(result, jsonb_build_object('settings', '{}'::jsonb, 'background_path', null));
end $$;

revoke all on function public.pair_tv_device(text, text) from public;
grant execute on function public.pair_tv_device(text, text) to anon, authenticated;
revoke all on function public.create_tv_pairing_code(uuid) from public;
grant execute on function public.create_tv_pairing_code(uuid) to authenticated;
revoke all on function public.get_tv_settings(text) from public;
grant execute on function public.get_tv_settings(text) to anon, authenticated;

-- Storage bucket for mosque backgrounds. Object path starts with the mosque UUID.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('mosque-backgrounds', 'mosque-backgrounds', false, 10485760, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;
drop policy if exists "Mosque members read their backgrounds" on storage.objects;
create policy "Mosque members read their backgrounds" on storage.objects for select to authenticated
using (bucket_id = 'mosque-backgrounds' and public.is_mosque_member((storage.foldername(name))[1]::uuid));
drop policy if exists "Mosque admins upload their backgrounds" on storage.objects;
create policy "Mosque admins upload their backgrounds" on storage.objects for insert to authenticated
with check (bucket_id = 'mosque-backgrounds' and exists(select 1 from public.mosque_members m where m.mosque_id = (storage.foldername(name))[1]::uuid and m.user_id = (select auth.uid()) and m.role in ('owner','admin')));
drop policy if exists "Mosque admins update their backgrounds" on storage.objects;
create policy "Mosque admins update their backgrounds" on storage.objects for update to authenticated
using (bucket_id = 'mosque-backgrounds' and exists(select 1 from public.mosque_members m where m.mosque_id = (storage.foldername(name))[1]::uuid and m.user_id = (select auth.uid()) and m.role in ('owner','admin')))
with check (bucket_id = 'mosque-backgrounds' and exists(select 1 from public.mosque_members m where m.mosque_id = (storage.foldername(name))[1]::uuid and m.user_id = (select auth.uid()) and m.role in ('owner','admin')));
drop policy if exists "Mosque admins delete their backgrounds" on storage.objects;
create policy "Mosque admins delete their backgrounds" on storage.objects for delete to authenticated
using (bucket_id = 'mosque-backgrounds' and exists(select 1 from public.mosque_members m where m.mosque_id = (storage.foldername(name))[1]::uuid and m.user_id = (select auth.uid()) and m.role in ('owner','admin')));

-- Account bootstrap helper. Creates one mosque and owner membership for a new user.
create or replace function public.create_mosque_account(mosque_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare new_id uuid; current_user_id uuid := (select auth.uid());
begin
  if current_user_id is null then raise exception 'Authentication required'; end if;
  if exists(select 1 from public.mosque_members where user_id = current_user_id) then raise exception 'Account already has a mosque'; end if;
  insert into public.mosques(name, owner_id) values(coalesce(nullif(trim(mosque_name), ''), 'Masjid'), current_user_id) returning id into new_id;
  insert into public.mosque_members(mosque_id, user_id, role) values(new_id, current_user_id, 'owner');
  insert into public.mosque_settings(mosque_id) values(new_id);
  return new_id;
end $$;
revoke all on function public.create_mosque_account(text) from public;
grant execute on function public.create_mosque_account(text) to authenticated;
