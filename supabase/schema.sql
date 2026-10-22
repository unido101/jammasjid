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

create table if not exists public.app_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.mosque_licenses (
  id uuid primary key default gen_random_uuid(),
  mosque_id uuid not null unique references public.mosques(id) on delete cascade,
  code_hash text not null unique,
  code_hint text not null,
  device_limit integer not null default 1 check(device_limit between 1 and 20),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

alter table public.tv_devices add column if not exists license_id uuid references public.mosque_licenses(id) on delete cascade;

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
alter table public.app_admins enable row level security;
alter table public.mosque_licenses enable row level security;

grant select on public.mosques, public.mosque_members, public.mosque_settings, public.tv_devices to authenticated;
grant update on public.mosques to authenticated;
grant insert, update on public.mosque_settings to authenticated;

drop policy if exists "Members can view their mosque" on public.mosques;
create policy "Members can view their mosque" on public.mosques for select to authenticated using (public.is_mosque_member(id));
drop policy if exists "Admins can update mosque profile" on public.mosques;
create policy "Admins can update mosque profile" on public.mosques for update to authenticated using (exists(select 1 from public.mosque_members m where m.mosque_id = mosques.id and m.user_id = (select auth.uid()) and m.role in ('owner','admin'))) with check (exists(select 1 from public.mosque_members m where m.mosque_id = mosques.id and m.user_id = (select auth.uid()) and m.role in ('owner','admin')));
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
  select jsonb_build_object('settings', s.settings, 'background_path', s.background_path, 'mosque_id', d.mosque_id)
    into result from public.tv_devices d left join public.mosque_settings s on s.mosque_id = d.mosque_id
    left join public.mosque_licenses l on l.id = d.license_id
    where d.token_hash = encode(extensions.digest(device_token, 'sha256'), 'hex') and d.license_id is not null and l.active;
  if result is null then raise exception 'License is inactive or device is not paired'; end if;
  return coalesce(result, jsonb_build_object('settings', '{}'::jsonb, 'background_path', null));
end $$;

create or replace function public.is_app_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists(select 1 from public.app_admins where user_id = (select auth.uid()))
$$;

create or replace function public.admin_create_license(mosque_name text, device_limit integer default 1)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare current_user_id uuid := (select auth.uid()); new_mosque uuid; new_license uuid; raw_code text;
begin
  if current_user_id is null or not public.is_app_admin() then raise exception 'Administrator access required'; end if;
  if device_limit < 1 or device_limit > 20 then raise exception 'Device limit must be between 1 and 20'; end if;
  insert into public.mosques(name, owner_id) values(coalesce(nullif(trim(mosque_name), ''), 'Masjid'), current_user_id) returning id into new_mosque;
  insert into public.mosque_members(mosque_id, user_id, role) values(new_mosque, current_user_id, 'owner');
  insert into public.mosque_settings(mosque_id, settings) values(new_mosque, jsonb_build_object('mosqueName',coalesce(nullif(trim(mosque_name), ''),'Masjid')));
  raw_code := upper(encode(extensions.gen_random_bytes(12), 'hex'));
  insert into public.mosque_licenses(mosque_id,code_hash,code_hint,device_limit)
    values(new_mosque,encode(extensions.digest(raw_code,'sha256'),'hex'),right(raw_code,4),device_limit) returning id into new_license;
  return jsonb_build_object('license_id',new_license,'mosque_id',new_mosque,'mosque_name',coalesce(nullif(trim(mosque_name), ''),'Masjid'),'license_code',raw_code,'device_limit',device_limit);
end $$;

create or replace function public.admin_list_licenses()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_app_admin() then raise exception 'Administrator access required'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id',l.id,'mosque_id',m.id,'mosque_name',m.name,'code_hint',l.code_hint,'device_limit',l.device_limit,'active',l.active,'created_at',l.created_at,'device_count',(select count(*) from public.tv_devices d where d.license_id=l.id)) order by l.created_at desc) from public.mosque_licenses l join public.mosques m on m.id=l.mosque_id),'[]'::jsonb);
end $$;

create or replace function public.admin_set_license_active(license_id uuid, make_active boolean)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_app_admin() then raise exception 'Administrator access required'; end if;
  update public.mosque_licenses set active=make_active,revoked_at=case when make_active then null else now() end where id=license_id;
  return found;
end $$;

create or replace function public.admin_reset_license_devices(target_license uuid)
returns integer language plpgsql security definer set search_path = '' as $$
declare removed integer;
begin
  if not public.is_app_admin() then raise exception 'Administrator access required'; end if;
  delete from public.tv_devices where tv_devices.license_id=target_license;
  get diagnostics removed = row_count;
  return removed;
end $$;

create or replace function public.activate_license(license_code text, device_name text default 'Layar masjid')
returns jsonb language plpgsql security definer set search_path = '' as $$
declare license public.mosque_licenses%rowtype; raw_token text; new_device public.tv_devices%rowtype; normalized_code text;
begin
  normalized_code := upper(regexp_replace(license_code,'[^A-Za-z0-9]','','g'));
  select * into license from public.mosque_licenses where code_hash=encode(extensions.digest(normalized_code,'sha256'),'hex') for update;
  if license.id is null or not license.active then raise exception 'Kode tidak valid atau lisensi sudah dinonaktifkan'; end if;
  if (select count(*) from public.tv_devices where license_id=license.id) >= license.device_limit then raise exception 'Batas jumlah TV untuk lisensi ini sudah tercapai'; end if;
  raw_token := encode(extensions.gen_random_bytes(32),'hex');
  insert into public.tv_devices(mosque_id,license_id,name,token_hash) values(license.mosque_id,license.id,coalesce(nullif(trim(device_name),''),'Layar masjid'),encode(extensions.digest(raw_token,'sha256'),'hex')) returning * into new_device;
  return jsonb_build_object('device_id',new_device.id,'device_token',raw_token,'mosque_id',new_device.mosque_id);
end $$;

create or replace function public.save_tv_settings(device_token text, new_settings jsonb)
returns boolean language plpgsql security definer set search_path = '' as $$
declare target public.tv_devices%rowtype;
begin
  select d.* into target from public.tv_devices d left join public.mosque_licenses l on l.id=d.license_id
    where d.token_hash=encode(extensions.digest(device_token,'sha256'),'hex') and d.license_id is not null and l.active for update of d;
  if target.id is null then raise exception 'License is inactive or device is not paired'; end if;
  update public.mosque_settings set settings=new_settings,updated_at=now() where mosque_id=target.mosque_id;
  update public.mosques set name=coalesce(nullif(trim(new_settings->>'mosqueName'),''),name) where id=target.mosque_id;
  return true;
end $$;

revoke all on function public.pair_tv_device(text, text) from public;
grant execute on function public.pair_tv_device(text, text) to anon, authenticated;
revoke all on function public.create_tv_pairing_code(uuid) from public;
grant execute on function public.create_tv_pairing_code(uuid) to authenticated;
revoke all on function public.get_tv_settings(text) from public;
grant execute on function public.get_tv_settings(text) to anon, authenticated;
revoke all on function public.is_app_admin() from public;
grant execute on function public.is_app_admin() to authenticated;
revoke all on function public.admin_create_license(text,integer) from public;
grant execute on function public.admin_create_license(text,integer) to authenticated;
revoke all on function public.admin_list_licenses() from public;
grant execute on function public.admin_list_licenses() to authenticated;
revoke all on function public.admin_set_license_active(uuid,boolean) from public;
grant execute on function public.admin_set_license_active(uuid,boolean) to authenticated;
revoke all on function public.admin_reset_license_devices(uuid) from public;
grant execute on function public.admin_reset_license_devices(uuid) to authenticated;
revoke all on function public.activate_license(text,text) from public;
grant execute on function public.activate_license(text,text) to anon, authenticated;
revoke all on function public.save_tv_settings(text,jsonb) from public;
grant execute on function public.save_tv_settings(text,jsonb) to anon, authenticated;
revoke all on function public.create_tv_pairing_code(uuid) from anon, authenticated;
revoke all on function public.pair_tv_device(text,text) from anon, authenticated;

-- Storage bucket for mosque backgrounds. Object path starts with the mosque UUID.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('mosque-backgrounds', 'mosque-backgrounds', false, 10485760, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = false, file_size_limit = 10485760, allowed_mime_types = array['image/jpeg','image/png','image/webp'];
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

