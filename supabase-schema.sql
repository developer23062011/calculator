-- ============================================================================
--  Pocket Calculator — Supabase schema
--  Run this ONCE in: Supabase Dashboard → SQL Editor → New query → Run.
--  Safe to re-run (idempotent).
--
--  What the server can ever see:  emails, roles, ciphertext blobs, encrypted
--  metadata, the (non-secret) PBKDF2 salt and an encrypted passphrase verifier.
--  What it never sees:           photos, file names, categories, the passphrase.
-- ============================================================================

-- ---------------------------------------------------------------- profiles --
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  role       text not null default 'pending'
             check (role in ('admin','user','pending','disabled')),
  created_at timestamptz not null default now()
);

-- First account ever created becomes the Admin. Everyone after that is
-- 'pending' (no access) until the Admin approves / creates them.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, role)
  values (
    new.id,
    new.email,
    case when exists (select 1 from public.profiles where role = 'admin')
         then 'pending' else 'admin' end
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ----------------------------------------------------------- helper funcs ---
create or replace function public.app_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid()
$$;

-- Lets the (logged-out) login screen know whether to show "setup" or "login".
create or replace function public.vault_initialized()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.profiles where role = 'admin')
$$;

-- Admin-only: permanently delete another user's login.
create or replace function public.admin_delete_user(target uuid)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if public.app_role() is distinct from 'admin' then
    raise exception 'Only the admin can delete users';
  end if;
  if target = auth.uid() then
    raise exception 'You cannot delete your own account';
  end if;
  delete from auth.users where id = target;
end;
$$;

revoke all on function public.app_role()          from public;
revoke all on function public.vault_initialized() from public;
revoke all on function public.admin_delete_user(uuid) from public;
grant execute on function public.app_role()               to authenticated;
grant execute on function public.vault_initialized()      to anon, authenticated;
grant execute on function public.admin_delete_user(uuid)  to authenticated;

-- ------------------------------------------------------------- vault meta ---
-- One row. Holds only non-secret KDF parameters + an encrypted "verifier"
-- used to check that a typed passphrase is correct.
create table if not exists public.vault_meta (
  id         int primary key check (id = 1),
  salt       text   not null,
  iterations int    not null,
  verifier   text   not null,
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------ vault items ---
create table if not exists public.vault_items (
  id         uuid primary key,
  owner      uuid references auth.users(id) on delete set null default auth.uid(),
  file_path  text not null,
  thumb_path text,
  meta_enc   text not null,            -- AES-GCM(JSON{name,category,...})
  size_bytes bigint not null default 0,
  created_at timestamptz not null default now()
);
create index if not exists vault_items_created_idx on public.vault_items (created_at desc);

-- -------------------------------------------------------------------- RLS ---
alter table public.profiles    enable row level security;
alter table public.vault_meta  enable row level security;
alter table public.vault_items enable row level security;

-- profiles
drop policy if exists "profiles: read own or admin"  on public.profiles;
drop policy if exists "profiles: admin updates"      on public.profiles;
create policy "profiles: read own or admin" on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.app_role() = 'admin');
create policy "profiles: admin updates" on public.profiles
  for update to authenticated
  using (public.app_role() = 'admin' and id <> auth.uid())
  with check (role in ('admin','user','pending','disabled'));

-- vault_meta
drop policy if exists "meta: members read"  on public.vault_meta;
drop policy if exists "meta: admin insert"  on public.vault_meta;
drop policy if exists "meta: admin delete"  on public.vault_meta;
create policy "meta: members read" on public.vault_meta
  for select to authenticated using (public.app_role() in ('admin','user'));
create policy "meta: admin insert" on public.vault_meta
  for insert to authenticated with check (public.app_role() = 'admin');
create policy "meta: admin delete" on public.vault_meta
  for delete to authenticated using (public.app_role() = 'admin');

-- vault_items
drop policy if exists "items: members read"   on public.vault_items;
drop policy if exists "items: members insert" on public.vault_items;
drop policy if exists "items: members update" on public.vault_items;
drop policy if exists "items: owner/admin delete" on public.vault_items;
create policy "items: members read" on public.vault_items
  for select to authenticated using (public.app_role() in ('admin','user'));
create policy "items: members insert" on public.vault_items
  for insert to authenticated
  with check (public.app_role() in ('admin','user') and owner = auth.uid());
create policy "items: members update" on public.vault_items
  for update to authenticated
  using (public.app_role() in ('admin','user'))
  with check (public.app_role() in ('admin','user'));
create policy "items: owner/admin delete" on public.vault_items
  for delete to authenticated
  using (public.app_role() = 'admin'
         or (public.app_role() = 'user' and owner = auth.uid()));

-- ---------------------------------------------------- private storage bucket -
insert into storage.buckets (id, name, public, file_size_limit)
values ('vault', 'vault', false, 52428800)   -- 50 MB per object (ciphertext)
on conflict (id) do update set public = false, file_size_limit = 52428800;

-- Objects live at  <uploader-uid>/<item-uuid>.bin  (and .t.bin for thumbnails)
drop policy if exists "vault: members read"   on storage.objects;
drop policy if exists "vault: members insert" on storage.objects;
drop policy if exists "vault: members update" on storage.objects;
drop policy if exists "vault: owner/admin delete" on storage.objects;

create policy "vault: members read" on storage.objects
  for select to authenticated
  using (bucket_id = 'vault' and public.app_role() in ('admin','user'));

create policy "vault: members insert" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'vault'
              and public.app_role() in ('admin','user')
              and (storage.foldername(name))[1] = auth.uid()::text);

create policy "vault: members update" on storage.objects
  for update to authenticated
  using (bucket_id = 'vault'
         and public.app_role() in ('admin','user')
         and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'vault'
              and (storage.foldername(name))[1] = auth.uid()::text);

create policy "vault: owner/admin delete" on storage.objects
  for delete to authenticated
  using (bucket_id = 'vault'
         and (public.app_role() = 'admin'
              or (public.app_role() = 'user'
                  and (storage.foldername(name))[1] = auth.uid()::text)));
