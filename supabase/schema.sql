-- Snagify licenses table
-- Run this in the Supabase SQL editor (Dashboard → SQL Editor → New query)

create table if not exists public.licenses (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  email text not null,
  status text not null default 'active',          -- active | cancelled | refunded
  plan text not null default 'pro',               -- pro | team
  lemonsqueezy_order_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists licenses_user_id_idx on public.licenses (user_id);
create index if not exists licenses_email_idx on public.licenses (email);

-- Idempotency: one license row per LemonSqueezy order, no matter how often
-- the webhook is retried. (NULLs don't conflict, so manual rows stay allowed.)
create unique index if not exists licenses_ls_order_idx on public.licenses (lemonsqueezy_order_id);

-- O(1) user lookup by email for the webhook — replaces paging through
-- auth.admin.listUsers(), which silently truncates beyond the first page.
-- security definer lets it read auth.users; execute is revoked from clients.
create or replace function public.get_user_id_by_email(p_email text)
returns uuid
language sql
security definer
set search_path = ''
as $$
  select id from auth.users where lower(email) = lower(p_email) limit 1;
$$;

revoke execute on function public.get_user_id_by_email(text) from anon, authenticated, public;

-- Row-level security: users can read only their own license rows.
-- Writes happen only via the service-role key (webhook function) — no user policy needed.
alter table public.licenses enable row level security;

create policy "Users can view own licenses"
  on public.licenses for select
  using (auth.uid() = user_id);
