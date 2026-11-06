-- Crest Matrix Digital Group: Shopify store audit platform (Phase 1 schema)
-- Run in the Supabase SQL editor, or with `supabase db push`.

create extension if not exists pgcrypto;

create table if not exists public.audits (
  id uuid primary key default gen_random_uuid(),
  token text not null default encode(gen_random_bytes(24), 'hex'),   -- secret that lets the owner open their report
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- lead details
  name text not null,
  email text not null,
  store_url text not null,
  domain text not null,
  goal text not null,
  consent boolean not null default false,
  ip_hash text,                                  -- salted hash, never the raw IP

  -- audit state
  status text not null default 'queued'
    check (status in ('queued','running','completed','failed','not_shopify','unreachable','password')),
  stage int not null default 0,                  -- index into the 10 audit stages (real progress)
  message text,                                  -- human-readable outcome for non-completed audits
  error text,
  score int,
  critical_count int,
  high_count int,
  report jsonb,                                  -- full evidence-based report
  completed_at timestamptz,

  -- lead management (used by the admin dashboard in Phase 2)
  lead_status text not null default 'New Lead'
    check (lead_status in ('New Lead','Audit In Progress','Audit Completed','Contacted','Consultation Scheduled','Proposal Sent','Project Won','Project Lost')),
  help_requested boolean not null default false,
  help_message text,
  shopify_connected boolean not null default false,
  internal_notes text
);

create index if not exists audits_created_idx on public.audits (created_at desc);
create index if not exists audits_domain_email_idx on public.audits (domain, email, created_at desc);
create index if not exists audits_ip_idx on public.audits (ip_hash, created_at desc);

create or replace function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;
drop trigger if exists audits_touch on public.audits;
create trigger audits_touch before update on public.audits for each row execute function public.touch_updated_at();

-- Lock the table down. Only the Edge Functions (service role) can read or write it.
-- Browsers use the anon key and have no policies, so they can never read leads or reports directly.
alter table public.audits enable row level security;

-- Data retention: remove audits (and the personal data in them) after 12 months.
-- Schedule with pg_cron if available:
--   select cron.schedule('audit-retention', '0 3 * * *', $$delete from public.audits where created_at < now() - interval '12 months'$$);
