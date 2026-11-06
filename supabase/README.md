# Shopify Store Audit: backend setup

The site is static (GitHub Pages). The audit engine runs on Supabase Edge Functions.

## One-time setup
1. Create a Supabase project. Note the Project Ref, the anon key and the service-role key.
2. Run `supabase/migrations/001_audit.sql` in the SQL editor.
3. Install the Supabase CLI, then: `supabase link --project-ref <ref>` and
   `supabase functions deploy start-audit audit-status request-help --no-verify-jwt`
4. Set secrets: `supabase secrets set ADMIN_EMAIL=hello@crestmatrixdigital.com EMAIL_FROM="Crest Matrix <audit@yourdomain>" SITE_URL=https://crestmatrixdigital.com IP_SALT=<long random string> RESEND_API_KEY=<key> PAGESPEED_API_KEY=<key>`
   - RESEND_API_KEY optional (no emails without it). PAGESPEED_API_KEY optional (without it Performance is shown as unscored and weights are re-normalised, which the report discloses).
5. Edit `assets/audit/config.js`: set `api` to `https://<ref>.supabase.co/functions/v1` and `anonKey` to the anon key (the anon key is public by design; RLS blocks direct table reads).
6. Commit and push. The form shows a "not connected" notice until step 5 is done.

## Tests
`node tests/audit.test.mjs` (Node 22+). Covers SSRF rules, redirects, scoring and non-Shopify/password/unreachable cases using fixtures.

## Not built yet (later phases)
Server-side branded PDF (the report currently uses browser Save as PDF), AI interpretation, admin dashboard (leads are in the `audits` table; view them in Supabase), Shopify OAuth, third-party traffic data. Traffic and sales are always shown as "unavailable" rather than estimated.
Retention: delete old audits periodically, e.g. `delete from audits where created_at < now() - interval '90 days';`
