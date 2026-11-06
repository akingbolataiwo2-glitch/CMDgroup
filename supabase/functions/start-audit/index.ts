// POST /functions/v1/start-audit  { storeUrl, name, email, goal, consent, website(honeypot) }
// Validates, rate-limits, stores the lead, then runs the real audit in the background.
import { cors, json, db, resolver, sha256, clientIp, sendEmail, ADMIN_EMAIL, SITE, esc } from '../_shared/common.ts';
import { parseTarget } from '../_shared/ssrf.ts';
import { runAudit } from '../_shared/audit.ts';

const GOALS = ['Increase sales', 'Improve conversion rate', 'Improve SEO and Google visibility', 'Improve website speed', 'Improve store design and user experience', 'Improve marketing performance', 'Launch a new Shopify store', 'Identify general growth opportunities'];
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;
const PER_IP_PER_HOUR = 3;
const GLOBAL_PER_HOUR = 150;

// deno-lint-ignore no-explicit-any
declare const EdgeRuntime: any;

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors(req) });
  if (req.method !== 'POST') return json(req, { error: 'Method not allowed' }, 405);
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json(req, { error: 'Invalid request.' }, 400); }

  if (body.website) return json(req, { id: crypto.randomUUID(), token: 'x' }); // honeypot: pretend success to bots
  const name = String(body.name || '').trim().replace(/\s+/g, ' ');
  const email = String(body.email || '').trim().toLowerCase();
  const goal = String(body.goal || '');
  if (name.length < 2 || name.length > 80) return json(req, { error: 'Please enter your full name.' }, 400);
  if (!EMAIL_RE.test(email) || email.length > 120) return json(req, { error: 'Please enter a valid business email.' }, 400);
  if (!GOALS.includes(goal)) return json(req, { error: 'Please choose a primary business goal.' }, 400);
  if (body.consent !== true) return json(req, { error: 'Please tick the consent box so we can run your audit.' }, 400);
  const target = parseTarget(String(body.storeUrl || ''));
  if (!target.ok) return json(req, { error: target.error }, 400);
  const url = target.url!;

  const supabase = db();
  const ipHash = await sha256((Deno.env.get('IP_SALT') || 'cmd-audit') + clientIp(req));
  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count: ipCount } = await supabase.from('audits').select('id', { count: 'exact', head: true }).eq('ip_hash', ipHash).gte('created_at', since);
  if ((ipCount ?? 0) >= PER_IP_PER_HOUR) return json(req, { error: 'You have run several audits in the last hour. Please try again a little later.' }, 429);
  const { count: allCount } = await supabase.from('audits').select('id', { count: 'exact', head: true }).gte('created_at', since);
  if ((allCount ?? 0) >= GLOBAL_PER_HOUR) return json(req, { error: 'We are running a lot of audits right now. Please try again in a few minutes.' }, 429);

  // Duplicate: same store + email in the last 24h returns the existing audit.
  const day = new Date(Date.now() - 86400_000).toISOString();
  const { data: dup } = await supabase.from('audits').select('id, token, status').eq('domain', url.hostname).eq('email', email).gte('created_at', day).order('created_at', { ascending: false }).limit(1);
  if (dup && dup.length && ['queued', 'running', 'completed'].includes(dup[0].status)) return json(req, { id: dup[0].id, token: dup[0].token, reused: true });

  const { data: row, error } = await supabase.from('audits').insert({ name, email, store_url: url.toString(), domain: url.hostname, goal, consent: true, ip_hash: ipHash, status: 'queued', lead_status: 'Audit In Progress' }).select('id, token').single();
  if (error || !row) return json(req, { error: 'We could not start your audit. Please try again.' }, 500);

  const job = (async () => {
    try {
      await supabase.from('audits').update({ status: 'running', stage: 0 }).eq('id', row.id);
      const out = await runAudit(url.toString(), { fetchImpl: fetch, resolve: resolver }, async (stage) => { await supabase.from('audits').update({ stage }).eq('id', row.id); }, { pageSpeedKey: Deno.env.get('PAGESPEED_API_KEY') || undefined });
      if (out.status === 'completed' && out.report) {
        await supabase.from('audits').update({ status: 'completed', stage: 10, report: out.report, score: out.report.overall.score, critical_count: out.report.counts.critical, high_count: out.report.counts.high, completed_at: new Date().toISOString(), lead_status: 'Audit Completed' }).eq('id', row.id);
        const link = `${SITE}/audit-report?id=${row.id}&t=${row.token}`;
        await sendEmail(email, `Your Shopify store audit is ready (${out.report.overall.score}/100)`, `<p>Hi ${esc(name.split(' ')[0])},</p><p>Your audit of <b>${esc(url.hostname)}</b> is ready. Overall store health score: <b>${out.report.overall.score}/100</b>, with ${out.report.counts.critical} critical and ${out.report.counts.high} high-priority issues.</p><p><a href="${link}">View your full report</a></p><p>Want help fixing what we found? Reply to this email or book a free consultation at ${SITE}/Consultation.html.</p><p>Crest Matrix Digital Group</p>`);
        await sendEmail(ADMIN_EMAIL(), `Audit completed: ${url.hostname} (${out.report.overall.score}/100)`, `<p>${esc(name)} &lt;${esc(email)}&gt; | goal: ${esc(goal)}</p><p>Score ${out.report.overall.score}, ${out.report.counts.critical} critical, ${out.report.counts.high} high.</p><p><a href="${link}">Open report</a></p>`);
      } else {
        await supabase.from('audits').update({ status: out.status, message: out.message, stage: 10, lead_status: 'New Lead' }).eq('id', row.id);
        await sendEmail(ADMIN_EMAIL(), `New audit request (${out.status}): ${url.hostname}`, `<p>${esc(name)} &lt;${esc(email)}&gt; | goal: ${esc(goal)}</p><p>${esc(out.message || out.status)}</p>`);
      }
    } catch (e) {
      await supabase.from('audits').update({ status: 'failed', error: String((e as Error).message || e).slice(0, 500), message: 'Something went wrong while auditing your store. Please try again later.' }).eq('id', row.id);
    }
  })();
  // Keep the audit running after the HTTP response returns.
  if (typeof EdgeRuntime !== 'undefined' && EdgeRuntime.waitUntil) EdgeRuntime.waitUntil(job); else job.catch(() => {});
  await sendEmail(ADMIN_EMAIL(), `New audit submitted: ${url.hostname}`, `<p>${esc(name)} &lt;${esc(email)}&gt;<br>Goal: ${esc(goal)}<br>Store: ${esc(url.toString())}</p>`);
  return json(req, { id: row.id, token: row.token });
});
