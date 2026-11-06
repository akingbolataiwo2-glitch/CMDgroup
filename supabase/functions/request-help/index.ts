// POST /functions/v1/request-help { id, token, kind, message } -> flags the lead and notifies the admin.
import { cors, json, db, safeEqual, sendEmail, ADMIN_EMAIL, SITE, esc } from '../_shared/common.ts';

const KINDS = ['assistance', 'consultation', 'contact'];
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors(req) });
  if (req.method !== 'POST') return json(req, { error: 'Method not allowed' }, 405);
  let b: Record<string, unknown>; try { b = await req.json(); } catch { return json(req, { error: 'Invalid request.' }, 400); }
  const id = String(b.id || ''), t = String(b.token || ''), kind = String(b.kind || 'assistance');
  const message = String(b.message || '').slice(0, 1000);
  if (!/^[0-9a-f-]{36}$/i.test(id) || !KINDS.includes(kind)) return json(req, { error: 'Invalid request.' }, 400);
  const supabase = db();
  const { data } = await supabase.from('audits').select('token, name, email, domain, score').eq('id', id).maybeSingle();
  if (!data || !safeEqual(data.token, t)) return json(req, { error: 'Not found' }, 404);
  await supabase.from('audits').update({ help_requested: true, help_message: message || null, lead_status: 'Contacted' }).eq('id', id);
  await sendEmail(ADMIN_EMAIL(), `Audit lead wants help (${kind}): ${data.domain}`, `<p>${esc(data.name)} &lt;${esc(data.email)}&gt; asked for <b>${esc(kind)}</b> after their audit of ${esc(data.domain)} (score ${data.score}).</p><p>${esc(message)}</p><p><a href="${SITE}/audit-report?id=${id}&t=${t}">Open their report</a></p>`);
  return json(req, { ok: true });
});
