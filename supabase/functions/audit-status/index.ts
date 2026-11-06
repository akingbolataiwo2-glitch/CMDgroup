// GET /functions/v1/audit-status?id=<uuid>&t=<token>  -> real progress + report when complete.
import { cors, json, db, safeEqual } from '../_shared/common.ts';
import { STAGES } from '../_shared/audit.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors(req) });
  const u = new URL(req.url);
  const id = u.searchParams.get('id') || '';
  const t = u.searchParams.get('t') || '';
  if (!/^[0-9a-f-]{36}$/i.test(id) || t.length < 20) return json(req, { error: 'Not found' }, 404);
  const { data } = await db().from('audits').select('token, status, stage, message, score, report, domain, created_at, completed_at').eq('id', id).maybeSingle();
  if (!data || !safeEqual(data.token, t)) return json(req, { error: 'Not found' }, 404);
  const done = data.status === 'completed';
  return json(req, { status: data.status, stage: data.stage, stages: STAGES, message: data.message, domain: data.domain, score: data.score, createdAt: data.created_at, completedAt: data.completed_at, report: done ? data.report : null });
});
