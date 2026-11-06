// _shared/common.ts
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";
var ALLOWED_ORIGINS = (Deno.env.get("ALLOWED_ORIGINS") || "https://crestmatrixdigital.com,https://www.crestmatrixdigital.com").split(",").map((s) => s.trim());
var SITE = Deno.env.get("SITE_URL") || "https://crestmatrixdigital.com";
function cors(req) {
  const o = req.headers.get("origin") || "";
  const allow = ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0];
  return { "access-control-allow-origin": allow, "access-control-allow-headers": "authorization, apikey, content-type, x-client-info", "access-control-allow-methods": "GET, POST, OPTIONS", vary: "origin" };
}
var json = (req, body, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors(req), "content-type": "application/json" } });
var db = () => createClient(Deno.env.get("SUPABASE_URL"), Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"), { auth: { persistSession: false } });
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// _shared/audit.ts
var STAGES = [
  "Validating store URL",
  "Detecting Shopify platform",
  "Discovering store pages",
  "Analysing page performance signals",
  "Evaluating technical SEO",
  "Reviewing user experience",
  "Checking conversion opportunities",
  "Evaluating marketing readiness",
  "Connecting related findings",
  "Preparing final report"
];

// audit-status/index.ts
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(req) });
  const u = new URL(req.url);
  const id = u.searchParams.get("id") || "";
  const t = u.searchParams.get("t") || "";
  if (!/^[0-9a-f-]{36}$/i.test(id) || t.length < 20) return json(req, { error: "Not found" }, 404);
  const { data } = await db().from("audits").select("token, status, stage, message, score, report, domain, created_at, completed_at").eq("id", id).maybeSingle();
  if (!data || !safeEqual(data.token, t)) return json(req, { error: "Not found" }, 404);
  const done = data.status === "completed";
  return json(req, { status: data.status, stage: data.stage, stages: STAGES, message: data.message, domain: data.domain, score: data.score, createdAt: data.created_at, completedAt: data.completed_at, report: done ? data.report : null });
});
