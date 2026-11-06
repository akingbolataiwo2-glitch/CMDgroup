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
var esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
async function sendEmail(to, subject, html) {
  const key = Deno.env.get("RESEND_API_KEY");
  if (!key || !to) return false;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify({ from: Deno.env.get("EMAIL_FROM") || "Crest Matrix Digital Group <hello@crestmatrixdigital.com>", to: [to], subject, html })
    });
    return r.ok;
  } catch {
    return false;
  }
}
var ADMIN_EMAIL = () => Deno.env.get("ADMIN_EMAIL") || "hello@crestmatrixdigital.com";

// request-help/index.ts
var KINDS = ["assistance", "consultation", "contact"];
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(req) });
  if (req.method !== "POST") return json(req, { error: "Method not allowed" }, 405);
  let b;
  try {
    b = await req.json();
  } catch {
    return json(req, { error: "Invalid request." }, 400);
  }
  const id = String(b.id || ""), t = String(b.token || ""), kind = String(b.kind || "assistance");
  const message = String(b.message || "").slice(0, 1e3);
  if (!/^[0-9a-f-]{36}$/i.test(id) || !KINDS.includes(kind)) return json(req, { error: "Invalid request." }, 400);
  const supabase = db();
  const { data } = await supabase.from("audits").select("token, name, email, domain, score").eq("id", id).maybeSingle();
  if (!data || !safeEqual(data.token, t)) return json(req, { error: "Not found" }, 404);
  await supabase.from("audits").update({ help_requested: true, help_message: message || null, lead_status: "Contacted" }).eq("id", id);
  await sendEmail(ADMIN_EMAIL(), `Audit lead wants help (${kind}): ${data.domain}`, `<p>${esc(data.name)} &lt;${esc(data.email)}&gt; asked for <b>${esc(kind)}</b> after their audit of ${esc(data.domain)} (score ${data.score}).</p><p>${esc(message)}</p><p><a href="${SITE}/audit-report?id=${id}&t=${t}">Open their report</a></p>`);
  return json(req, { ok: true });
});
