import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.4';
import type { Resolver } from './ssrf.ts';

export const ALLOWED_ORIGINS = (Deno.env.get('ALLOWED_ORIGINS') || 'https://crestmatrixdigital.com,https://www.crestmatrixdigital.com').split(',').map((s) => s.trim());
export const SITE = Deno.env.get('SITE_URL') || 'https://crestmatrixdigital.com';

export function cors(req: Request): Record<string, string> {
  const o = req.headers.get('origin') || '';
  const allow = ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0];
  return { 'access-control-allow-origin': allow, 'access-control-allow-headers': 'authorization, apikey, content-type, x-client-info', 'access-control-allow-methods': 'GET, POST, OPTIONS', vary: 'origin' };
}
export const json = (req: Request, body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors(req), 'content-type': 'application/json' } });
export const db = () => createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } });

export const resolver: Resolver = async (host, type) => {
  // deno-lint-ignore no-explicit-any
  return await (Deno as any).resolveDns(host, type);
};

export async function sha256(s: string): Promise<string> {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
export function clientIp(req: Request): string {
  return (req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'unknown').split(',')[0].trim();
}
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
export const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

// Email via Resend. Optional: if RESEND_API_KEY is not set, this quietly does nothing.
export async function sendEmail(to: string, subject: string, html: string): Promise<boolean> {
  const key = Deno.env.get('RESEND_API_KEY');
  if (!key || !to) return false;
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: Deno.env.get('EMAIL_FROM') || 'Crest Matrix Digital Group <hello@crestmatrixdigital.com>', to: [to], subject, html }),
    });
    return r.ok;
  } catch { return false; }
}
export const ADMIN_EMAIL = () => Deno.env.get('ADMIN_EMAIL') || 'hello@crestmatrixdigital.com';
