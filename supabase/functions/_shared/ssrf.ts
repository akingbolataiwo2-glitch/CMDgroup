// URL validation and SSRF protection for the audit crawler.
// Every request the audit makes goes through safeFetch(), which re-validates the
// host (including DNS results) on every redirect hop.

export type Resolver = (host: string, type: 'A' | 'AAAA') => Promise<string[]>;

export function isPrivateIp(ip: string): boolean {
  const v = ip.trim().toLowerCase();
  if (v.includes(':')) {
    // IPv6
    if (v === '::1' || v === '::') return true;
    if (v.startsWith('fe80') || v.startsWith('fc') || v.startsWith('fd')) return true;
    if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
    return false;
  }
  const p = v.split('.').map((n) => Number(n));
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true; // malformed => block
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast/reserved
  return false;
}

const IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;

export interface ParsedTarget {
  ok: boolean;
  url?: URL;
  error?: string;
}

export function parseTarget(input: string): ParsedTarget {
  let raw = String(input || '').trim();
  if (!raw) return { ok: false, error: 'Please enter your store URL.' };
  if (raw.length > 300) return { ok: false, error: 'That URL is too long.' };
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, error: 'That does not look like a valid web address.' };
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return { ok: false, error: 'Only http and https addresses are supported.' };
  if (u.username || u.password) return { ok: false, error: 'Please enter the address without a username or password.' };
  const host = u.hostname.toLowerCase();
  if (!host.includes('.') || host.endsWith('.')) return { ok: false, error: 'Please enter a full domain, like yourstore.com.' };
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return { ok: false, error: 'That address cannot be audited.' };
  }
  if (IPV4_LITERAL.test(host) || host.startsWith('[')) return { ok: false, error: 'Please enter a store domain, not an IP address.' };
  if (!/^[a-z0-9.-]+$/.test(host) && !host.startsWith('xn--') && !/[^\x00-\x7f]/.test(host)) {
    return { ok: false, error: 'That domain contains characters we cannot audit.' };
  }
  if (u.port && u.port !== '80' && u.port !== '443') return { ok: false, error: 'Please use a standard web address without a custom port.' };
  // Normalise to the origin. The audit always starts at the homepage.
  const origin = new URL(`${u.protocol}//${host}/`);
  return { ok: true, url: origin };
}

export async function assertPublicHost(host: string, resolve: Resolver): Promise<void> {
  const addrs: string[] = [];
  for (const t of ['A', 'AAAA'] as const) {
    try {
      addrs.push(...(await resolve(host, t)));
    } catch {
      /* no record of this type */
    }
  }
  if (addrs.length === 0) throw new Error('DNS_NOT_FOUND');
  for (const ip of addrs) if (isPrivateIp(ip)) throw new Error('PRIVATE_ADDRESS');
}

export interface FetchResult {
  ok: boolean;
  status: number;
  url: string; // final URL
  headers: Record<string, string>;
  body: string;
  ms: number;
  redirects: string[];
  truncated: boolean;
  error?: string;
}

export interface FetchDeps {
  fetchImpl: typeof fetch;
  resolve: Resolver;
}

const MAX_BYTES = 1_500_000;
const MAX_REDIRECTS = 4;
const TIMEOUT_MS = 12_000;
const UA = 'CMDGroupAuditBot/1.0 (+https://crestmatrixdigital.com/shopify-store-audit)';

export async function safeFetch(rawUrl: string, deps: FetchDeps, init: { accept?: string } = {}): Promise<FetchResult> {
  const started = Date.now();
  const redirects: string[] = [];
  let current = rawUrl;
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const u = new URL(current);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('BAD_PROTOCOL');
      if (u.port && u.port !== '80' && u.port !== '443') throw new Error('BAD_PORT');
      await assertPublicHost(u.hostname, deps.resolve);
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
      let res: Response;
      try {
        res = await deps.fetchImpl(u.toString(), {
          redirect: 'manual',
          signal: ctrl.signal,
          headers: { 'user-agent': UA, accept: init.accept || 'text/html,application/json,application/xml,text/plain;q=0.9,*/*;q=0.5' },
        });
      } finally {
        clearTimeout(timer);
      }
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        const next = new URL(res.headers.get('location')!, u).toString();
        redirects.push(next);
        current = next;
        try { await res.body?.cancel(); } catch { /* ignore */ }
        continue;
      }
      // Read capped body
      let body = '';
      let truncated = false;
      if (res.body) {
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let total = 0;
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > MAX_BYTES) {
            truncated = true;
            body += dec.decode(value.slice(0, Math.max(0, value.byteLength - (total - MAX_BYTES))));
            try { await reader.cancel(); } catch { /* ignore */ }
            break;
          }
          body += dec.decode(value, { stream: true });
        }
      }
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
      return { ok: res.status >= 200 && res.status < 300, status: res.status, url: u.toString(), headers, body, ms: Date.now() - started, redirects, truncated };
    }
    throw new Error('TOO_MANY_REDIRECTS');
  } catch (e) {
    return { ok: false, status: 0, url: current, headers: {}, body: '', ms: Date.now() - started, redirects, truncated: false, error: (e as Error).message || 'FETCH_FAILED' };
  }
}
