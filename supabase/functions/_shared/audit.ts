// Crest Matrix Digital Group — Shopify store audit engine (Phase 1).
// Gathers real, public evidence first; every finding cites what was observed.
// Nothing here invents traffic, sales, rankings or conversion data.

import { safeFetch, type FetchDeps, type FetchResult } from './ssrf.ts';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'opportunity';
export type CategoryKey = 'seo' | 'ux' | 'cro' | 'performance' | 'technical' | 'marketing';
export type Confidence = 'verified' | 'likely' | 'indicative';

export interface Finding {
  id: string;
  category: CategoryKey;
  area: string; // display group, e.g. "Trust & security"
  title: string;
  severity: Severity;
  url: string;
  evidence: string[];
  what: string;
  why: string;
  impact: string;
  fix: string;
  confidence: Confidence;
}

export interface Pass {
  id: string;
  category: CategoryKey;
  title: string;
  detail: string;
}

export const STAGES = [
  'Validating store URL',
  'Detecting Shopify platform',
  'Discovering store pages',
  'Analysing page performance signals',
  'Evaluating technical SEO',
  'Reviewing user experience',
  'Checking conversion opportunities',
  'Evaluating marketing readiness',
  'Connecting related findings',
  'Preparing final report',
];

export const WEIGHTS: Record<CategoryKey, number> = { seo: 20, ux: 20, cro: 20, performance: 15, technical: 15, marketing: 10 };
export const CATEGORY_LABEL: Record<CategoryKey, string> = {
  seo: 'SEO', ux: 'User experience', cro: 'Conversion optimisation', performance: 'Website performance', technical: 'Technical health', marketing: 'Marketing readiness',
};
const PENALTY: Record<Severity, number> = { critical: 28, high: 14, medium: 6, low: 2, opportunity: 0 };

export type Progress = (stage: number, note?: string) => Promise<void> | void;

export interface AuditOptions {
  pageSpeedKey?: string;
  now?: () => Date;
}

// ---------- HTML helpers (regex based; no DOM available in edge runtimes) ----------
const strip = (s: string) => s.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
const decode = (s: string) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');
export function getTitle(html: string): string { const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i); return m ? decode(m[1].replace(/\s+/g, ' ').trim()) : ''; }
export function getMeta(html: string, name: string): string {
  const re = new RegExp(`<meta[^>]+(?:name|property)=["']${name}["'][^>]*>`, 'i');
  const tag = html.match(re)?.[0] || '';
  const c = tag.match(/content=["']([\s\S]*?)["']/i);
  return c ? decode(c[1].trim()) : '';
}
export function getCanonical(html: string): string { const m = html.match(/<link[^>]+rel=["']canonical["'][^>]*>/i)?.[0] || ''; return m.match(/href=["']([^"']+)["']/i)?.[1] || ''; }
export function getH1s(html: string): string[] { return [...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi)].map((m) => strip(m[1])).filter(Boolean); }
export function getImages(html: string): { src: string; alt: string | null; loading: string | null; hasDims: boolean }[] {
  return [...html.matchAll(/<img\b[^>]*>/gi)].map((m) => {
    const t = m[0];
    const alt = t.match(/\balt=(["'])([\s\S]*?)\1/i);
    return { src: t.match(/\bsrc=["']([^"']*)["']/i)?.[1] || '', alt: alt ? alt[2] : null, loading: t.match(/\bloading=["']([^"']*)["']/i)?.[1] || null, hasDims: /\bwidth=/i.test(t) && /\bheight=/i.test(t) };
  });
}
export function getScripts(html: string): { src: string; async: boolean; defer: boolean; inHead: boolean; module: boolean }[] {
  const headEnd = html.search(/<\/head>/i);
  return [...html.matchAll(/<script\b([^>]*)>/gi)].map((m) => ({
    src: m[1].match(/\bsrc=["']([^"']+)["']/i)?.[1] || '',
    async: /\basync\b/i.test(m[1]), defer: /\bdefer\b/i.test(m[1]), module: /type=["']module["']/i.test(m[1]),
    inHead: headEnd < 0 ? false : (m.index ?? 0) < headEnd,
  })).filter((s) => s.src);
}
export function getJsonLdTypes(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      const walk = (n: unknown) => {
        if (Array.isArray(n)) n.forEach(walk);
        else if (n && typeof n === 'object') {
          const o = n as Record<string, unknown>;
          const t = o['@type'];
          if (typeof t === 'string') out.push(t); else if (Array.isArray(t)) out.push(...(t as string[]));
          if (o['@graph']) walk(o['@graph']);
        }
      };
      walk(JSON.parse(m[1]));
    } catch { /* ignore malformed block */ }
  }
  return out;
}
const hostOf = (u: string, base: string) => { try { return new URL(u, base).hostname; } catch { return ''; } };
const wordsToPct = (n: number, d: number) => (d ? Math.round((n / d) * 100) : 0);

interface Fetched { label: string; path: string; res: FetchResult }

export interface Report {
  version: 1;
  store: { name: string; domain: string; url: string; niche: string; platform: 'shopify' };
  auditedAt: string;
  overall: { score: number; scoredCategories: CategoryKey[]; note: string };
  categories: { key: CategoryKey; label: string; weight: number; scored: boolean; score: number | null; findings: number; note: string }[];
  counts: { total: number; critical: number; high: number; medium: number; low: number; opportunity: number };
  findings: Finding[];
  passes: Pass[];
  connections: { title: string; text: string; findingIds: string[] }[];
  roadmap: { phase: string; items: { title: string; why: string; priority: Severity; findingId: string }[] }[];
  opportunities: { title: string; text: string }[];
  summary: string;
  performance: { lab: Record<string, unknown> | null; field: Record<string, unknown> | null; note: string };
  trafficIntelligence: { status: 'unavailable'; note: string };
  coverage: {
    pagesRequested: number; pagesAnalysed: number; pagesFailed: { path: string; reason: string }[];
    pages: { path: string; status: number; ms: number }[];
    catalogSampled: { products: number; collections: number; note: string };
    tools: string[]; verified: string[]; estimated: string[]; unavailable: string[]; limitations: string[];
  };
}

export async function runAudit(origin: string, deps: FetchDeps, progress: Progress, opts: AuditOptions = {}): Promise<{ status: 'completed' | 'not_shopify' | 'unreachable' | 'password'; report?: Report; message?: string }> {
  const now = (opts.now || (() => new Date()))();
  const base = origin.replace(/\/$/, '');
  const host = new URL(origin).hostname;
  const get = (path: string) => safeFetch(path.startsWith('http') ? path : base + path, deps);

  // ---- Stage 0/1: reach homepage + detect Shopify
  await progress(0);
  const home = await get('/');
  if (!home.ok && home.status === 0) return { status: 'unreachable', message: `We could not reach ${host} (${home.error || 'no response'}).` };
  if (home.status >= 400) return { status: 'unreachable', message: `${host} answered with HTTP ${home.status}, so the store could not be audited.` };
  await progress(1);
  const html = home.body;
  const hdr = home.headers;
  const signals: string[] = [];
  if (/cdn\.shopify\.com|\/cdn\/shop\//i.test(html)) signals.push('Shopify CDN assets (cdn.shopify.com or /cdn/shop/) loaded on the homepage');
  if (/Shopify\.theme|Shopify\.shop\s*=|shopify-features/i.test(html)) signals.push('Shopify JavaScript globals present in the page source');
  if (hdr['x-shopid'] || hdr['x-shardid'] || /shopify/i.test(hdr['powered-by'] || '')) signals.push('Shopify response headers (x-shopid / x-shardid)');
  const productsRes = await get('/products.json?limit=250');
  let productsJson: { products?: Record<string, unknown>[] } | null = null;
  try { productsJson = productsRes.ok ? JSON.parse(productsRes.body) : null; } catch { productsJson = null; }
  if (productsJson && Array.isArray(productsJson.products)) signals.push('Public Shopify catalogue endpoint /products.json responded');
  if (signals.length === 0) {
    return { status: 'not_shopify', message: `${host} does not appear to be powered by Shopify (no Shopify signals found in the page source, headers or catalogue endpoint).` };
  }
  if (/\/password\/?$/.test(new URL(home.url).pathname) || /<form[^>]+action=["'][^"']*\/password/i.test(html)) {
    return { status: 'password', message: `${host} is currently password-protected, so shoppers (and our audit) cannot see the store.` };
  }

  // ---- Stage 2: discover pages
  await progress(2);
  const products = ((productsJson?.products || []) as Record<string, any>[]);
  const firstHandle = products[0]?.handle as string | undefined;
  const collRes = await get('/collections.json?limit=100');
  let collections: Record<string, any>[] = [];
  try { collections = collRes.ok ? (JSON.parse(collRes.body).collections || []) : []; } catch { collections = []; }
  const firstCollection = collections.find((c) => c.products_count > 0)?.handle || collections[0]?.handle;
  const wanted: [string, string][] = [
    ['robots.txt', '/robots.txt'], ['sitemap.xml', '/sitemap.xml'],
    ['Refund policy', '/policies/refund-policy'], ['Shipping policy', '/policies/shipping-policy'], ['Privacy policy', '/policies/privacy-policy'], ['Terms of service', '/policies/terms-of-service'],
    ['Contact page', '/pages/contact'], ['About page', '/pages/about-us'], ['About page (alt)', '/pages/about'],
  ];
  if (firstHandle) wanted.push(['Sample product page', `/products/${firstHandle}`]);
  if (firstCollection) wanted.push(['Sample collection page', `/collections/${firstCollection}`]);
  const fetched: Fetched[] = [];
  const results = await Promise.all(wanted.map(async ([label, path]) => ({ label, path, res: await get(path) })));
  fetched.push(...results);
  const httpHome = await safeFetch(`http://${host}/`, deps);
  const by = (label: string) => fetched.find((f) => f.label === label)?.res;
  const productPage = by('Sample product page');
  const collectionPage = by('Sample collection page');
  const robots = by('robots.txt');
  const sitemap = by('sitemap.xml');

  const findings: Finding[] = [];
  const passes: Pass[] = [];
  const add = (f: Omit<Finding, 'area'> & { area?: string }) => findings.push({ area: f.area || CATEGORY_LABEL[f.category], ...f });
  const pass = (p: Pass) => passes.push(p);
  const storeName = decode(getMeta(html, 'og:site_name') || getTitle(html).split(/[|–—-]/).pop()?.trim() || host).slice(0, 80);
  const homeUrl = home.url;

  // ---- Stage 3: performance signals (page-level, observed from the HTML)
  await progress(3);
  const scripts = getScripts(html);
  const external = scripts.filter((s) => { const h = hostOf(s.src, homeUrl); return h && h !== host; });
  const thirdParty = [...new Set(external.map((s) => hostOf(s.src, homeUrl)).filter((h) => !/shopify|shopifycdn|shopifysvc/i.test(h)))];
  const renderBlocking = scripts.filter((s) => s.inHead && !s.async && !s.defer && !s.module);
  const imgs = getImages(html);
  const bytes = new TextEncoder().encode(html).length;
  if (bytes > 400_000) add({ id: 'perf.page_weight', category: 'performance', title: 'Homepage HTML is very large', severity: 'medium', url: homeUrl, evidence: [`Homepage HTML is ${(bytes / 1024).toFixed(0)} KB${home.truncated ? ' (truncated at our read limit)' : ''}.`], what: 'The homepage document itself is unusually heavy before images and scripts are counted.', why: 'Large documents take longer to download and parse, especially on mobile networks.', impact: 'Slower first render can increase early drop-off on mobile.', fix: 'Trim inline scripts and unused theme sections, and reduce the number of sections rendered on the homepage.', confidence: 'verified' });
  else pass({ id: 'perf.page_weight', category: 'performance', title: 'Homepage HTML size is reasonable', detail: `${(bytes / 1024).toFixed(0)} KB.` });
  if (external.length > 25) add({ id: 'perf.scripts', category: 'performance', title: 'Many external scripts load on the homepage', severity: 'medium', url: homeUrl, evidence: [`${external.length} external script tags found.`, `Third-party hosts include: ${thirdParty.slice(0, 8).join(', ') || 'none outside Shopify'}.`], what: 'A high number of external scripts compete for the browser during page load.', why: 'Every extra script adds download, parse and execution time, and many come from installed apps.', impact: 'Heavy script loads are a common cause of slow mobile interaction. Exact impact needs a Lighthouse run.', fix: 'Audit installed apps, remove those that are unused, and defer non-essential scripts.', confidence: 'likely' });
  if (renderBlocking.length > 5) add({ id: 'perf.render_blocking', category: 'performance', title: 'Render-blocking scripts in the page head', severity: 'medium', url: homeUrl, evidence: [`${renderBlocking.length} scripts in <head> have neither async nor defer.`, ...renderBlocking.slice(0, 3).map((s) => s.src.slice(0, 120))], what: 'Scripts in the head without async/defer pause page rendering while they load.', why: 'The browser cannot show content until these scripts finish.', impact: 'Delays the first visible content for shoppers.', fix: 'Add defer/async where safe or move scripts to the end of the body.', confidence: 'verified' });
  const lazyCandidates = imgs.slice(3);
  const notLazy = lazyCandidates.filter((i) => i.loading !== 'lazy');
  if (lazyCandidates.length >= 8 && wordsToPct(notLazy.length, lazyCandidates.length) > 50) add({ id: 'perf.lazy', category: 'performance', title: 'Below-the-fold images are not lazy-loaded', severity: 'low', url: homeUrl, evidence: [`${notLazy.length} of ${lazyCandidates.length} images after the first three have no loading="lazy".`], what: 'Images far down the page load immediately instead of when needed.', why: 'They compete with important content for bandwidth.', impact: 'Slower initial load on mobile data.', fix: 'Set loading="lazy" on images below the first screen.', confidence: 'verified' });
  const noDims = imgs.filter((i) => !i.hasDims);
  if (imgs.length >= 5 && wordsToPct(noDims.length, imgs.length) > 40) add({ id: 'perf.img_dims', category: 'performance', title: 'Images missing width and height attributes', severity: 'low', url: homeUrl, evidence: [`${noDims.length} of ${imgs.length} homepage images have no width/height.`], what: 'Without dimensions the browser cannot reserve space for images.', why: 'Content jumps as images load (layout shift).', impact: 'Layout shift is a Core Web Vitals factor and frustrates shoppers.', fix: 'Add width and height (or aspect-ratio) to images in the theme.', confidence: 'verified' });
  if (home.ms > 2500) add({ id: 'perf.ttfb', category: 'performance', title: 'Slow homepage response in our test', severity: 'low', url: homeUrl, evidence: [`Homepage fetched in ${home.ms} ms from our audit server (single sample, includes redirects).`], what: 'The first request was slow in this single measurement.', why: 'Server and redirect time add to every page load.', impact: 'Indicative only: one sample from one location.', fix: 'Re-test with Lighthouse; check redirects and the CDN setup.', confidence: 'indicative' });

  // ---- PageSpeed (optional, real lab + field data when a key is configured)
  let perf: Report['performance'] = { lab: null, field: null, note: 'Not run: no Google PageSpeed Insights API key is configured for this audit engine, so Lighthouse lab data and Chrome field data are unavailable. Performance is therefore not scored.' };
  let perfScore: number | null = null;
  if (opts.pageSpeedKey) {
    const ps = await getPageSpeed(origin, opts.pageSpeedKey, deps.fetchImpl);
    if (ps) {
      perf = ps.perf; perfScore = ps.score;
      for (const f of ps.findings) add(f);
    } else perf.note = 'PageSpeed Insights was requested but did not return a result (timeout or quota). Performance is not scored.';
  }

  // ---- Stage 4: technical SEO
  await progress(4);
  if (new URL(homeUrl).protocol !== 'https:') add({ id: 'tech.https', category: 'technical', area: 'Trust & security', title: 'Store is not served over HTTPS', severity: 'critical', url: homeUrl, evidence: [`Final homepage URL: ${homeUrl}`], what: 'The store loads over an insecure connection.', why: 'Browsers warn shoppers and payment trust suffers.', impact: 'Visitors are likely to leave and search engines favour secure pages.', fix: 'Enable SSL for the domain in Shopify (Settings > Domains) and force HTTPS.', confidence: 'verified' });
  else pass({ id: 'tech.https', category: 'technical', title: 'HTTPS is enabled', detail: 'The homepage is served over HTTPS.' });
  if (httpHome.status && !(new URL(httpHome.url).protocol === 'https:')) add({ id: 'tech.http_redirect', category: 'technical', title: 'HTTP version does not redirect to HTTPS', severity: 'medium', url: `http://${host}/`, evidence: [`http://${host}/ ended on ${httpHome.url} (HTTP ${httpHome.status}).`], what: 'The insecure address is reachable without upgrading.', why: 'Shoppers and crawlers can land on an unsecured version.', impact: 'Splits trust and ranking signals.', fix: 'Turn on "Redirect all traffic to the primary domain" and SSL in Shopify.', confidence: 'verified' });
  if (home.redirects.length > 2) add({ id: 'tech.redirect_chain', category: 'technical', title: 'Homepage goes through a redirect chain', severity: 'low', url: base + '/', evidence: [`${home.redirects.length} redirects before the homepage: ${home.redirects.join(' → ')}`], what: 'More than two redirects are needed to reach the homepage.', why: 'Each hop adds delay and can dilute link signals.', impact: 'Slower first load.', fix: 'Point the primary domain directly to the final address.', confidence: 'verified' });
  if (!/<meta[^>]+name=["']viewport["']/i.test(html)) add({ id: 'tech.viewport', category: 'technical', title: 'No mobile viewport tag on the homepage', severity: 'high', url: homeUrl, evidence: ['No <meta name="viewport"> found in the homepage source.'], what: 'The page does not declare a mobile viewport.', why: 'Phones may render it as a shrunken desktop page.', impact: 'Poor mobile experience hurts conversion and mobile search.', fix: 'Add a viewport meta tag to theme.liquid or switch to a current responsive theme.', confidence: 'verified' });
  else pass({ id: 'tech.viewport', category: 'technical', title: 'Mobile viewport tag present', detail: 'The homepage declares a responsive viewport.' });
  if (/<meta[^>]+name=["']robots["'][^>]+content=["'][^"']*noindex/i.test(html)) add({ id: 'tech.noindex', category: 'technical', title: 'Homepage is set to noindex', severity: 'critical', url: homeUrl, evidence: ['A robots meta tag containing "noindex" was found on the homepage.'], what: 'Search engines are told not to index the homepage.', why: 'It cannot appear in search results.', impact: 'Organic visibility can be lost entirely for this page.', fix: 'Remove the noindex tag unless the store is intentionally hidden.', confidence: 'verified' });
  if (!getCanonical(html)) add({ id: 'tech.canonical', category: 'technical', title: 'No canonical tag on the homepage', severity: 'medium', url: homeUrl, evidence: ['No <link rel="canonical"> found.'], what: 'The homepage does not declare its preferred URL.', why: 'Duplicate URL versions can split ranking signals.', impact: 'Weaker consolidation of SEO signals.', fix: 'Add {{ canonical_url }} to the theme head.', confidence: 'verified' });
  if (!/<html[^>]+\blang=/i.test(html)) add({ id: 'tech.lang', category: 'technical', title: 'No language attribute on <html>', severity: 'low', url: homeUrl, evidence: ['The <html> tag has no lang attribute.'], what: 'The page language is not declared.', why: 'It helps search engines and screen readers.', impact: 'Minor accessibility and international SEO loss.', fix: 'Add lang="{{ request.locale.iso_code }}" to the theme.', confidence: 'verified' });
  if (!robots?.ok) add({ id: 'tech.robots', category: 'technical', title: 'robots.txt could not be retrieved', severity: 'medium', url: base + '/robots.txt', evidence: [`HTTP ${robots?.status ?? 0} for /robots.txt.`], what: 'The robots file did not load.', why: 'Crawlers rely on it for crawl guidance.', impact: 'Possible crawl issues.', fix: 'Check the domain setup; Shopify normally serves this automatically.', confidence: 'verified' });
  else if (!/sitemap:/i.test(robots.body)) add({ id: 'tech.robots_sitemap', category: 'technical', title: 'robots.txt does not reference a sitemap', severity: 'low', url: base + '/robots.txt', evidence: ['No "Sitemap:" line in robots.txt.'], what: 'The sitemap is not advertised to crawlers.', why: 'Helps discovery of all pages.', impact: 'Slower discovery of new products.', fix: 'Reference the sitemap URL in robots.txt.liquid.', confidence: 'verified' });
  else pass({ id: 'tech.robots', category: 'technical', title: 'robots.txt present and references a sitemap', detail: 'Crawlers can find the sitemap.' });
  if (!sitemap?.ok) add({ id: 'tech.sitemap', category: 'technical', title: 'XML sitemap not found', severity: 'high', url: base + '/sitemap.xml', evidence: [`HTTP ${sitemap?.status ?? 0} for /sitemap.xml.`], what: 'The standard Shopify sitemap did not load.', why: 'Search engines use it to find products and collections.', impact: 'New and updated products may be indexed more slowly.', fix: 'Confirm the domain is correctly connected and submit the sitemap in Google Search Console.', confidence: 'verified' });
  else pass({ id: 'tech.sitemap', category: 'technical', title: 'XML sitemap is available', detail: `${(sitemap.body.match(/<loc>/g) || []).length} sitemap entries listed at the top level.` });
  const homeLd = getJsonLdTypes(html);
  const prodLd = productPage?.ok ? getJsonLdTypes(productPage.body) : [];
  if (productPage?.ok && !prodLd.some((t) => /Product/i.test(t))) add({ id: 'seo.product_schema', category: 'seo', title: 'Product page has no Product structured data', severity: 'high', url: productPage.url, evidence: [`JSON-LD types found on the sampled product page: ${prodLd.join(', ') || 'none'}.`], what: 'The sampled product page does not expose Product schema.', why: 'Structured data enables price, availability and review rich results.', impact: 'Missed visibility in rich search results.', fix: 'Use a theme that outputs Product JSON-LD or add it via theme code.', confidence: 'verified' });
  else if (productPage?.ok) pass({ id: 'seo.product_schema', category: 'seo', title: 'Product structured data present', detail: 'The sampled product page exposes Product schema.' });
  if (!homeLd.some((t) => /Organization|WebSite|Store/i.test(t))) add({ id: 'seo.org_schema', category: 'seo', title: 'No Organization or WebSite structured data on the homepage', severity: 'opportunity', url: homeUrl, evidence: [`JSON-LD types on the homepage: ${homeLd.join(', ') || 'none'}.`], what: 'The homepage gives machines little structured information about the business.', why: 'Clear entity data helps search engines and AI assistants understand and cite the brand (GEO).', impact: 'Potential knowledge-panel and AI-answer visibility. No ranking data was retrieved.', fix: 'Add Organization and WebSite schema, with logo, social profiles and contact details.', confidence: 'verified' });

  // ---- On-page SEO
  const title = getTitle(html);
  const mdesc = getMeta(html, 'description');
  const h1s = getH1s(html);
  if (!title) add({ id: 'seo.title', category: 'seo', title: 'Homepage has no title tag', severity: 'high', url: homeUrl, evidence: ['No <title> found.'], what: 'The homepage title is missing.', why: 'The title is the main on-page ranking and click signal.', impact: 'Weak search snippets.', fix: 'Set a descriptive title in Online Store > Preferences.', confidence: 'verified' });
  else if (title.length < 20 || title.length > 65) add({ id: 'seo.title_len', category: 'seo', title: title.length < 20 ? 'Homepage title is very short' : 'Homepage title is too long for search results', severity: 'low', url: homeUrl, evidence: [`Title: "${title}" (${title.length} characters).`], what: 'The title length is outside the range that displays well.', why: 'Short titles waste keyword space; long titles are truncated.', impact: 'Less effective search snippet.', fix: 'Aim for roughly 30–60 characters that include what you sell.', confidence: 'verified' });
  else pass({ id: 'seo.title', category: 'seo', title: 'Homepage title length is good', detail: `"${title}"` });
  if (!mdesc) add({ id: 'seo.meta_desc', category: 'seo', title: 'Homepage has no meta description', severity: 'high', url: homeUrl, evidence: ['No meta description tag found.'], what: 'The homepage meta description is missing.', why: 'It shapes the text shown under your link in search results.', impact: 'Search engines pick random text, which usually clicks worse.', fix: 'Write a 120–155 character description in Preferences.', confidence: 'verified' });
  else if (mdesc.length < 70 || mdesc.length > 165) add({ id: 'seo.meta_desc_len', category: 'seo', title: 'Homepage meta description length is off', severity: 'low', url: homeUrl, evidence: [`"${mdesc.slice(0, 160)}" (${mdesc.length} characters).`], what: 'The description is too short or will be truncated.', why: 'Best results use about 120–155 characters.', impact: 'Minor click-through impact.', fix: 'Rewrite to a clear benefit-led 120–155 characters.', confidence: 'verified' });
  else pass({ id: 'seo.meta_desc', category: 'seo', title: 'Homepage meta description is set', detail: `${mdesc.length} characters.` });
  if (h1s.length === 0) add({ id: 'seo.h1', category: 'seo', title: 'Homepage has no H1 heading', severity: 'medium', url: homeUrl, evidence: ['No <h1> element found.'], what: 'The page has no main heading.', why: 'The H1 tells shoppers and search engines what the page is about.', impact: 'Weaker topical clarity.', fix: 'Add one clear H1 to the first section.', confidence: 'verified' });
  else if (h1s.length > 1) add({ id: 'seo.h1_multi', category: 'seo', title: 'Homepage has several H1 headings', severity: 'low', url: homeUrl, evidence: [`${h1s.length} H1 elements: ${h1s.slice(0, 3).map((h) => `"${h.slice(0, 60)}"`).join(', ')}`], what: 'More than one H1 is present.', why: 'A single H1 keeps the page hierarchy clear.', impact: 'Minor SEO clarity loss.', fix: 'Keep one H1 and use H2/H3 for other headings.', confidence: 'verified' });
  else pass({ id: 'seo.h1', category: 'seo', title: 'One H1 on the homepage', detail: `"${h1s[0].slice(0, 80)}"` });
  if (/welcome to our store|your store name|lorem ipsum/i.test(strip(html))) add({ id: 'seo.default_text', category: 'seo', title: 'Default theme placeholder text is visible', severity: 'high', url: homeUrl, evidence: ['Placeholder phrase such as "Welcome to our store" or "Lorem ipsum" found in homepage text.'], what: 'Theme starter copy is still live.', why: 'It signals an unfinished store and wastes prime keyword space.', impact: 'Lower trust and weaker search relevance.', fix: 'Replace placeholder text with clear brand and product messaging.', confidence: 'verified' });
  if (!getMeta(html, 'og:image') || !getMeta(html, 'og:title')) add({ id: 'seo.og', category: 'seo', title: 'Social sharing tags are incomplete', severity: 'low', url: homeUrl, evidence: [`og:title: ${getMeta(html, 'og:title') ? 'present' : 'missing'}, og:image: ${getMeta(html, 'og:image') ? 'present' : 'missing'}.`], what: 'Shared links will have a weak preview.', why: 'Previews affect clicks from social and messaging apps.', impact: 'Fewer clicks on shared links.', fix: 'Set a social sharing image in Preferences.', confidence: 'verified' });
  const noAlt = imgs.filter((i) => i.alt === null || i.alt.trim() === '');
  const contentImgs = imgs.filter((i) => !/pixel|spacer|icon/i.test(i.src));
  if (contentImgs.length >= 6 && wordsToPct(noAlt.length, imgs.length) > 30) add({ id: 'seo.alt_home', category: 'seo', title: 'Many homepage images have no alt text', severity: 'medium', url: homeUrl, evidence: [`${noAlt.length} of ${imgs.length} homepage images have empty or missing alt text.`], what: 'Images lack descriptive alt text.', why: 'Alt text feeds image search and accessibility.', impact: 'Lost image-search traffic and weaker accessibility.', fix: 'Describe each meaningful image in a few words.', confidence: 'verified' });

  // Catalogue (observed from /products.json)
  const total = products.length;
  const descOf = (p: Record<string, any>) => strip(String(p.body_html || ''));
  const thin = products.filter((p) => descOf(p).length < 100);
  if (total >= 3 && wordsToPct(thin.length, total) > 25) add({ id: 'seo.product_desc', category: 'seo', title: 'Many products have thin or missing descriptions', severity: wordsToPct(thin.length, total) > 60 ? 'high' : 'medium', url: base + '/products.json', evidence: [`${thin.length} of ${total} sampled products have fewer than 100 characters of description.`, ...thin.slice(0, 3).map((p) => `Example: ${base}/products/${p.handle}`)], what: 'Product pages carry little descriptive copy.', why: 'Descriptions answer buyer questions and give search engines content to rank.', impact: 'Lower product discoverability and weaker purchase confidence.', fix: 'Write benefit-led descriptions with materials, size, use and care details.', confidence: 'verified' });
  else if (total >= 3) pass({ id: 'seo.product_desc', category: 'seo', title: 'Most products have real descriptions', detail: `${total - thin.length} of ${total} sampled products have 100+ characters.` });
  const allImgs = products.flatMap((p) => (p.images || []) as Record<string, any>[]);
  const imgNoAlt = allImgs.filter((i) => !i.alt || !String(i.alt).trim());
  if (allImgs.length >= 5 && wordsToPct(imgNoAlt.length, allImgs.length) > 40) add({ id: 'seo.product_alt', category: 'seo', title: 'Most product images have no alt text', severity: 'medium', url: base + '/products.json', evidence: [`${imgNoAlt.length} of ${allImgs.length} product images have no alt text.`], what: 'Product photos are not described for search or accessibility.', why: 'Alt text supports image search and screen readers.', impact: 'Missed Google Images traffic for product searches.', fix: 'Add alt text to product images (describe the product and view).', confidence: 'verified' });
  const shortTitles = products.filter((p) => String(p.title || '').length < 12 || /^[A-Z0-9 ]{8,}$/.test(String(p.title || '')));
  if (total >= 5 && wordsToPct(shortTitles.length, total) > 30) add({ id: 'seo.product_titles', category: 'seo', title: 'Product titles may be too short or all caps', severity: 'low', url: base + '/products.json', evidence: [`${shortTitles.length} of ${total} products: ${shortTitles.slice(0, 3).map((p) => `"${p.title}"`).join(', ')}`], what: 'Titles carry little searchable detail.', why: 'Buyers search by product type, material and use.', impact: 'Lower relevance for product searches.', fix: 'Include the product type and a key attribute in each title.', confidence: 'likely' });
  const emptyColl = collections.filter((c) => !strip(String(c.body_html || '')));
  if (collections.length >= 2 && wordsToPct(emptyColl.length, collections.length) > 50) add({ id: 'seo.collection_desc', category: 'seo', title: 'Collection pages have no description text', severity: 'medium', url: base + '/collections.json', evidence: [`${emptyColl.length} of ${collections.length} collections have no description: ${emptyColl.slice(0, 3).map((c) => c.title).join(', ')}.`], what: 'Collections are bare product grids.', why: 'Collections target broad searches and need copy to rank.', impact: 'Underdeveloped category search visibility. No ranking data retrieved.', fix: 'Add a short intro and buying guide to each key collection.', confidence: 'verified' });
  if (productPage?.ok) {
    const pt = getTitle(productPage.body); const pd = getMeta(productPage.body, 'description');
    if (!pd) add({ id: 'seo.product_meta', category: 'seo', title: 'Sampled product page has no meta description', severity: 'medium', url: productPage.url, evidence: [`No meta description on ${productPage.url}.`], what: 'Product meta descriptions are missing or not generated.', why: 'They shape search snippets.', impact: 'Lower click-through from search.', fix: 'Set search engine listing text for products.', confidence: 'verified' });
    if (pt && title && pt === title) add({ id: 'seo.product_title_dup', category: 'seo', title: 'Product page title matches the homepage title', severity: 'medium', url: productPage.url, evidence: [`Both titled "${pt}".`], what: 'Duplicate titles across different pages.', why: 'Each page should have a unique title.', impact: 'Search engines struggle to tell pages apart.', fix: 'Give each product its own search listing title.', confidence: 'verified' });
  }
  if (!by('Sample product page') && total === 0) { /* nothing */ }

  // ---- Stage 5: UX & trust
  await progress(5);
  const contact = by('Contact page');
  const hasMailTel = /href=["'](mailto:|tel:)/i.test(html);
  if (!contact?.ok && !hasMailTel) add({ id: 'ux.contact', category: 'ux', area: 'Trust & security', title: 'No visible way to contact the store', severity: 'high', url: base + '/pages/contact', evidence: [`/pages/contact returned HTTP ${contact?.status ?? 0} and no mailto: or tel: link was found on the homepage.`], what: 'We could not find a contact page or contact details.', why: 'Shoppers want to know someone is reachable before paying.', impact: 'Reduced purchase confidence.', fix: 'Add a contact page with email, a form and response times.', confidence: 'likely' });
  else pass({ id: 'ux.contact', category: 'ux', title: 'A way to contact the store exists', detail: contact?.ok ? 'Contact page loads.' : 'Email or phone link found on the homepage.' });
  const about = by('About page')?.ok ? by('About page') : by('About page (alt)');
  if (!about?.ok && !/href=["'][^"']*about/i.test(html)) add({ id: 'ux.about', category: 'ux', area: 'Trust & security', title: 'No About page found', severity: 'medium', url: base + '/pages/about-us', evidence: ['/pages/about-us and /pages/about both failed, and no "about" link was found on the homepage.'], what: 'There is no obvious brand story page.', why: 'Shoppers check who is behind a store before buying.', impact: 'Weaker brand credibility.', fix: 'Add an About page with your story, location and proof points.', confidence: 'likely' });
  else pass({ id: 'ux.about', category: 'ux', title: 'About page found', detail: 'Brand story page is available.' });
  const policy = (label: string, id: string, sev: Severity, cat: CategoryKey, noun: string, why: string) => {
    const r = by(label);
    if (!r?.ok) add({ id, category: cat, area: 'Trust & security', title: `${noun} not found`, severity: sev, url: base + (wanted.find((w) => w[0] === label)?.[1] || ''), evidence: [`${base}${wanted.find((w) => w[0] === label)?.[1]} returned HTTP ${r?.status ?? 0}.`], what: `The ${noun.toLowerCase()} page is missing or empty.`, why, impact: 'Lower trust at the moment of purchase. This is not a legal assessment; consider professional review.', fix: `Add a clear ${noun.toLowerCase()} in Settings > Policies.`, confidence: 'verified' });
    else if (strip(r.body).length < 600) add({ id: id + '_thin', category: cat, area: 'Trust & security', title: `${noun} looks very thin`, severity: 'low', url: r.url, evidence: [`About ${strip(r.body).length} characters of text.`], what: 'The policy contains little detail.', why: 'Shoppers look for time limits, costs and how to start a return or track delivery.', impact: 'Unanswered questions reduce confidence.', fix: 'Spell out timeframes, costs and the process step by step.', confidence: 'likely' });
    else pass({ id, category: cat, title: `${noun} is published`, detail: r.url });
  };
  policy('Refund policy', 'trust.refund', 'high', 'cro', 'Refund policy', 'Return terms are among the top things shoppers check before ordering.');
  policy('Shipping policy', 'trust.shipping', 'high', 'cro', 'Shipping policy', 'Unclear delivery costs and times are a leading reason for abandoned carts.');
  policy('Privacy policy', 'trust.privacy', 'medium', 'ux', 'Privacy policy', 'Privacy information is expected and often required.');
  policy('Terms of service', 'trust.terms', 'low', 'ux', 'Terms of service', 'Clear terms set expectations for orders and disputes.');
  const hasSearch = /action=["'][^"']*\/search|name=["']q["']|type=["']search["']/i.test(html);
  if (!hasSearch && total > 30) add({ id: 'ux.search', category: 'ux', title: 'No site search on the homepage', severity: 'medium', url: homeUrl, evidence: [`The catalogue has ${total}+ products but no search form or search input was found in the homepage markup.`], what: 'Shoppers cannot search a sizeable catalogue.', why: 'Searchers convert at a higher rate than browsers.', impact: 'Harder product discovery on a larger catalogue.', fix: 'Add a search bar to the header.', confidence: 'likely' });
  if (collections.length === 0 && total > 20) add({ id: 'ux.collections', category: 'ux', title: 'No collections found for a larger catalogue', severity: 'medium', url: base + '/collections.json', evidence: [`${total} products but /collections.json listed none.`], what: 'Products are not organised into categories.', why: 'Collections guide browsing and carry category SEO.', impact: 'Harder discovery and weaker category rankings.', fix: 'Create collections by product type, use case and audience.', confidence: 'likely' });
  else if (collections.length) pass({ id: 'ux.collections', category: 'ux', title: 'Products are organised into collections', detail: `${collections.length} public collections found.` });
  if (!/<link[^>]+rel=["'](shortcut )?icon["']/i.test(html)) add({ id: 'ux.favicon', category: 'ux', title: 'No favicon declared', severity: 'low', url: homeUrl, evidence: ['No icon link found in the page head.'], what: 'The browser tab shows a blank icon.', why: 'Favicons aid recognition and look professional.', impact: 'Minor brand polish.', fix: 'Upload a favicon in theme settings.', confidence: 'verified' });
  const social = /(instagram|facebook|tiktok|pinterest|youtube|twitter|x)\.com\/[^"'\s<]+/i.test(html);
  if (!social) add({ id: 'ux.social', category: 'ux', title: 'No social profile links on the homepage', severity: 'low', url: homeUrl, evidence: ['No links to major social platforms found in the homepage source.'], what: 'Shoppers cannot verify your social presence.', why: 'Active social profiles are a trust signal.', impact: 'Slightly lower credibility.', fix: 'Link your social profiles in the footer.', confidence: 'verified' });
  const imgsPerProduct = products.filter((p) => ((p.images || []) as unknown[]).length <= 1);
  if (total >= 5 && wordsToPct(imgsPerProduct.length, total) > 40) add({ id: 'cro.product_images', category: 'cro', title: 'Many products have only one image', severity: 'medium', url: base + '/products.json', evidence: [`${imgsPerProduct.length} of ${total} products have 0–1 images.`, ...imgsPerProduct.slice(0, 2).map((p) => `${base}/products/${p.handle}`)], what: 'Single photos do not show scale, detail or use.', why: 'Shoppers cannot touch the product; images do that job.', impact: 'Lower purchase confidence. Count of images only: quality was not judged.', fix: 'Add 4–6 images per product: angles, detail, in-use and scale.', confidence: 'verified' });

  // ---- Stage 6: CRO
  await progress(6);
  const pbody = productPage?.ok ? productPage.body : '';
  if (productPage?.ok) {
    const hasAdd = /name=["']add["']|add[-_ ]to[-_ ]cart|product-form|data-add-to-cart|sold out|unavailable/i.test(pbody);
    if (!hasAdd) add({ id: 'cro.add_to_cart', category: 'cro', title: 'No add-to-cart button detected on the sampled product page', severity: 'high', url: productPage.url, evidence: [`No add-to-cart form or button markup found on ${productPage.url}.`], what: 'The sampled product page may not offer a clear way to buy.', why: 'The add-to-cart button is the conversion point.', impact: 'Possible lost sales if confirmed. Verify manually, as some themes load the button with scripts.', fix: 'Check the product template and any page-builder or app overrides.', confidence: 'likely' });
    else pass({ id: 'cro.add_to_cart', category: 'cro', title: 'Add-to-cart present on product page', detail: productPage.url });
    const hasReviews = /judge\.me|loox|stamped\.io|yotpo|okendo|reviews\.io|trustpilot|ali-?reviews|shopify-product-reviews|spr-badge|rating/i.test(pbody + html);
    if (!hasReviews) add({ id: 'cro.reviews', category: 'cro', title: 'No customer reviews detected', severity: 'medium', url: productPage.url, evidence: ['No review app or ratings markup found on the sampled product page or homepage.'], what: 'Social proof from customers is not visible.', why: 'Reviews are one of the strongest purchase triggers for new visitors.', impact: 'Higher hesitation for first-time buyers. Reviews loaded late by scripts may not be detected.', fix: 'Install a reviews app and request reviews after delivery.', confidence: 'likely' });
    else pass({ id: 'cro.reviews', category: 'cro', title: 'Reviews or ratings signal detected', detail: 'Review markup or app found (not verified as complete).' });
    if (!/shipping|delivery|dispatch/i.test(strip(pbody)) && !by('Shipping policy')?.ok) add({ id: 'cro.shipping_visible', category: 'cro', title: 'Shipping information not visible near the product', severity: 'medium', url: productPage.url, evidence: ['No mention of shipping or delivery found in the sampled product page text.'], what: 'Shoppers cannot see delivery costs or times before the cart.', why: 'Surprise costs at checkout are a top abandonment cause.', impact: 'Potential cart abandonment.', fix: 'Add a short delivery and returns line under the buy button.', confidence: 'likely' });
    if (!/recommend|you may also like|related|complete the look|frequently bought/i.test(pbody)) add({ id: 'cro.upsell', category: 'cro', title: 'No related or recommended products on the product page', severity: 'opportunity', url: productPage.url, evidence: ['No recommendations section markup found on the sampled product page.'], what: 'There is no visible cross-sell on product pages.', why: 'Recommendations raise order value and keep shoppers browsing.', impact: 'Missed average-order-value opportunity. Size not quantified.', fix: 'Enable related products or bundle offers on product pages.', confidence: 'likely' });
    if (!/shop pay|visa|mastercard|paypal|apple pay|secure checkout|payment/i.test(pbody + html)) add({ id: 'cro.payment_trust', category: 'cro', title: 'No payment or secure-checkout cues visible', severity: 'low', url: productPage.url, evidence: ['No payment icons or secure-checkout wording found on the product page or homepage.'], what: 'Payment options are not shown before checkout.', why: 'Familiar payment icons reassure shoppers.', impact: 'Slightly lower checkout confidence.', fix: 'Show accepted payment icons in the footer or under the buy button.', confidence: 'indicative' });
  }
  const variants = products.flatMap((p) => (p.variants || []) as Record<string, any>[]);
  const unavailable = variants.filter((v) => v.available === false);
  if (variants.length >= 10 && wordsToPct(unavailable.length, variants.length) > 30) add({ id: 'cro.out_of_stock', category: 'cro', title: 'A large share of variants are unavailable', severity: 'medium', url: base + '/products.json', evidence: [`${unavailable.length} of ${variants.length} variants are marked unavailable (point-in-time snapshot).`], what: 'Many items cannot be bought right now.', why: 'Sold-out pages lose traffic that has no alternative to buy.', impact: 'Lost sales and wasted ad clicks while stock is out.', fix: 'Add back-in-stock alerts and hide or redirect long-term unavailable items.', confidence: 'verified' });
  if (total > 0 && !variants.some((v) => v.compare_at_price && Number(v.compare_at_price) > Number(v.price))) add({ id: 'cro.compare_at', category: 'cro', title: 'No sale or compare-at pricing in use', severity: 'opportunity', url: base + '/products.json', evidence: [`None of the ${variants.length} sampled variants has a compare-at price.`], what: 'Price anchoring is not used.', why: 'Showing a reference price helps shoppers judge value.', impact: 'Possible conversion upside on promotions. Not quantified.', fix: 'Use compare-at pricing for genuine promotions.', confidence: 'verified' });
  if (total > 0 && total < 6) add({ id: 'cro.thin_catalog', category: 'cro', title: 'Very small catalogue', severity: 'opportunity', url: base + '/products.json', evidence: [`${total} public products found.`], what: 'Few products limit browsing and basket size.', why: 'Small ranges need strong bundles and a clear hero product.', impact: 'Limited cross-sell room.', fix: 'Add bundles, variants and complementary products.', confidence: 'verified' });
  if (total >= 250) { /* sample cap, disclosed in coverage */ }

  // ---- Stage 7: marketing readiness
  await progress(7);
  const all = html + (pbody || '');
  const has = (re: RegExp) => re.test(all);
  const emailForm = /<input[^>]+type=["']email["']|name=["']contact\[email\]["']|customer_form|newsletter/i.test(html);
  if (!emailForm) add({ id: 'mkt.email_capture', category: 'marketing', title: 'No email signup form found on the homepage', severity: 'high', url: homeUrl, evidence: ['No email input or newsletter form found in the homepage markup (pop-ups loaded by apps may not be visible to this check).'], what: 'There is no visible way to join your list.', why: 'Email is the cheapest channel for repeat sales.', impact: 'Visitors leave without being captured. Pop-ups added by apps could exist but were not detected.', fix: 'Add a signup form in the footer and an incentive-led pop-up.', confidence: 'likely' });
  else pass({ id: 'mkt.email_capture', category: 'marketing', title: 'Email signup form present', detail: 'A signup form or email input was found on the homepage.' });
  const platforms: [string, RegExp][] = [['Klaviyo', /klaviyo/i], ['Mailchimp', /mailchimp|chimpstatic/i], ['Omnisend', /omnisend/i], ['Shopify Email', /shopify-email|shopifyemail/i], ['Brevo/Sendinblue', /sendinblue|brevo/i], ['Privy', /privy\.com|privy-?widget/i], ['Attentive/Postscript (SMS)', /attn\.tv|attentive|postscript/i]];
  const detected = platforms.filter(([, re]) => has(re)).map(([n]) => n);
  if (!detected.length) add({ id: 'mkt.email_platform', category: 'marketing', title: 'No email marketing platform detected', severity: 'medium', url: homeUrl, evidence: ['No Klaviyo, Mailchimp, Omnisend, Brevo or similar scripts found in the page source.'], what: 'We could not detect an email or SMS marketing tool.', why: 'Welcome, abandoned-cart and post-purchase flows run on one of these.', impact: 'Repeat-purchase automation may be missing. Detection is by public scripts only; an installed tool is not proof its flows work.', fix: 'Set up Klaviyo (or similar) with welcome, abandoned cart, browse abandonment and post-purchase flows.', confidence: 'indicative' });
  else pass({ id: 'mkt.email_platform', category: 'marketing', title: `Marketing tool signal detected: ${detected.join(', ')}`, detail: 'Detected from public scripts. Whether campaigns and automations work was not tested.' });
  const shopifyAnalytics = /web-pixels-manager|trekkie|shopify\.analytics|monorail/i.test(all);
  const meta = /fbevents\.js|fbq\(|connect\.facebook\.net/i.test(all);
  const ga = /gtag\/js|googletagmanager\.com|google-analytics\.com|ga\('create'/i.test(all);
  if (!meta && !ga) add({ id: 'mkt.tracking', category: 'marketing', title: 'No Meta Pixel or Google tag found in the page source', severity: 'opportunity', url: homeUrl, evidence: [`Meta pixel script: ${meta ? 'found' : 'not found'}; Google tag/GTM: ${ga ? 'found' : 'not found'}; Shopify analytics signals: ${shopifyAnalytics ? 'found' : 'not found'}.`], what: 'Common tracking scripts were not visible in the HTML.', why: 'Tracking powers ads optimisation and analytics.', impact: 'Indicative only: Shopify can load pixels through sandboxed web pixels that this check cannot see, so tracking may exist.', fix: 'Confirm Meta and Google tracking in Shopify Customer Events and Google Tag Assistant.', confidence: 'indicative' });
  else pass({ id: 'mkt.tracking', category: 'marketing', title: 'Tracking signals detected', detail: `${meta ? 'Meta Pixel ' : ''}${ga ? 'Google tag/GTM ' : ''}detected. Correct configuration was not verified.` });
  if (!has(/smile\.io|yotpo|loyaltylion|swell|referralcandy|growave|rise\.ai|stamped|loyalty/i)) add({ id: 'mkt.loyalty', category: 'marketing', title: 'No loyalty or referral programme detected', severity: 'opportunity', url: homeUrl, evidence: ['No loyalty or referral app signals found in the page source.'], what: 'Nothing visible encourages repeat orders or referrals.', why: 'Repeat customers cost less to win than new ones.', impact: 'Possible repeat-purchase upside; not quantified.', fix: 'Add a simple points or referral offer after first purchase.', confidence: 'indicative' });
  if (!/href=["'][^"']*\/blogs\//i.test(html)) add({ id: 'mkt.content', category: 'marketing', title: 'No blog or content hub linked from the homepage', severity: 'opportunity', url: homeUrl, evidence: ['No link to /blogs/ found in the homepage source.'], what: 'There is no visible content marketing channel.', why: 'Guides and how-tos capture buyers earlier in the search journey.', impact: 'Possible organic traffic opportunity. No keyword data retrieved.', fix: 'Publish buying guides and answers to common product questions.', confidence: 'likely' });

  // ---- Stage 8: connect related findings
  await progress(8);
  const has2 = (id: string) => findings.some((f) => f.id === id);
  const conn: Report['connections'] = [];
  if ((has2('seo.product_desc') || has2('seo.product_titles')) && (has2('seo.meta_desc') || has2('seo.product_meta') || has2('seo.product_schema'))) conn.push({ title: 'Thin product content plus weak search markup', text: 'Short product descriptions and missing meta data or structured data give search engines little to work with, so products are harder to find and shoppers who do arrive have fewer answers.', findingIds: ['seo.product_desc', 'seo.product_titles', 'seo.meta_desc', 'seo.product_meta', 'seo.product_schema'].filter(has2) });
  if (findings.some((f) => f.category === 'performance') && (has2('cro.product_images') || has2('cro.add_to_cart'))) conn.push({ title: 'Heavy pages and a harder product page', text: 'Performance signals suggest extra weight on the page, and the product page also shows friction. Together this can make the path to purchase slower and less clear on mobile.', findingIds: findings.filter((f) => f.category === 'performance' || f.id === 'cro.product_images' || f.id === 'cro.add_to_cart').map((f) => f.id) });
  if ((has2('cro.reviews') || has2('trust.refund') || has2('ux.contact')) && (has2('trust.shipping') || has2('cro.shipping_visible'))) conn.push({ title: 'Missing proof plus unclear delivery terms', text: 'No visible reviews or contact route, combined with unclear shipping or return terms, leaves first-time buyers with unanswered risk questions at the moment they decide.', findingIds: ['cro.reviews', 'trust.refund', 'ux.contact', 'trust.shipping', 'cro.shipping_visible'].filter(has2) });
  if (has2('mkt.email_capture') || has2('mkt.email_platform')) if (has2('mkt.email_capture') && has2('mkt.email_platform')) conn.push({ title: 'No list-building and no detected email tool', text: 'With no signup form and no detected email platform, visitors who are not ready to buy have no way to stay connected, which limits repeat business.', findingIds: ['mkt.email_capture', 'mkt.email_platform'] });
  if (has2('seo.default_text') || has2('seo.title') || has2('seo.h1')) conn.push({ title: 'Homepage messaging is unclear to shoppers and search engines', text: 'Placeholder text or missing title/H1 weakens both first impressions and keyword relevance on your most important page.', findingIds: ['seo.default_text', 'seo.title', 'seo.h1'].filter(has2) });

  // ---- Stage 9: score + assemble
  await progress(9);
  const cats = (Object.keys(WEIGHTS) as CategoryKey[]).map((key) => {
    const fs = findings.filter((f) => f.category === key);
    const checksRun = fs.length + passes.filter((p) => p.category === key).length;
    let scored = checksRun >= 3;
    let score: number | null = null;
    let note = `${checksRun} checks run.`;
    if (key === 'performance') {
      if (perfScore !== null) { score = Math.round(perfScore); scored = true; note = 'Mobile Lighthouse performance score (lab data) from Google PageSpeed Insights.'; }
      else { scored = false; note = 'Not scored: needs Lighthouse / PageSpeed data. Page-level signals are listed as findings but do not affect the score.'; }
    } else if (scored) {
      score = Math.max(0, Math.round(100 - fs.reduce((s, f) => s + PENALTY[f.severity], 0)));
    } else note = 'Not enough accessible information to score this category.';
    return { key, label: CATEGORY_LABEL[key], weight: WEIGHTS[key], scored, score, findings: fs.length, note };
  });
  const scoredCats = cats.filter((c) => c.scored && c.score !== null);
  const wsum = scoredCats.reduce((s, c) => s + c.weight, 0);
  const overall = Math.round(scoredCats.reduce((s, c) => s + (c.score as number) * c.weight, 0) / (wsum || 1));
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, opportunity: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const counts = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, opportunity: 0 };
  findings.forEach((f) => counts[f.severity]++);
  const phase = (f: Finding) => (f.severity === 'critical' ? 0 : f.category === 'technical' || f.category === 'seo' || f.category === 'performance' ? 1 : f.category === 'ux' ? 2 : f.category === 'cro' ? 3 : 4);
  const phaseNames = ['Phase 1: Critical corrections', 'Phase 2: Technical and SEO improvements', 'Phase 3: User experience and design improvements', 'Phase 4: Conversion optimisation', 'Phase 5: Marketing and customer retention'];
  const roadmap = phaseNames.map((p, i) => ({ phase: p, items: findings.filter((f) => phase(f) === i && f.severity !== 'opportunity').map((f) => ({ title: f.fix, why: f.title, priority: f.severity, findingId: f.id })) }));
  const opps = findings.filter((f) => f.severity === 'opportunity').map((f) => ({ title: f.title, text: `${f.why} ${f.fix}` }));
  const weakest = [...scoredCats].sort((a, b) => (a.score as number) - (b.score as number)).slice(0, 2).map((c) => c.label.toLowerCase());
  const summary = `We reviewed ${host} using public information from ${fetched.filter((f) => f.res.ok).length + 1} accessible pages plus the public product catalogue. The store scores ${overall}/100 across ${scoredCats.length} scored categories, with ${counts.critical} critical and ${counts.high} high-priority issues. ${weakest.length ? `The main areas to look at first are ${weakest.join(' and ')}.` : ''} ${passes.length} checks passed. This is a public-data audit: it does not include your sales, traffic or conversion data.`;
  const pages = [{ path: '/', status: home.status, ms: home.ms }, { path: '/products.json', status: productsRes.status, ms: productsRes.ms }, { path: '/collections.json', status: collRes.status, ms: collRes.ms }, ...fetched.map((f) => ({ path: f.path, status: f.res.status, ms: f.res.ms }))];
  const failed = pages.filter((p) => !(p.status >= 200 && p.status < 300));
  const nicheGuess = collections.slice(0, 4).map((c) => c.title).filter(Boolean).join(', ') || [...new Set(products.map((p) => p.product_type).filter(Boolean))].slice(0, 4).join(', ') || 'Not determined';
  const report: Report = {
    version: 1,
    store: { name: storeName, domain: host, url: origin, niche: nicheGuess, platform: 'shopify' },
    auditedAt: now.toISOString(),
    overall: { score: overall, scoredCategories: scoredCats.map((c) => c.key), note: `Weighted across scored categories only (${scoredCats.map((c) => `${c.label} ${c.weight}%`).join(', ')}). Unscored categories are not counted against the store; weights are re-normalised.` },
    categories: cats,
    counts, findings, passes, connections: conn, roadmap, opportunities: opps, summary,
    performance: perf,
    trafficIntelligence: { status: 'unavailable', note: 'Traffic, sales, revenue and conversion figures cannot be read from a public store URL and no third-party traffic provider is connected to this audit. We do not estimate or invent them. A connected-Shopify audit (read-only OAuth) is planned for a later phase.' },
    coverage: {
      pagesRequested: pages.length, pagesAnalysed: pages.length - failed.length,
      pagesFailed: failed.map((p) => ({ path: p.path, reason: p.status === 0 ? 'No response' : `HTTP ${p.status}` })),
      pages,
      catalogSampled: { products: total, collections: collections.length, note: total >= 250 ? 'The first 250 products from the public catalogue were analysed; larger catalogues are sampled.' : 'The full public catalogue was analysed.' },
      tools: ['Server-side page fetch (public HTML)', 'Shopify public catalogue endpoints (/products.json, /collections.json)', 'robots.txt and sitemap.xml checks', 'Rule-based scoring (documented weights)'].concat(opts.pageSpeedKey ? ['Google PageSpeed Insights API'] : []),
      verified: ['HTTPS and redirects', 'Homepage and product page meta data, headings and structured data', 'Presence of policy, contact and about pages', 'Catalogue content counts (descriptions, images, alt text, availability)', 'Detected scripts and apps (presence only)'],
      estimated: [],
      unavailable: ['Traffic, orders, revenue, conversion rate and average order value', 'Search rankings and keyword data', 'Checkout testing and abandoned-cart automation behaviour', 'Real-user Core Web Vitals' + (perfScore !== null ? ' (see performance section)' : ' and Lighthouse lab data'), 'Pages behind login or scripts that render content after load'],
      limitations: ['This is not a full crawl: it samples key pages, one product and one collection page, and the public catalogue.', 'Detection of apps and pixels uses public page source only; detected does not mean correctly configured.', 'Shopify web pixels and some pop-ups load in ways a page fetch cannot see.', 'Policy findings are observations, not legal advice.', 'Findings are point-in-time from one server location.'],
    },
    // AI interpretation is added by a later phase; Phase 1 uses deterministic, evidence-based text only.
  } as Report;
  return { status: 'completed', report };
}

// ---------- Google PageSpeed Insights (real lab + CrUX field data) ----------
async function getPageSpeed(url: string, key: string, fetchImpl: typeof fetch): Promise<{ perf: Report['performance']; score: number; findings: Omit<Finding, 'area'>[] } | null> {
  try {
    const api = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=mobile&category=performance&key=${encodeURIComponent(key)}`;
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 45_000);
    const r = await fetchImpl(api, { signal: ctrl.signal }); clearTimeout(t);
    if (!r.ok) return null;
    const j = await r.json();
    const lh = j.lighthouseResult; if (!lh) return null;
    const a = lh.audits || {};
    const score = Math.round((lh.categories?.performance?.score ?? 0) * 100);
    const lab = { score, lcpMs: a['largest-contentful-paint']?.numericValue, cls: a['cumulative-layout-shift']?.numericValue, tbtMs: a['total-blocking-time']?.numericValue, fcpMs: a['first-contentful-paint']?.numericValue, speedIndexMs: a['speed-index']?.numericValue, strategy: 'mobile', source: 'Lighthouse lab test via PageSpeed Insights' };
    const fe = j.loadingExperience?.metrics;
    const field = fe ? { lcpMs: fe.LARGEST_CONTENTFUL_PAINT_MS?.percentile, inpMs: fe.INTERACTION_TO_NEXT_PAINT?.percentile, cls: fe.CUMULATIVE_LAYOUT_SHIFT_SCORE?.percentile != null ? fe.CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile / 100 : null, category: j.loadingExperience?.overall_category, source: 'Chrome UX Report (real users, 28 days)' } : null;
    const findings: Omit<Finding, 'area'>[] = [];
    const u = url;
    if (lab.lcpMs > 4000) findings.push({ id: 'perf.lcp', category: 'performance', title: 'Slow Largest Contentful Paint (lab)', severity: lab.lcpMs > 6000 ? 'high' : 'medium', url: u, evidence: [`Lab LCP ${(lab.lcpMs / 1000).toFixed(1)}s on a simulated mobile device (good is under 2.5s).`], what: 'The main content takes long to appear on mobile.', why: 'LCP measures when shoppers see the main content.', impact: 'Slow loads raise early abandonment. Lab data is a simulation, not real-user data.', fix: 'Compress and properly size the hero image and defer heavy scripts.', confidence: 'verified' });
    if (lab.cls > 0.1) findings.push({ id: 'perf.cls', category: 'performance', title: 'Layout shift detected (lab)', severity: lab.cls > 0.25 ? 'medium' : 'low', url: u, evidence: [`Lab CLS ${lab.cls.toFixed(2)} (good is under 0.1).`], what: 'Page elements move while loading.', why: 'Shifting content causes mis-taps and frustration.', impact: 'Hurts the mobile experience and a Core Web Vitals signal.', fix: 'Reserve space for images, banners and app widgets.', confidence: 'verified' });
    if (lab.tbtMs > 600) findings.push({ id: 'perf.tbt', category: 'performance', title: 'High blocking time from JavaScript (lab)', severity: 'medium', url: u, evidence: [`Total Blocking Time ${Math.round(lab.tbtMs)} ms (good is under 200 ms).`], what: 'JavaScript keeps the page unresponsive during load.', why: 'It is closely related to Interaction to Next Paint.', impact: 'Taps feel laggy on mid-range phones.', fix: 'Remove unused apps and defer third-party scripts.', confidence: 'verified' });
    return { perf: { lab, field, note: 'Lab figures come from a simulated mobile Lighthouse run; field figures (if shown) come from real Chrome users and are only available for sites with enough traffic.' }, score, findings };
  } catch { return null; }
}
