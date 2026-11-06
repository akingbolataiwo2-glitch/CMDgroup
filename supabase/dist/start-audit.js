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
var resolver = async (host, type) => {
  return await Deno.resolveDns(host, type);
};
async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function clientIp(req) {
  return (req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for") || "unknown").split(",")[0].trim();
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

// _shared/ssrf.ts
function isPrivateIp(ip) {
  const v = ip.trim().toLowerCase();
  if (v.includes(":")) {
    if (v === "::1" || v === "::") return true;
    if (v.startsWith("fe80") || v.startsWith("fc") || v.startsWith("fd")) return true;
    if (v.startsWith("::ffff:")) return isPrivateIp(v.slice(7));
    return false;
  }
  const p = v.split(".").map((n) => Number(n));
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}
var IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;
function parseTarget(input) {
  let raw = String(input || "").trim();
  if (!raw) return { ok: false, error: "Please enter your store URL." };
  if (raw.length > 300) return { ok: false, error: "That URL is too long." };
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, error: "That does not look like a valid web address." };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { ok: false, error: "Only http and https addresses are supported." };
  if (u.username || u.password) return { ok: false, error: "Please enter the address without a username or password." };
  const host = u.hostname.toLowerCase();
  if (!host.includes(".") || host.endsWith(".")) return { ok: false, error: "Please enter a full domain, like yourstore.com." };
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    return { ok: false, error: "That address cannot be audited." };
  }
  if (IPV4_LITERAL.test(host) || host.startsWith("[")) return { ok: false, error: "Please enter a store domain, not an IP address." };
  if (!/^[a-z0-9.-]+$/.test(host) && !host.startsWith("xn--") && !/[^\x00-\x7f]/.test(host)) {
    return { ok: false, error: "That domain contains characters we cannot audit." };
  }
  if (u.port && u.port !== "80" && u.port !== "443") return { ok: false, error: "Please use a standard web address without a custom port." };
  const origin = new URL(`${u.protocol}//${host}/`);
  return { ok: true, url: origin };
}
async function assertPublicHost(host, resolve) {
  const addrs = [];
  for (const t of ["A", "AAAA"]) {
    try {
      addrs.push(...await resolve(host, t));
    } catch {
    }
  }
  if (addrs.length === 0) throw new Error("DNS_NOT_FOUND");
  for (const ip of addrs) if (isPrivateIp(ip)) throw new Error("PRIVATE_ADDRESS");
}
var MAX_BYTES = 15e5;
var MAX_REDIRECTS = 4;
var TIMEOUT_MS = 12e3;
var UA = "CMDGroupAuditBot/1.0 (+https://crestmatrixdigital.com/shopify-store-audit)";
async function safeFetch(rawUrl, deps, init = {}) {
  const started = Date.now();
  const redirects = [];
  let current = rawUrl;
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const u = new URL(current);
      if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("BAD_PROTOCOL");
      if (u.port && u.port !== "80" && u.port !== "443") throw new Error("BAD_PORT");
      await assertPublicHost(u.hostname, deps.resolve);
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
      let res;
      try {
        res = await deps.fetchImpl(u.toString(), {
          redirect: "manual",
          signal: ctrl.signal,
          headers: { "user-agent": UA, accept: init.accept || "text/html,application/json,application/xml,text/plain;q=0.9,*/*;q=0.5" }
        });
      } finally {
        clearTimeout(timer);
      }
      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        const next = new URL(res.headers.get("location"), u).toString();
        redirects.push(next);
        current = next;
        try {
          await res.body?.cancel();
        } catch {
        }
        continue;
      }
      let body = "";
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
            try {
              await reader.cancel();
            } catch {
            }
            break;
          }
          body += dec.decode(value, { stream: true });
        }
      }
      const headers = {};
      res.headers.forEach((v, k) => headers[k.toLowerCase()] = v);
      return { ok: res.status >= 200 && res.status < 300, status: res.status, url: u.toString(), headers, body, ms: Date.now() - started, redirects, truncated };
    }
    throw new Error("TOO_MANY_REDIRECTS");
  } catch (e) {
    return { ok: false, status: 0, url: current, headers: {}, body: "", ms: Date.now() - started, redirects, truncated: false, error: e.message || "FETCH_FAILED" };
  }
}

// _shared/audit.ts
var WEIGHTS = { seo: 20, ux: 20, cro: 20, performance: 15, technical: 15, marketing: 10 };
var CATEGORY_LABEL = {
  seo: "SEO",
  ux: "User experience",
  cro: "Conversion optimisation",
  performance: "Website performance",
  technical: "Technical health",
  marketing: "Marketing readiness"
};
var PENALTY = { critical: 28, high: 14, medium: 6, low: 2, opportunity: 0 };
var strip = (s) => s.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();
var decode = (s) => s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
function getTitle(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? decode(m[1].replace(/\s+/g, " ").trim()) : "";
}
function getMeta(html, name) {
  const re = new RegExp(`<meta[^>]+(?:name|property)=["']${name}["'][^>]*>`, "i");
  const tag = html.match(re)?.[0] || "";
  const c = tag.match(/content=["']([\s\S]*?)["']/i);
  return c ? decode(c[1].trim()) : "";
}
function getCanonical(html) {
  const m = html.match(/<link[^>]+rel=["']canonical["'][^>]*>/i)?.[0] || "";
  return m.match(/href=["']([^"']+)["']/i)?.[1] || "";
}
function getH1s(html) {
  return [...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi)].map((m) => strip(m[1])).filter(Boolean);
}
function getImages(html) {
  return [...html.matchAll(/<img\b[^>]*>/gi)].map((m) => {
    const t = m[0];
    const alt = t.match(/\balt=(["'])([\s\S]*?)\1/i);
    return { src: t.match(/\bsrc=["']([^"']*)["']/i)?.[1] || "", alt: alt ? alt[2] : null, loading: t.match(/\bloading=["']([^"']*)["']/i)?.[1] || null, hasDims: /\bwidth=/i.test(t) && /\bheight=/i.test(t) };
  });
}
function getScripts(html) {
  const headEnd = html.search(/<\/head>/i);
  return [...html.matchAll(/<script\b([^>]*)>/gi)].map((m) => ({
    src: m[1].match(/\bsrc=["']([^"']+)["']/i)?.[1] || "",
    async: /\basync\b/i.test(m[1]),
    defer: /\bdefer\b/i.test(m[1]),
    module: /type=["']module["']/i.test(m[1]),
    inHead: headEnd < 0 ? false : (m.index ?? 0) < headEnd
  })).filter((s) => s.src);
}
function getJsonLdTypes(html) {
  const out = [];
  for (const m of html.matchAll(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      const walk = (n) => {
        if (Array.isArray(n)) n.forEach(walk);
        else if (n && typeof n === "object") {
          const o = n;
          const t = o["@type"];
          if (typeof t === "string") out.push(t);
          else if (Array.isArray(t)) out.push(...t);
          if (o["@graph"]) walk(o["@graph"]);
        }
      };
      walk(JSON.parse(m[1]));
    } catch {
    }
  }
  return out;
}
var hostOf = (u, base) => {
  try {
    return new URL(u, base).hostname;
  } catch {
    return "";
  }
};
var wordsToPct = (n, d) => d ? Math.round(n / d * 100) : 0;
async function runAudit(origin, deps, progress, opts = {}) {
  const now = (opts.now || (() => /* @__PURE__ */ new Date()))();
  const base = origin.replace(/\/$/, "");
  const host = new URL(origin).hostname;
  const get = (path) => safeFetch(path.startsWith("http") ? path : base + path, deps);
  await progress(0);
  const home = await get("/");
  if (!home.ok && home.status === 0) return { status: "unreachable", message: `We could not reach ${host} (${home.error || "no response"}).` };
  if (home.status >= 400) return { status: "unreachable", message: `${host} answered with HTTP ${home.status}, so the store could not be audited.` };
  await progress(1);
  const html = home.body;
  const hdr = home.headers;
  const signals = [];
  if (/cdn\.shopify\.com|\/cdn\/shop\//i.test(html)) signals.push("Shopify CDN assets (cdn.shopify.com or /cdn/shop/) loaded on the homepage");
  if (/Shopify\.theme|Shopify\.shop\s*=|shopify-features/i.test(html)) signals.push("Shopify JavaScript globals present in the page source");
  if (hdr["x-shopid"] || hdr["x-shardid"] || /shopify/i.test(hdr["powered-by"] || "")) signals.push("Shopify response headers (x-shopid / x-shardid)");
  const productsRes = await get("/products.json?limit=250");
  let productsJson = null;
  try {
    productsJson = productsRes.ok ? JSON.parse(productsRes.body) : null;
  } catch {
    productsJson = null;
  }
  if (productsJson && Array.isArray(productsJson.products)) signals.push("Public Shopify catalogue endpoint /products.json responded");
  if (signals.length === 0) {
    return { status: "not_shopify", message: `${host} does not appear to be powered by Shopify (no Shopify signals found in the page source, headers or catalogue endpoint).` };
  }
  if (/\/password\/?$/.test(new URL(home.url).pathname) || /<form[^>]+action=["'][^"']*\/password/i.test(html)) {
    return { status: "password", message: `${host} is currently password-protected, so shoppers (and our audit) cannot see the store.` };
  }
  await progress(2);
  const products = productsJson?.products || [];
  const firstHandle = products[0]?.handle;
  const collRes = await get("/collections.json?limit=100");
  let collections = [];
  try {
    collections = collRes.ok ? JSON.parse(collRes.body).collections || [] : [];
  } catch {
    collections = [];
  }
  const firstCollection = collections.find((c) => c.products_count > 0)?.handle || collections[0]?.handle;
  const wanted = [
    ["robots.txt", "/robots.txt"],
    ["sitemap.xml", "/sitemap.xml"],
    ["Refund policy", "/policies/refund-policy"],
    ["Shipping policy", "/policies/shipping-policy"],
    ["Privacy policy", "/policies/privacy-policy"],
    ["Terms of service", "/policies/terms-of-service"],
    ["Contact page", "/pages/contact"],
    ["About page", "/pages/about-us"],
    ["About page (alt)", "/pages/about"]
  ];
  if (firstHandle) wanted.push(["Sample product page", `/products/${firstHandle}`]);
  if (firstCollection) wanted.push(["Sample collection page", `/collections/${firstCollection}`]);
  const fetched = [];
  const results = await Promise.all(wanted.map(async ([label, path]) => ({ label, path, res: await get(path) })));
  fetched.push(...results);
  const httpHome = await safeFetch(`http://${host}/`, deps);
  const by = (label) => fetched.find((f) => f.label === label)?.res;
  const productPage = by("Sample product page");
  const collectionPage = by("Sample collection page");
  const robots = by("robots.txt");
  const sitemap = by("sitemap.xml");
  const findings = [];
  const passes = [];
  const add = (f) => findings.push({ area: f.area || CATEGORY_LABEL[f.category], ...f });
  const pass = (p) => passes.push(p);
  const storeName = decode(getMeta(html, "og:site_name") || getTitle(html).split(/[|–—-]/).pop()?.trim() || host).slice(0, 80);
  const homeUrl = home.url;
  await progress(3);
  const scripts = getScripts(html);
  const external = scripts.filter((s) => {
    const h = hostOf(s.src, homeUrl);
    return h && h !== host;
  });
  const thirdParty = [...new Set(external.map((s) => hostOf(s.src, homeUrl)).filter((h) => !/shopify|shopifycdn|shopifysvc/i.test(h)))];
  const renderBlocking = scripts.filter((s) => s.inHead && !s.async && !s.defer && !s.module);
  const imgs = getImages(html);
  const bytes = new TextEncoder().encode(html).length;
  if (bytes > 4e5) add({ id: "perf.page_weight", category: "performance", title: "Homepage HTML is very large", severity: "medium", url: homeUrl, evidence: [`Homepage HTML is ${(bytes / 1024).toFixed(0)} KB${home.truncated ? " (truncated at our read limit)" : ""}.`], what: "The homepage document itself is unusually heavy before images and scripts are counted.", why: "Large documents take longer to download and parse, especially on mobile networks.", impact: "Slower first render can increase early drop-off on mobile.", fix: "Trim inline scripts and unused theme sections, and reduce the number of sections rendered on the homepage.", confidence: "verified" });
  else pass({ id: "perf.page_weight", category: "performance", title: "Homepage HTML size is reasonable", detail: `${(bytes / 1024).toFixed(0)} KB.` });
  if (external.length > 25) add({ id: "perf.scripts", category: "performance", title: "Many external scripts load on the homepage", severity: "medium", url: homeUrl, evidence: [`${external.length} external script tags found.`, `Third-party hosts include: ${thirdParty.slice(0, 8).join(", ") || "none outside Shopify"}.`], what: "A high number of external scripts compete for the browser during page load.", why: "Every extra script adds download, parse and execution time, and many come from installed apps.", impact: "Heavy script loads are a common cause of slow mobile interaction. Exact impact needs a Lighthouse run.", fix: "Audit installed apps, remove those that are unused, and defer non-essential scripts.", confidence: "likely" });
  if (renderBlocking.length > 5) add({ id: "perf.render_blocking", category: "performance", title: "Render-blocking scripts in the page head", severity: "medium", url: homeUrl, evidence: [`${renderBlocking.length} scripts in <head> have neither async nor defer.`, ...renderBlocking.slice(0, 3).map((s) => s.src.slice(0, 120))], what: "Scripts in the head without async/defer pause page rendering while they load.", why: "The browser cannot show content until these scripts finish.", impact: "Delays the first visible content for shoppers.", fix: "Add defer/async where safe or move scripts to the end of the body.", confidence: "verified" });
  const lazyCandidates = imgs.slice(3);
  const notLazy = lazyCandidates.filter((i) => i.loading !== "lazy");
  if (lazyCandidates.length >= 8 && wordsToPct(notLazy.length, lazyCandidates.length) > 50) add({ id: "perf.lazy", category: "performance", title: "Below-the-fold images are not lazy-loaded", severity: "low", url: homeUrl, evidence: [`${notLazy.length} of ${lazyCandidates.length} images after the first three have no loading="lazy".`], what: "Images far down the page load immediately instead of when needed.", why: "They compete with important content for bandwidth.", impact: "Slower initial load on mobile data.", fix: 'Set loading="lazy" on images below the first screen.', confidence: "verified" });
  const noDims = imgs.filter((i) => !i.hasDims);
  if (imgs.length >= 5 && wordsToPct(noDims.length, imgs.length) > 40) add({ id: "perf.img_dims", category: "performance", title: "Images missing width and height attributes", severity: "low", url: homeUrl, evidence: [`${noDims.length} of ${imgs.length} homepage images have no width/height.`], what: "Without dimensions the browser cannot reserve space for images.", why: "Content jumps as images load (layout shift).", impact: "Layout shift is a Core Web Vitals factor and frustrates shoppers.", fix: "Add width and height (or aspect-ratio) to images in the theme.", confidence: "verified" });
  if (home.ms > 2500) add({ id: "perf.ttfb", category: "performance", title: "Slow homepage response in our test", severity: "low", url: homeUrl, evidence: [`Homepage fetched in ${home.ms} ms from our audit server (single sample, includes redirects).`], what: "The first request was slow in this single measurement.", why: "Server and redirect time add to every page load.", impact: "Indicative only: one sample from one location.", fix: "Re-test with Lighthouse; check redirects and the CDN setup.", confidence: "indicative" });
  let perf = { lab: null, field: null, note: "Not run: no Google PageSpeed Insights API key is configured for this audit engine, so Lighthouse lab data and Chrome field data are unavailable. Performance is therefore not scored." };
  let perfScore = null;
  if (opts.pageSpeedKey) {
    const ps = await getPageSpeed(origin, opts.pageSpeedKey, deps.fetchImpl);
    if (ps) {
      perf = ps.perf;
      perfScore = ps.score;
      for (const f of ps.findings) add(f);
    } else perf.note = "PageSpeed Insights was requested but did not return a result (timeout or quota). Performance is not scored.";
  }
  await progress(4);
  if (new URL(homeUrl).protocol !== "https:") add({ id: "tech.https", category: "technical", area: "Trust & security", title: "Store is not served over HTTPS", severity: "critical", url: homeUrl, evidence: [`Final homepage URL: ${homeUrl}`], what: "The store loads over an insecure connection.", why: "Browsers warn shoppers and payment trust suffers.", impact: "Visitors are likely to leave and search engines favour secure pages.", fix: "Enable SSL for the domain in Shopify (Settings > Domains) and force HTTPS.", confidence: "verified" });
  else pass({ id: "tech.https", category: "technical", title: "HTTPS is enabled", detail: "The homepage is served over HTTPS." });
  if (httpHome.status && !(new URL(httpHome.url).protocol === "https:")) add({ id: "tech.http_redirect", category: "technical", title: "HTTP version does not redirect to HTTPS", severity: "medium", url: `http://${host}/`, evidence: [`http://${host}/ ended on ${httpHome.url} (HTTP ${httpHome.status}).`], what: "The insecure address is reachable without upgrading.", why: "Shoppers and crawlers can land on an unsecured version.", impact: "Splits trust and ranking signals.", fix: 'Turn on "Redirect all traffic to the primary domain" and SSL in Shopify.', confidence: "verified" });
  if (home.redirects.length > 2) add({ id: "tech.redirect_chain", category: "technical", title: "Homepage goes through a redirect chain", severity: "low", url: base + "/", evidence: [`${home.redirects.length} redirects before the homepage: ${home.redirects.join(" \u2192 ")}`], what: "More than two redirects are needed to reach the homepage.", why: "Each hop adds delay and can dilute link signals.", impact: "Slower first load.", fix: "Point the primary domain directly to the final address.", confidence: "verified" });
  if (!/<meta[^>]+name=["']viewport["']/i.test(html)) add({ id: "tech.viewport", category: "technical", title: "No mobile viewport tag on the homepage", severity: "high", url: homeUrl, evidence: ['No <meta name="viewport"> found in the homepage source.'], what: "The page does not declare a mobile viewport.", why: "Phones may render it as a shrunken desktop page.", impact: "Poor mobile experience hurts conversion and mobile search.", fix: "Add a viewport meta tag to theme.liquid or switch to a current responsive theme.", confidence: "verified" });
  else pass({ id: "tech.viewport", category: "technical", title: "Mobile viewport tag present", detail: "The homepage declares a responsive viewport." });
  if (/<meta[^>]+name=["']robots["'][^>]+content=["'][^"']*noindex/i.test(html)) add({ id: "tech.noindex", category: "technical", title: "Homepage is set to noindex", severity: "critical", url: homeUrl, evidence: ['A robots meta tag containing "noindex" was found on the homepage.'], what: "Search engines are told not to index the homepage.", why: "It cannot appear in search results.", impact: "Organic visibility can be lost entirely for this page.", fix: "Remove the noindex tag unless the store is intentionally hidden.", confidence: "verified" });
  if (!getCanonical(html)) add({ id: "tech.canonical", category: "technical", title: "No canonical tag on the homepage", severity: "medium", url: homeUrl, evidence: ['No <link rel="canonical"> found.'], what: "The homepage does not declare its preferred URL.", why: "Duplicate URL versions can split ranking signals.", impact: "Weaker consolidation of SEO signals.", fix: "Add {{ canonical_url }} to the theme head.", confidence: "verified" });
  if (!/<html[^>]+\blang=/i.test(html)) add({ id: "tech.lang", category: "technical", title: "No language attribute on <html>", severity: "low", url: homeUrl, evidence: ["The <html> tag has no lang attribute."], what: "The page language is not declared.", why: "It helps search engines and screen readers.", impact: "Minor accessibility and international SEO loss.", fix: 'Add lang="{{ request.locale.iso_code }}" to the theme.', confidence: "verified" });
  if (!robots?.ok) add({ id: "tech.robots", category: "technical", title: "robots.txt could not be retrieved", severity: "medium", url: base + "/robots.txt", evidence: [`HTTP ${robots?.status ?? 0} for /robots.txt.`], what: "The robots file did not load.", why: "Crawlers rely on it for crawl guidance.", impact: "Possible crawl issues.", fix: "Check the domain setup; Shopify normally serves this automatically.", confidence: "verified" });
  else if (!/sitemap:/i.test(robots.body)) add({ id: "tech.robots_sitemap", category: "technical", title: "robots.txt does not reference a sitemap", severity: "low", url: base + "/robots.txt", evidence: ['No "Sitemap:" line in robots.txt.'], what: "The sitemap is not advertised to crawlers.", why: "Helps discovery of all pages.", impact: "Slower discovery of new products.", fix: "Reference the sitemap URL in robots.txt.liquid.", confidence: "verified" });
  else pass({ id: "tech.robots", category: "technical", title: "robots.txt present and references a sitemap", detail: "Crawlers can find the sitemap." });
  if (!sitemap?.ok) add({ id: "tech.sitemap", category: "technical", title: "XML sitemap not found", severity: "high", url: base + "/sitemap.xml", evidence: [`HTTP ${sitemap?.status ?? 0} for /sitemap.xml.`], what: "The standard Shopify sitemap did not load.", why: "Search engines use it to find products and collections.", impact: "New and updated products may be indexed more slowly.", fix: "Confirm the domain is correctly connected and submit the sitemap in Google Search Console.", confidence: "verified" });
  else pass({ id: "tech.sitemap", category: "technical", title: "XML sitemap is available", detail: `${(sitemap.body.match(/<loc>/g) || []).length} sitemap entries listed at the top level.` });
  const homeLd = getJsonLdTypes(html);
  const prodLd = productPage?.ok ? getJsonLdTypes(productPage.body) : [];
  if (productPage?.ok && !prodLd.some((t) => /Product/i.test(t))) add({ id: "seo.product_schema", category: "seo", title: "Product page has no Product structured data", severity: "high", url: productPage.url, evidence: [`JSON-LD types found on the sampled product page: ${prodLd.join(", ") || "none"}.`], what: "The sampled product page does not expose Product schema.", why: "Structured data enables price, availability and review rich results.", impact: "Missed visibility in rich search results.", fix: "Use a theme that outputs Product JSON-LD or add it via theme code.", confidence: "verified" });
  else if (productPage?.ok) pass({ id: "seo.product_schema", category: "seo", title: "Product structured data present", detail: "The sampled product page exposes Product schema." });
  if (!homeLd.some((t) => /Organization|WebSite|Store/i.test(t))) add({ id: "seo.org_schema", category: "seo", title: "No Organization or WebSite structured data on the homepage", severity: "opportunity", url: homeUrl, evidence: [`JSON-LD types on the homepage: ${homeLd.join(", ") || "none"}.`], what: "The homepage gives machines little structured information about the business.", why: "Clear entity data helps search engines and AI assistants understand and cite the brand (GEO).", impact: "Potential knowledge-panel and AI-answer visibility. No ranking data was retrieved.", fix: "Add Organization and WebSite schema, with logo, social profiles and contact details.", confidence: "verified" });
  const title = getTitle(html);
  const mdesc = getMeta(html, "description");
  const h1s = getH1s(html);
  if (!title) add({ id: "seo.title", category: "seo", title: "Homepage has no title tag", severity: "high", url: homeUrl, evidence: ["No <title> found."], what: "The homepage title is missing.", why: "The title is the main on-page ranking and click signal.", impact: "Weak search snippets.", fix: "Set a descriptive title in Online Store > Preferences.", confidence: "verified" });
  else if (title.length < 20 || title.length > 65) add({ id: "seo.title_len", category: "seo", title: title.length < 20 ? "Homepage title is very short" : "Homepage title is too long for search results", severity: "low", url: homeUrl, evidence: [`Title: "${title}" (${title.length} characters).`], what: "The title length is outside the range that displays well.", why: "Short titles waste keyword space; long titles are truncated.", impact: "Less effective search snippet.", fix: "Aim for roughly 30\u201360 characters that include what you sell.", confidence: "verified" });
  else pass({ id: "seo.title", category: "seo", title: "Homepage title length is good", detail: `"${title}"` });
  if (!mdesc) add({ id: "seo.meta_desc", category: "seo", title: "Homepage has no meta description", severity: "high", url: homeUrl, evidence: ["No meta description tag found."], what: "The homepage meta description is missing.", why: "It shapes the text shown under your link in search results.", impact: "Search engines pick random text, which usually clicks worse.", fix: "Write a 120\u2013155 character description in Preferences.", confidence: "verified" });
  else if (mdesc.length < 70 || mdesc.length > 165) add({ id: "seo.meta_desc_len", category: "seo", title: "Homepage meta description length is off", severity: "low", url: homeUrl, evidence: [`"${mdesc.slice(0, 160)}" (${mdesc.length} characters).`], what: "The description is too short or will be truncated.", why: "Best results use about 120\u2013155 characters.", impact: "Minor click-through impact.", fix: "Rewrite to a clear benefit-led 120\u2013155 characters.", confidence: "verified" });
  else pass({ id: "seo.meta_desc", category: "seo", title: "Homepage meta description is set", detail: `${mdesc.length} characters.` });
  if (h1s.length === 0) add({ id: "seo.h1", category: "seo", title: "Homepage has no H1 heading", severity: "medium", url: homeUrl, evidence: ["No <h1> element found."], what: "The page has no main heading.", why: "The H1 tells shoppers and search engines what the page is about.", impact: "Weaker topical clarity.", fix: "Add one clear H1 to the first section.", confidence: "verified" });
  else if (h1s.length > 1) add({ id: "seo.h1_multi", category: "seo", title: "Homepage has several H1 headings", severity: "low", url: homeUrl, evidence: [`${h1s.length} H1 elements: ${h1s.slice(0, 3).map((h) => `"${h.slice(0, 60)}"`).join(", ")}`], what: "More than one H1 is present.", why: "A single H1 keeps the page hierarchy clear.", impact: "Minor SEO clarity loss.", fix: "Keep one H1 and use H2/H3 for other headings.", confidence: "verified" });
  else pass({ id: "seo.h1", category: "seo", title: "One H1 on the homepage", detail: `"${h1s[0].slice(0, 80)}"` });
  if (/welcome to our store|your store name|lorem ipsum/i.test(strip(html))) add({ id: "seo.default_text", category: "seo", title: "Default theme placeholder text is visible", severity: "high", url: homeUrl, evidence: ['Placeholder phrase such as "Welcome to our store" or "Lorem ipsum" found in homepage text.'], what: "Theme starter copy is still live.", why: "It signals an unfinished store and wastes prime keyword space.", impact: "Lower trust and weaker search relevance.", fix: "Replace placeholder text with clear brand and product messaging.", confidence: "verified" });
  if (!getMeta(html, "og:image") || !getMeta(html, "og:title")) add({ id: "seo.og", category: "seo", title: "Social sharing tags are incomplete", severity: "low", url: homeUrl, evidence: [`og:title: ${getMeta(html, "og:title") ? "present" : "missing"}, og:image: ${getMeta(html, "og:image") ? "present" : "missing"}.`], what: "Shared links will have a weak preview.", why: "Previews affect clicks from social and messaging apps.", impact: "Fewer clicks on shared links.", fix: "Set a social sharing image in Preferences.", confidence: "verified" });
  const noAlt = imgs.filter((i) => i.alt === null || i.alt.trim() === "");
  const contentImgs = imgs.filter((i) => !/pixel|spacer|icon/i.test(i.src));
  if (contentImgs.length >= 6 && wordsToPct(noAlt.length, imgs.length) > 30) add({ id: "seo.alt_home", category: "seo", title: "Many homepage images have no alt text", severity: "medium", url: homeUrl, evidence: [`${noAlt.length} of ${imgs.length} homepage images have empty or missing alt text.`], what: "Images lack descriptive alt text.", why: "Alt text feeds image search and accessibility.", impact: "Lost image-search traffic and weaker accessibility.", fix: "Describe each meaningful image in a few words.", confidence: "verified" });
  const total = products.length;
  const descOf = (p) => strip(String(p.body_html || ""));
  const thin = products.filter((p) => descOf(p).length < 100);
  if (total >= 3 && wordsToPct(thin.length, total) > 25) add({ id: "seo.product_desc", category: "seo", title: "Many products have thin or missing descriptions", severity: wordsToPct(thin.length, total) > 60 ? "high" : "medium", url: base + "/products.json", evidence: [`${thin.length} of ${total} sampled products have fewer than 100 characters of description.`, ...thin.slice(0, 3).map((p) => `Example: ${base}/products/${p.handle}`)], what: "Product pages carry little descriptive copy.", why: "Descriptions answer buyer questions and give search engines content to rank.", impact: "Lower product discoverability and weaker purchase confidence.", fix: "Write benefit-led descriptions with materials, size, use and care details.", confidence: "verified" });
  else if (total >= 3) pass({ id: "seo.product_desc", category: "seo", title: "Most products have real descriptions", detail: `${total - thin.length} of ${total} sampled products have 100+ characters.` });
  const allImgs = products.flatMap((p) => p.images || []);
  const imgNoAlt = allImgs.filter((i) => !i.alt || !String(i.alt).trim());
  if (allImgs.length >= 5 && wordsToPct(imgNoAlt.length, allImgs.length) > 40) add({ id: "seo.product_alt", category: "seo", title: "Most product images have no alt text", severity: "medium", url: base + "/products.json", evidence: [`${imgNoAlt.length} of ${allImgs.length} product images have no alt text.`], what: "Product photos are not described for search or accessibility.", why: "Alt text supports image search and screen readers.", impact: "Missed Google Images traffic for product searches.", fix: "Add alt text to product images (describe the product and view).", confidence: "verified" });
  const shortTitles = products.filter((p) => String(p.title || "").length < 12 || /^[A-Z0-9 ]{8,}$/.test(String(p.title || "")));
  if (total >= 5 && wordsToPct(shortTitles.length, total) > 30) add({ id: "seo.product_titles", category: "seo", title: "Product titles may be too short or all caps", severity: "low", url: base + "/products.json", evidence: [`${shortTitles.length} of ${total} products: ${shortTitles.slice(0, 3).map((p) => `"${p.title}"`).join(", ")}`], what: "Titles carry little searchable detail.", why: "Buyers search by product type, material and use.", impact: "Lower relevance for product searches.", fix: "Include the product type and a key attribute in each title.", confidence: "likely" });
  const emptyColl = collections.filter((c) => !strip(String(c.body_html || "")));
  if (collections.length >= 2 && wordsToPct(emptyColl.length, collections.length) > 50) add({ id: "seo.collection_desc", category: "seo", title: "Collection pages have no description text", severity: "medium", url: base + "/collections.json", evidence: [`${emptyColl.length} of ${collections.length} collections have no description: ${emptyColl.slice(0, 3).map((c) => c.title).join(", ")}.`], what: "Collections are bare product grids.", why: "Collections target broad searches and need copy to rank.", impact: "Underdeveloped category search visibility. No ranking data retrieved.", fix: "Add a short intro and buying guide to each key collection.", confidence: "verified" });
  if (productPage?.ok) {
    const pt = getTitle(productPage.body);
    const pd = getMeta(productPage.body, "description");
    if (!pd) add({ id: "seo.product_meta", category: "seo", title: "Sampled product page has no meta description", severity: "medium", url: productPage.url, evidence: [`No meta description on ${productPage.url}.`], what: "Product meta descriptions are missing or not generated.", why: "They shape search snippets.", impact: "Lower click-through from search.", fix: "Set search engine listing text for products.", confidence: "verified" });
    if (pt && title && pt === title) add({ id: "seo.product_title_dup", category: "seo", title: "Product page title matches the homepage title", severity: "medium", url: productPage.url, evidence: [`Both titled "${pt}".`], what: "Duplicate titles across different pages.", why: "Each page should have a unique title.", impact: "Search engines struggle to tell pages apart.", fix: "Give each product its own search listing title.", confidence: "verified" });
  }
  if (!by("Sample product page") && total === 0) {
  }
  await progress(5);
  const contact = by("Contact page");
  const hasMailTel = /href=["'](mailto:|tel:)/i.test(html);
  if (!contact?.ok && !hasMailTel) add({ id: "ux.contact", category: "ux", area: "Trust & security", title: "No visible way to contact the store", severity: "high", url: base + "/pages/contact", evidence: [`/pages/contact returned HTTP ${contact?.status ?? 0} and no mailto: or tel: link was found on the homepage.`], what: "We could not find a contact page or contact details.", why: "Shoppers want to know someone is reachable before paying.", impact: "Reduced purchase confidence.", fix: "Add a contact page with email, a form and response times.", confidence: "likely" });
  else pass({ id: "ux.contact", category: "ux", title: "A way to contact the store exists", detail: contact?.ok ? "Contact page loads." : "Email or phone link found on the homepage." });
  const about = by("About page")?.ok ? by("About page") : by("About page (alt)");
  if (!about?.ok && !/href=["'][^"']*about/i.test(html)) add({ id: "ux.about", category: "ux", area: "Trust & security", title: "No About page found", severity: "medium", url: base + "/pages/about-us", evidence: ['/pages/about-us and /pages/about both failed, and no "about" link was found on the homepage.'], what: "There is no obvious brand story page.", why: "Shoppers check who is behind a store before buying.", impact: "Weaker brand credibility.", fix: "Add an About page with your story, location and proof points.", confidence: "likely" });
  else pass({ id: "ux.about", category: "ux", title: "About page found", detail: "Brand story page is available." });
  const policy = (label, id, sev, cat, noun, why) => {
    const r = by(label);
    if (!r?.ok) add({ id, category: cat, area: "Trust & security", title: `${noun} not found`, severity: sev, url: base + (wanted.find((w) => w[0] === label)?.[1] || ""), evidence: [`${base}${wanted.find((w) => w[0] === label)?.[1]} returned HTTP ${r?.status ?? 0}.`], what: `The ${noun.toLowerCase()} page is missing or empty.`, why, impact: "Lower trust at the moment of purchase. This is not a legal assessment; consider professional review.", fix: `Add a clear ${noun.toLowerCase()} in Settings > Policies.`, confidence: "verified" });
    else if (strip(r.body).length < 600) add({ id: id + "_thin", category: cat, area: "Trust & security", title: `${noun} looks very thin`, severity: "low", url: r.url, evidence: [`About ${strip(r.body).length} characters of text.`], what: "The policy contains little detail.", why: "Shoppers look for time limits, costs and how to start a return or track delivery.", impact: "Unanswered questions reduce confidence.", fix: "Spell out timeframes, costs and the process step by step.", confidence: "likely" });
    else pass({ id, category: cat, title: `${noun} is published`, detail: r.url });
  };
  policy("Refund policy", "trust.refund", "high", "cro", "Refund policy", "Return terms are among the top things shoppers check before ordering.");
  policy("Shipping policy", "trust.shipping", "high", "cro", "Shipping policy", "Unclear delivery costs and times are a leading reason for abandoned carts.");
  policy("Privacy policy", "trust.privacy", "medium", "ux", "Privacy policy", "Privacy information is expected and often required.");
  policy("Terms of service", "trust.terms", "low", "ux", "Terms of service", "Clear terms set expectations for orders and disputes.");
  const hasSearch = /action=["'][^"']*\/search|name=["']q["']|type=["']search["']/i.test(html);
  if (!hasSearch && total > 30) add({ id: "ux.search", category: "ux", title: "No site search on the homepage", severity: "medium", url: homeUrl, evidence: [`The catalogue has ${total}+ products but no search form or search input was found in the homepage markup.`], what: "Shoppers cannot search a sizeable catalogue.", why: "Searchers convert at a higher rate than browsers.", impact: "Harder product discovery on a larger catalogue.", fix: "Add a search bar to the header.", confidence: "likely" });
  if (collections.length === 0 && total > 20) add({ id: "ux.collections", category: "ux", title: "No collections found for a larger catalogue", severity: "medium", url: base + "/collections.json", evidence: [`${total} products but /collections.json listed none.`], what: "Products are not organised into categories.", why: "Collections guide browsing and carry category SEO.", impact: "Harder discovery and weaker category rankings.", fix: "Create collections by product type, use case and audience.", confidence: "likely" });
  else if (collections.length) pass({ id: "ux.collections", category: "ux", title: "Products are organised into collections", detail: `${collections.length} public collections found.` });
  if (!/<link[^>]+rel=["'](shortcut )?icon["']/i.test(html)) add({ id: "ux.favicon", category: "ux", title: "No favicon declared", severity: "low", url: homeUrl, evidence: ["No icon link found in the page head."], what: "The browser tab shows a blank icon.", why: "Favicons aid recognition and look professional.", impact: "Minor brand polish.", fix: "Upload a favicon in theme settings.", confidence: "verified" });
  const social = /(instagram|facebook|tiktok|pinterest|youtube|twitter|x)\.com\/[^"'\s<]+/i.test(html);
  if (!social) add({ id: "ux.social", category: "ux", title: "No social profile links on the homepage", severity: "low", url: homeUrl, evidence: ["No links to major social platforms found in the homepage source."], what: "Shoppers cannot verify your social presence.", why: "Active social profiles are a trust signal.", impact: "Slightly lower credibility.", fix: "Link your social profiles in the footer.", confidence: "verified" });
  const imgsPerProduct = products.filter((p) => (p.images || []).length <= 1);
  if (total >= 5 && wordsToPct(imgsPerProduct.length, total) > 40) add({ id: "cro.product_images", category: "cro", title: "Many products have only one image", severity: "medium", url: base + "/products.json", evidence: [`${imgsPerProduct.length} of ${total} products have 0\u20131 images.`, ...imgsPerProduct.slice(0, 2).map((p) => `${base}/products/${p.handle}`)], what: "Single photos do not show scale, detail or use.", why: "Shoppers cannot touch the product; images do that job.", impact: "Lower purchase confidence. Count of images only: quality was not judged.", fix: "Add 4\u20136 images per product: angles, detail, in-use and scale.", confidence: "verified" });
  await progress(6);
  const pbody = productPage?.ok ? productPage.body : "";
  if (productPage?.ok) {
    const hasAdd = /name=["']add["']|add[-_ ]to[-_ ]cart|product-form|data-add-to-cart|sold out|unavailable/i.test(pbody);
    if (!hasAdd) add({ id: "cro.add_to_cart", category: "cro", title: "No add-to-cart button detected on the sampled product page", severity: "high", url: productPage.url, evidence: [`No add-to-cart form or button markup found on ${productPage.url}.`], what: "The sampled product page may not offer a clear way to buy.", why: "The add-to-cart button is the conversion point.", impact: "Possible lost sales if confirmed. Verify manually, as some themes load the button with scripts.", fix: "Check the product template and any page-builder or app overrides.", confidence: "likely" });
    else pass({ id: "cro.add_to_cart", category: "cro", title: "Add-to-cart present on product page", detail: productPage.url });
    const hasReviews = /judge\.me|loox|stamped\.io|yotpo|okendo|reviews\.io|trustpilot|ali-?reviews|shopify-product-reviews|spr-badge|rating/i.test(pbody + html);
    if (!hasReviews) add({ id: "cro.reviews", category: "cro", title: "No customer reviews detected", severity: "medium", url: productPage.url, evidence: ["No review app or ratings markup found on the sampled product page or homepage."], what: "Social proof from customers is not visible.", why: "Reviews are one of the strongest purchase triggers for new visitors.", impact: "Higher hesitation for first-time buyers. Reviews loaded late by scripts may not be detected.", fix: "Install a reviews app and request reviews after delivery.", confidence: "likely" });
    else pass({ id: "cro.reviews", category: "cro", title: "Reviews or ratings signal detected", detail: "Review markup or app found (not verified as complete)." });
    if (!/shipping|delivery|dispatch/i.test(strip(pbody)) && !by("Shipping policy")?.ok) add({ id: "cro.shipping_visible", category: "cro", title: "Shipping information not visible near the product", severity: "medium", url: productPage.url, evidence: ["No mention of shipping or delivery found in the sampled product page text."], what: "Shoppers cannot see delivery costs or times before the cart.", why: "Surprise costs at checkout are a top abandonment cause.", impact: "Potential cart abandonment.", fix: "Add a short delivery and returns line under the buy button.", confidence: "likely" });
    if (!/recommend|you may also like|related|complete the look|frequently bought/i.test(pbody)) add({ id: "cro.upsell", category: "cro", title: "No related or recommended products on the product page", severity: "opportunity", url: productPage.url, evidence: ["No recommendations section markup found on the sampled product page."], what: "There is no visible cross-sell on product pages.", why: "Recommendations raise order value and keep shoppers browsing.", impact: "Missed average-order-value opportunity. Size not quantified.", fix: "Enable related products or bundle offers on product pages.", confidence: "likely" });
    if (!/shop pay|visa|mastercard|paypal|apple pay|secure checkout|payment/i.test(pbody + html)) add({ id: "cro.payment_trust", category: "cro", title: "No payment or secure-checkout cues visible", severity: "low", url: productPage.url, evidence: ["No payment icons or secure-checkout wording found on the product page or homepage."], what: "Payment options are not shown before checkout.", why: "Familiar payment icons reassure shoppers.", impact: "Slightly lower checkout confidence.", fix: "Show accepted payment icons in the footer or under the buy button.", confidence: "indicative" });
  }
  const variants = products.flatMap((p) => p.variants || []);
  const unavailable = variants.filter((v) => v.available === false);
  if (variants.length >= 10 && wordsToPct(unavailable.length, variants.length) > 30) add({ id: "cro.out_of_stock", category: "cro", title: "A large share of variants are unavailable", severity: "medium", url: base + "/products.json", evidence: [`${unavailable.length} of ${variants.length} variants are marked unavailable (point-in-time snapshot).`], what: "Many items cannot be bought right now.", why: "Sold-out pages lose traffic that has no alternative to buy.", impact: "Lost sales and wasted ad clicks while stock is out.", fix: "Add back-in-stock alerts and hide or redirect long-term unavailable items.", confidence: "verified" });
  if (total > 0 && !variants.some((v) => v.compare_at_price && Number(v.compare_at_price) > Number(v.price))) add({ id: "cro.compare_at", category: "cro", title: "No sale or compare-at pricing in use", severity: "opportunity", url: base + "/products.json", evidence: [`None of the ${variants.length} sampled variants has a compare-at price.`], what: "Price anchoring is not used.", why: "Showing a reference price helps shoppers judge value.", impact: "Possible conversion upside on promotions. Not quantified.", fix: "Use compare-at pricing for genuine promotions.", confidence: "verified" });
  if (total > 0 && total < 6) add({ id: "cro.thin_catalog", category: "cro", title: "Very small catalogue", severity: "opportunity", url: base + "/products.json", evidence: [`${total} public products found.`], what: "Few products limit browsing and basket size.", why: "Small ranges need strong bundles and a clear hero product.", impact: "Limited cross-sell room.", fix: "Add bundles, variants and complementary products.", confidence: "verified" });
  if (total >= 250) {
  }
  await progress(7);
  const all = html + (pbody || "");
  const has = (re) => re.test(all);
  const emailForm = /<input[^>]+type=["']email["']|name=["']contact\[email\]["']|customer_form|newsletter/i.test(html);
  if (!emailForm) add({ id: "mkt.email_capture", category: "marketing", title: "No email signup form found on the homepage", severity: "high", url: homeUrl, evidence: ["No email input or newsletter form found in the homepage markup (pop-ups loaded by apps may not be visible to this check)."], what: "There is no visible way to join your list.", why: "Email is the cheapest channel for repeat sales.", impact: "Visitors leave without being captured. Pop-ups added by apps could exist but were not detected.", fix: "Add a signup form in the footer and an incentive-led pop-up.", confidence: "likely" });
  else pass({ id: "mkt.email_capture", category: "marketing", title: "Email signup form present", detail: "A signup form or email input was found on the homepage." });
  const platforms = [["Klaviyo", /klaviyo/i], ["Mailchimp", /mailchimp|chimpstatic/i], ["Omnisend", /omnisend/i], ["Shopify Email", /shopify-email|shopifyemail/i], ["Brevo/Sendinblue", /sendinblue|brevo/i], ["Privy", /privy\.com|privy-?widget/i], ["Attentive/Postscript (SMS)", /attn\.tv|attentive|postscript/i]];
  const detected = platforms.filter(([, re]) => has(re)).map(([n]) => n);
  if (!detected.length) add({ id: "mkt.email_platform", category: "marketing", title: "No email marketing platform detected", severity: "medium", url: homeUrl, evidence: ["No Klaviyo, Mailchimp, Omnisend, Brevo or similar scripts found in the page source."], what: "We could not detect an email or SMS marketing tool.", why: "Welcome, abandoned-cart and post-purchase flows run on one of these.", impact: "Repeat-purchase automation may be missing. Detection is by public scripts only; an installed tool is not proof its flows work.", fix: "Set up Klaviyo (or similar) with welcome, abandoned cart, browse abandonment and post-purchase flows.", confidence: "indicative" });
  else pass({ id: "mkt.email_platform", category: "marketing", title: `Marketing tool signal detected: ${detected.join(", ")}`, detail: "Detected from public scripts. Whether campaigns and automations work was not tested." });
  const shopifyAnalytics = /web-pixels-manager|trekkie|shopify\.analytics|monorail/i.test(all);
  const meta = /fbevents\.js|fbq\(|connect\.facebook\.net/i.test(all);
  const ga = /gtag\/js|googletagmanager\.com|google-analytics\.com|ga\('create'/i.test(all);
  if (!meta && !ga) add({ id: "mkt.tracking", category: "marketing", title: "No Meta Pixel or Google tag found in the page source", severity: "opportunity", url: homeUrl, evidence: [`Meta pixel script: ${meta ? "found" : "not found"}; Google tag/GTM: ${ga ? "found" : "not found"}; Shopify analytics signals: ${shopifyAnalytics ? "found" : "not found"}.`], what: "Common tracking scripts were not visible in the HTML.", why: "Tracking powers ads optimisation and analytics.", impact: "Indicative only: Shopify can load pixels through sandboxed web pixels that this check cannot see, so tracking may exist.", fix: "Confirm Meta and Google tracking in Shopify Customer Events and Google Tag Assistant.", confidence: "indicative" });
  else pass({ id: "mkt.tracking", category: "marketing", title: "Tracking signals detected", detail: `${meta ? "Meta Pixel " : ""}${ga ? "Google tag/GTM " : ""}detected. Correct configuration was not verified.` });
  if (!has(/smile\.io|yotpo|loyaltylion|swell|referralcandy|growave|rise\.ai|stamped|loyalty/i)) add({ id: "mkt.loyalty", category: "marketing", title: "No loyalty or referral programme detected", severity: "opportunity", url: homeUrl, evidence: ["No loyalty or referral app signals found in the page source."], what: "Nothing visible encourages repeat orders or referrals.", why: "Repeat customers cost less to win than new ones.", impact: "Possible repeat-purchase upside; not quantified.", fix: "Add a simple points or referral offer after first purchase.", confidence: "indicative" });
  if (!/href=["'][^"']*\/blogs\//i.test(html)) add({ id: "mkt.content", category: "marketing", title: "No blog or content hub linked from the homepage", severity: "opportunity", url: homeUrl, evidence: ["No link to /blogs/ found in the homepage source."], what: "There is no visible content marketing channel.", why: "Guides and how-tos capture buyers earlier in the search journey.", impact: "Possible organic traffic opportunity. No keyword data retrieved.", fix: "Publish buying guides and answers to common product questions.", confidence: "likely" });
  await progress(8);
  const has2 = (id) => findings.some((f) => f.id === id);
  const conn = [];
  if ((has2("seo.product_desc") || has2("seo.product_titles")) && (has2("seo.meta_desc") || has2("seo.product_meta") || has2("seo.product_schema"))) conn.push({ title: "Thin product content plus weak search markup", text: "Short product descriptions and missing meta data or structured data give search engines little to work with, so products are harder to find and shoppers who do arrive have fewer answers.", findingIds: ["seo.product_desc", "seo.product_titles", "seo.meta_desc", "seo.product_meta", "seo.product_schema"].filter(has2) });
  if (findings.some((f) => f.category === "performance") && (has2("cro.product_images") || has2("cro.add_to_cart"))) conn.push({ title: "Heavy pages and a harder product page", text: "Performance signals suggest extra weight on the page, and the product page also shows friction. Together this can make the path to purchase slower and less clear on mobile.", findingIds: findings.filter((f) => f.category === "performance" || f.id === "cro.product_images" || f.id === "cro.add_to_cart").map((f) => f.id) });
  if ((has2("cro.reviews") || has2("trust.refund") || has2("ux.contact")) && (has2("trust.shipping") || has2("cro.shipping_visible"))) conn.push({ title: "Missing proof plus unclear delivery terms", text: "No visible reviews or contact route, combined with unclear shipping or return terms, leaves first-time buyers with unanswered risk questions at the moment they decide.", findingIds: ["cro.reviews", "trust.refund", "ux.contact", "trust.shipping", "cro.shipping_visible"].filter(has2) });
  if (has2("mkt.email_capture") || has2("mkt.email_platform")) {
    if (has2("mkt.email_capture") && has2("mkt.email_platform")) conn.push({ title: "No list-building and no detected email tool", text: "With no signup form and no detected email platform, visitors who are not ready to buy have no way to stay connected, which limits repeat business.", findingIds: ["mkt.email_capture", "mkt.email_platform"] });
  }
  if (has2("seo.default_text") || has2("seo.title") || has2("seo.h1")) conn.push({ title: "Homepage messaging is unclear to shoppers and search engines", text: "Placeholder text or missing title/H1 weakens both first impressions and keyword relevance on your most important page.", findingIds: ["seo.default_text", "seo.title", "seo.h1"].filter(has2) });
  await progress(9);
  const cats = Object.keys(WEIGHTS).map((key) => {
    const fs = findings.filter((f) => f.category === key);
    const checksRun = fs.length + passes.filter((p) => p.category === key).length;
    let scored = checksRun >= 3;
    let score = null;
    let note = `${checksRun} checks run.`;
    if (key === "performance") {
      if (perfScore !== null) {
        score = Math.round(perfScore);
        scored = true;
        note = "Mobile Lighthouse performance score (lab data) from Google PageSpeed Insights.";
      } else {
        scored = false;
        note = "Not scored: needs Lighthouse / PageSpeed data. Page-level signals are listed as findings but do not affect the score.";
      }
    } else if (scored) {
      score = Math.max(0, Math.round(100 - fs.reduce((s, f) => s + PENALTY[f.severity], 0)));
    } else note = "Not enough accessible information to score this category.";
    return { key, label: CATEGORY_LABEL[key], weight: WEIGHTS[key], scored, score, findings: fs.length, note };
  });
  const scoredCats = cats.filter((c) => c.scored && c.score !== null);
  const wsum = scoredCats.reduce((s, c) => s + c.weight, 0);
  const overall = Math.round(scoredCats.reduce((s, c) => s + c.score * c.weight, 0) / (wsum || 1));
  const order = { critical: 0, high: 1, medium: 2, low: 3, opportunity: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const counts = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, opportunity: 0 };
  findings.forEach((f) => counts[f.severity]++);
  const phase = (f) => f.severity === "critical" ? 0 : f.category === "technical" || f.category === "seo" || f.category === "performance" ? 1 : f.category === "ux" ? 2 : f.category === "cro" ? 3 : 4;
  const phaseNames = ["Phase 1: Critical corrections", "Phase 2: Technical and SEO improvements", "Phase 3: User experience and design improvements", "Phase 4: Conversion optimisation", "Phase 5: Marketing and customer retention"];
  const roadmap = phaseNames.map((p, i) => ({ phase: p, items: findings.filter((f) => phase(f) === i && f.severity !== "opportunity").map((f) => ({ title: f.fix, why: f.title, priority: f.severity, findingId: f.id })) }));
  const opps = findings.filter((f) => f.severity === "opportunity").map((f) => ({ title: f.title, text: `${f.why} ${f.fix}` }));
  const weakest = [...scoredCats].sort((a, b) => a.score - b.score).slice(0, 2).map((c) => c.label.toLowerCase());
  const summary = `We reviewed ${host} using public information from ${fetched.filter((f) => f.res.ok).length + 1} accessible pages plus the public product catalogue. The store scores ${overall}/100 across ${scoredCats.length} scored categories, with ${counts.critical} critical and ${counts.high} high-priority issues. ${weakest.length ? `The main areas to look at first are ${weakest.join(" and ")}.` : ""} ${passes.length} checks passed. This is a public-data audit: it does not include your sales, traffic or conversion data.`;
  const pages = [{ path: "/", status: home.status, ms: home.ms }, { path: "/products.json", status: productsRes.status, ms: productsRes.ms }, { path: "/collections.json", status: collRes.status, ms: collRes.ms }, ...fetched.map((f) => ({ path: f.path, status: f.res.status, ms: f.res.ms }))];
  const failed = pages.filter((p) => !(p.status >= 200 && p.status < 300));
  const nicheGuess = collections.slice(0, 4).map((c) => c.title).filter(Boolean).join(", ") || [...new Set(products.map((p) => p.product_type).filter(Boolean))].slice(0, 4).join(", ") || "Not determined";
  const report = {
    version: 1,
    store: { name: storeName, domain: host, url: origin, niche: nicheGuess, platform: "shopify" },
    auditedAt: now.toISOString(),
    overall: { score: overall, scoredCategories: scoredCats.map((c) => c.key), note: `Weighted across scored categories only (${scoredCats.map((c) => `${c.label} ${c.weight}%`).join(", ")}). Unscored categories are not counted against the store; weights are re-normalised.` },
    categories: cats,
    counts,
    findings,
    passes,
    connections: conn,
    roadmap,
    opportunities: opps,
    summary,
    performance: perf,
    trafficIntelligence: { status: "unavailable", note: "Traffic, sales, revenue and conversion figures cannot be read from a public store URL and no third-party traffic provider is connected to this audit. We do not estimate or invent them. A connected-Shopify audit (read-only OAuth) is planned for a later phase." },
    coverage: {
      pagesRequested: pages.length,
      pagesAnalysed: pages.length - failed.length,
      pagesFailed: failed.map((p) => ({ path: p.path, reason: p.status === 0 ? "No response" : `HTTP ${p.status}` })),
      pages,
      catalogSampled: { products: total, collections: collections.length, note: total >= 250 ? "The first 250 products from the public catalogue were analysed; larger catalogues are sampled." : "The full public catalogue was analysed." },
      tools: ["Server-side page fetch (public HTML)", "Shopify public catalogue endpoints (/products.json, /collections.json)", "robots.txt and sitemap.xml checks", "Rule-based scoring (documented weights)"].concat(opts.pageSpeedKey ? ["Google PageSpeed Insights API"] : []),
      verified: ["HTTPS and redirects", "Homepage and product page meta data, headings and structured data", "Presence of policy, contact and about pages", "Catalogue content counts (descriptions, images, alt text, availability)", "Detected scripts and apps (presence only)"],
      estimated: [],
      unavailable: ["Traffic, orders, revenue, conversion rate and average order value", "Search rankings and keyword data", "Checkout testing and abandoned-cart automation behaviour", "Real-user Core Web Vitals" + (perfScore !== null ? " (see performance section)" : " and Lighthouse lab data"), "Pages behind login or scripts that render content after load"],
      limitations: ["This is not a full crawl: it samples key pages, one product and one collection page, and the public catalogue.", "Detection of apps and pixels uses public page source only; detected does not mean correctly configured.", "Shopify web pixels and some pop-ups load in ways a page fetch cannot see.", "Policy findings are observations, not legal advice.", "Findings are point-in-time from one server location."]
    }
    // AI interpretation is added by a later phase; Phase 1 uses deterministic, evidence-based text only.
  };
  return { status: "completed", report };
}
async function getPageSpeed(url, key, fetchImpl) {
  try {
    const api = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=mobile&category=performance&key=${encodeURIComponent(key)}`;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 45e3);
    const r = await fetchImpl(api, { signal: ctrl.signal });
    clearTimeout(t);
    if (!r.ok) return null;
    const j = await r.json();
    const lh = j.lighthouseResult;
    if (!lh) return null;
    const a = lh.audits || {};
    const score = Math.round((lh.categories?.performance?.score ?? 0) * 100);
    const lab = { score, lcpMs: a["largest-contentful-paint"]?.numericValue, cls: a["cumulative-layout-shift"]?.numericValue, tbtMs: a["total-blocking-time"]?.numericValue, fcpMs: a["first-contentful-paint"]?.numericValue, speedIndexMs: a["speed-index"]?.numericValue, strategy: "mobile", source: "Lighthouse lab test via PageSpeed Insights" };
    const fe = j.loadingExperience?.metrics;
    const field = fe ? { lcpMs: fe.LARGEST_CONTENTFUL_PAINT_MS?.percentile, inpMs: fe.INTERACTION_TO_NEXT_PAINT?.percentile, cls: fe.CUMULATIVE_LAYOUT_SHIFT_SCORE?.percentile != null ? fe.CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile / 100 : null, category: j.loadingExperience?.overall_category, source: "Chrome UX Report (real users, 28 days)" } : null;
    const findings = [];
    const u = url;
    if (lab.lcpMs > 4e3) findings.push({ id: "perf.lcp", category: "performance", title: "Slow Largest Contentful Paint (lab)", severity: lab.lcpMs > 6e3 ? "high" : "medium", url: u, evidence: [`Lab LCP ${(lab.lcpMs / 1e3).toFixed(1)}s on a simulated mobile device (good is under 2.5s).`], what: "The main content takes long to appear on mobile.", why: "LCP measures when shoppers see the main content.", impact: "Slow loads raise early abandonment. Lab data is a simulation, not real-user data.", fix: "Compress and properly size the hero image and defer heavy scripts.", confidence: "verified" });
    if (lab.cls > 0.1) findings.push({ id: "perf.cls", category: "performance", title: "Layout shift detected (lab)", severity: lab.cls > 0.25 ? "medium" : "low", url: u, evidence: [`Lab CLS ${lab.cls.toFixed(2)} (good is under 0.1).`], what: "Page elements move while loading.", why: "Shifting content causes mis-taps and frustration.", impact: "Hurts the mobile experience and a Core Web Vitals signal.", fix: "Reserve space for images, banners and app widgets.", confidence: "verified" });
    if (lab.tbtMs > 600) findings.push({ id: "perf.tbt", category: "performance", title: "High blocking time from JavaScript (lab)", severity: "medium", url: u, evidence: [`Total Blocking Time ${Math.round(lab.tbtMs)} ms (good is under 200 ms).`], what: "JavaScript keeps the page unresponsive during load.", why: "It is closely related to Interaction to Next Paint.", impact: "Taps feel laggy on mid-range phones.", fix: "Remove unused apps and defer third-party scripts.", confidence: "verified" });
    return { perf: { lab, field, note: "Lab figures come from a simulated mobile Lighthouse run; field figures (if shown) come from real Chrome users and are only available for sites with enough traffic." }, score, findings };
  } catch {
    return null;
  }
}

// start-audit/index.ts
var GOALS = ["Increase sales", "Improve conversion rate", "Improve SEO and Google visibility", "Improve website speed", "Improve store design and user experience", "Improve marketing performance", "Launch a new Shopify store", "Identify general growth opportunities"];
var EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;
var PER_IP_PER_HOUR = 3;
var GLOBAL_PER_HOUR = 150;
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(req) });
  if (req.method !== "POST") return json(req, { error: "Method not allowed" }, 405);
  let body;
  try {
    body = await req.json();
  } catch {
    return json(req, { error: "Invalid request." }, 400);
  }
  if (body.website) return json(req, { id: crypto.randomUUID(), token: "x" });
  const name = String(body.name || "").trim().replace(/\s+/g, " ");
  const email = String(body.email || "").trim().toLowerCase();
  const goal = String(body.goal || "");
  if (name.length < 2 || name.length > 80) return json(req, { error: "Please enter your full name." }, 400);
  if (!EMAIL_RE.test(email) || email.length > 120) return json(req, { error: "Please enter a valid business email." }, 400);
  if (!GOALS.includes(goal)) return json(req, { error: "Please choose a primary business goal." }, 400);
  if (body.consent !== true) return json(req, { error: "Please tick the consent box so we can run your audit." }, 400);
  const target = parseTarget(String(body.storeUrl || ""));
  if (!target.ok) return json(req, { error: target.error }, 400);
  const url = target.url;
  const supabase = db();
  const ipHash = await sha256((Deno.env.get("IP_SALT") || "cmd-audit") + clientIp(req));
  const since = new Date(Date.now() - 36e5).toISOString();
  const { count: ipCount } = await supabase.from("audits").select("id", { count: "exact", head: true }).eq("ip_hash", ipHash).gte("created_at", since);
  if ((ipCount ?? 0) >= PER_IP_PER_HOUR) return json(req, { error: "You have run several audits in the last hour. Please try again a little later." }, 429);
  const { count: allCount } = await supabase.from("audits").select("id", { count: "exact", head: true }).gte("created_at", since);
  if ((allCount ?? 0) >= GLOBAL_PER_HOUR) return json(req, { error: "We are running a lot of audits right now. Please try again in a few minutes." }, 429);
  const day = new Date(Date.now() - 864e5).toISOString();
  const { data: dup } = await supabase.from("audits").select("id, token, status").eq("domain", url.hostname).eq("email", email).gte("created_at", day).order("created_at", { ascending: false }).limit(1);
  if (dup && dup.length && ["queued", "running", "completed"].includes(dup[0].status)) return json(req, { id: dup[0].id, token: dup[0].token, reused: true });
  const { data: row, error } = await supabase.from("audits").insert({ name, email, store_url: url.toString(), domain: url.hostname, goal, consent: true, ip_hash: ipHash, status: "queued", lead_status: "Audit In Progress" }).select("id, token").single();
  if (error || !row) return json(req, { error: "We could not start your audit. Please try again." }, 500);
  const job = (async () => {
    try {
      await supabase.from("audits").update({ status: "running", stage: 0 }).eq("id", row.id);
      const out = await runAudit(url.toString(), { fetchImpl: fetch, resolve: resolver }, async (stage) => {
        await supabase.from("audits").update({ stage }).eq("id", row.id);
      }, { pageSpeedKey: Deno.env.get("PAGESPEED_API_KEY") || void 0 });
      if (out.status === "completed" && out.report) {
        await supabase.from("audits").update({ status: "completed", stage: 10, report: out.report, score: out.report.overall.score, critical_count: out.report.counts.critical, high_count: out.report.counts.high, completed_at: (/* @__PURE__ */ new Date()).toISOString(), lead_status: "Audit Completed" }).eq("id", row.id);
        const link = `${SITE}/audit-report?id=${row.id}&t=${row.token}`;
        await sendEmail(email, `Your Shopify store audit is ready (${out.report.overall.score}/100)`, `<p>Hi ${esc(name.split(" ")[0])},</p><p>Your audit of <b>${esc(url.hostname)}</b> is ready. Overall store health score: <b>${out.report.overall.score}/100</b>, with ${out.report.counts.critical} critical and ${out.report.counts.high} high-priority issues.</p><p><a href="${link}">View your full report</a></p><p>Want help fixing what we found? Reply to this email or book a free consultation at ${SITE}/Consultation.html.</p><p>Crest Matrix Digital Group</p>`);
        await sendEmail(ADMIN_EMAIL(), `Audit completed: ${url.hostname} (${out.report.overall.score}/100)`, `<p>${esc(name)} &lt;${esc(email)}&gt; | goal: ${esc(goal)}</p><p>Score ${out.report.overall.score}, ${out.report.counts.critical} critical, ${out.report.counts.high} high.</p><p><a href="${link}">Open report</a></p>`);
      } else {
        await supabase.from("audits").update({ status: out.status, message: out.message, stage: 10, lead_status: "New Lead" }).eq("id", row.id);
        await sendEmail(ADMIN_EMAIL(), `New audit request (${out.status}): ${url.hostname}`, `<p>${esc(name)} &lt;${esc(email)}&gt; | goal: ${esc(goal)}</p><p>${esc(out.message || out.status)}</p>`);
      }
    } catch (e) {
      await supabase.from("audits").update({ status: "failed", error: String(e.message || e).slice(0, 500), message: "Something went wrong while auditing your store. Please try again later." }).eq("id", row.id);
    }
  })();
  if (typeof EdgeRuntime !== "undefined" && EdgeRuntime.waitUntil) EdgeRuntime.waitUntil(job);
  else job.catch(() => {
  });
  await sendEmail(ADMIN_EMAIL(), `New audit submitted: ${url.hostname}`, `<p>${esc(name)} &lt;${esc(email)}&gt;<br>Goal: ${esc(goal)}<br>Store: ${esc(url.toString())}</p>`);
  return json(req, { id: row.id, token: row.token });
});
