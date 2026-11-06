// Run: node tests/audit.test.mjs   (Node 22+, runs the TypeScript directly)
import assert from 'node:assert/strict';
import { parseTarget, isPrivateIp, safeFetch, assertPublicHost } from '../supabase/functions/_shared/ssrf.ts';
import { runAudit, STAGES } from '../supabase/functions/_shared/audit.ts';

let pass = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log('ok  -', name); } catch (e) { console.error('FAIL -', name, '\n', e); process.exitCode = 1; } };

// ---------- SSRF ----------
await t('private IPs are blocked', () => {
  for (const ip of ['127.0.0.1', '10.0.0.5', '172.16.0.1', '172.31.255.1', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '::1', 'fe80::1', 'fd00::1', '::ffff:10.0.0.1', '224.0.0.1', '999.1.1.1']) assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ['8.8.8.8', '23.227.38.65', '2606:4700::1111']) assert.equal(isPrivateIp(ip), false, ip);
});
await t('parseTarget rejects dangerous and malformed input', () => {
  for (const bad of ['', 'localhost', 'http://127.0.0.1', 'http://[::1]/', 'http://10.0.0.1', 'ftp://example.com', 'http://user:pw@example.com', 'https://example.com:8080', 'foo', 'http://metadata.google.internal', 'https://a.local', 'http://169.254.169.254/latest/meta-data']) assert.equal(parseTarget(bad).ok, false, bad);
});
await t('parseTarget normalises good input to an origin', () => {
  assert.equal(parseTarget('MyStore.com/products/x?y=1').url.toString(), 'https://mystore.com/');
  assert.equal(parseTarget('http://shop.example.co.uk').url.toString(), 'http://shop.example.co.uk/');
});
await t('DNS that resolves to a private IP is refused', async () => {
  await assert.rejects(assertPublicHost('evil.example', async () => ['10.0.0.9']), /PRIVATE_ADDRESS/);
  await assert.rejects(assertPublicHost('nxdomain.example', async () => { throw new Error('nx'); }), /DNS_NOT_FOUND/);
});
await t('redirect to an internal address is blocked mid-chain', async () => {
  let calls = 0;
  const fetchImpl = async (url) => { calls++; return new Response('', { status: 302, headers: { location: 'http://internal.example/admin' } }); };
  const resolve = async (h) => (h === 'internal.example' ? ['192.168.0.10'] : ['23.227.38.65']);
  const r = await safeFetch('https://good.example/', { fetchImpl, resolve });
  assert.equal(r.ok, false); assert.match(r.error, /PRIVATE_ADDRESS/); assert.equal(calls, 1);
});
await t('redirect loops stop', async () => {
  const fetchImpl = async () => new Response('', { status: 302, headers: { location: 'https://good.example/' } });
  const r = await safeFetch('https://good.example/', { fetchImpl, resolve: async () => ['23.227.38.65'] });
  assert.match(r.error, /TOO_MANY_REDIRECTS/);
});
await t('response body is capped', async () => {
  const big = 'x'.repeat(3_000_000);
  const r = await safeFetch('https://good.example/', { fetchImpl: async () => new Response(big, { status: 200 }), resolve: async () => ['23.227.38.65'] });
  assert.equal(r.truncated, true); assert.ok(r.body.length <= 1_600_000);
});

// ---------- fixture stores ----------
const resolve = async () => ['23.227.38.65'];
const mk = (routes) => async (url) => {
  const u = new URL(url);
  const key = u.pathname + u.search;
  const hit = routes[key] ?? routes[u.pathname];
  if (!hit) return new Response('Not found', { status: 404 });
  if (typeof hit === 'function') return hit(u);
  return new Response(hit.body, { status: hit.status || 200, headers: hit.headers || { 'content-type': 'text/html' } });
};
const weakHome = `<!doctype html><html><head><title>Shop</title>
<script src="https://cdn.shopify.com/s/files/theme.js"></script>
${Array.from({ length: 30 }, (_, i) => `<script src="https://apps${i}.example.com/a.js"></script>`).join('')}
</head><body><h1>A</h1><h1>B</h1><p>Welcome to our store</p>
${Array.from({ length: 8 }, (_, i) => `<img src="/img${i}.jpg">`).join('')}
</body></html>`;
const weakProducts = JSON.stringify({ products: Array.from({ length: 10 }, (_, i) => ({ handle: `p${i}`, title: `Item ${i}`, body_html: '', product_type: 'Mugs', images: [{ alt: null }], variants: [{ price: '10.00', compare_at_price: null, available: i % 2 === 0 }] })) });
const weakStore = mk({
  '/': { body: weakHome }, '/products.json': { body: weakProducts, headers: { 'content-type': 'application/json' } },
  '/collections.json': { body: JSON.stringify({ collections: [{ title: 'Mugs', handle: 'mugs', body_html: '', products_count: 10 }, { title: 'All', handle: 'all', body_html: '', products_count: 10 }] }), headers: { 'content-type': 'application/json' } },
  '/products/p0': { body: '<html><head><title>Shop</title></head><body><h1>Item 0</h1></body></html>' },
  '/collections/mugs': { body: '<html><head><title>Mugs</title></head><body></body></html>' },
});
const goodHome = `<!doctype html><html lang="en"><head><title>Brightleaf Ceramics | Handmade mugs and bowls</title>
<meta name="viewport" content="width=device-width"><meta name="description" content="Handmade stoneware mugs, bowls and plates made in small batches. Free shipping over $50 and easy 30 day returns on every order.">
<link rel="canonical" href="https://good.example/"><link rel="icon" href="/f.png"><meta property="og:title" content="x"><meta property="og:image" content="y">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Brightleaf"}</script>
<script src="https://cdn.shopify.com/a.js" defer></script><script src="https://static.klaviyo.com/onsite/js/klaviyo.js" async></script><script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
</head><body><h1>Handmade ceramics</h1><form action="/search"><input name="q"></form>
<form><input type="email" name="contact[email]"></form><a href="mailto:hi@good.example">Contact</a><a href="/pages/about-us">About</a><a href="/blogs/news">Journal</a>
<a href="https://instagram.com/brightleaf">IG</a><img src="/a.jpg" alt="Mug" width="10" height="10" loading="lazy"></body></html>`;
const longPolicy = '<html><body>' + 'Returns within thirty days of delivery, refunds issued to the original payment method. '.repeat(15) + '</body></html>';
const goodProducts = JSON.stringify({ products: Array.from({ length: 8 }, (_, i) => ({ handle: `m${i}`, title: `Stoneware speckled mug ${i}`, body_html: '<p>' + 'A hand thrown stoneware mug with a speckled glaze, holds 350ml, dishwasher safe. '.repeat(3) + '</p>', product_type: 'Mugs', images: [{ alt: 'Mug front' }, { alt: 'Mug side' }], variants: [{ price: '20.00', compare_at_price: '25.00', available: true }] })) });
const goodStore = mk({
  '/': { body: goodHome, headers: { 'content-type': 'text/html', 'x-shopid': '123' } }, '/products.json': { body: goodProducts, headers: { 'content-type': 'application/json' } },
  '/collections.json': { body: JSON.stringify({ collections: [{ title: 'Mugs', handle: 'mugs', body_html: '<p>Our mugs</p>', products_count: 8 }, { title: 'Bowls', handle: 'bowls', body_html: '<p>Bowls</p>', products_count: 2 }] }), headers: { 'content-type': 'application/json' } },
  '/robots.txt': { body: 'User-agent: *\nSitemap: https://good.example/sitemap.xml', headers: { 'content-type': 'text/plain' } },
  '/sitemap.xml': { body: '<urlset><loc>a</loc><loc>b</loc></urlset>', headers: { 'content-type': 'application/xml' } },
  '/policies/refund-policy': { body: longPolicy }, '/policies/shipping-policy': { body: longPolicy }, '/policies/privacy-policy': { body: longPolicy }, '/policies/terms-of-service': { body: longPolicy },
  '/pages/contact': { body: '<html>contact</html>' }, '/pages/about-us': { body: '<html>about</html>' },
  '/products/m0': { body: `<html><head><title>Mug 0 – Brightleaf</title><meta name="description" content="A mug"><script type="application/ld+json">{"@type":"Product","name":"m"}</script></head><body><form class="product-form"><button name="add">Add to cart</button></form><div>judge.me reviews</div><p>Free shipping and delivery in 3 days.</p><h2>You may also like</h2><p>Visa Mastercard</p></body></html>` },
  '/collections/mugs': { body: '<html><head><title>Mugs</title></head></html>' },
});

const noop = () => {};
await t('weak store: finds real issues with evidence and scores low', async () => {
  const stages = [];
  const r = await runAudit('https://weak.example/', { fetchImpl: weakStore, resolve }, (i) => stages.push(i));
  assert.equal(r.status, 'completed');
  const ids = r.report.findings.map((f) => f.id);
  for (const id of ['seo.meta_desc', 'seo.h1_multi', 'seo.default_text', 'seo.product_desc', 'seo.product_alt', 'trust.refund', 'trust.shipping', 'ux.contact', 'mkt.email_capture', 'tech.viewport', 'tech.sitemap', 'cro.out_of_stock', 'perf.scripts', 'cro.product_images']) assert.ok(ids.includes(id), 'missing ' + id + ' in ' + ids.join(','));
  assert.ok(r.report.findings.every((f) => f.evidence.length > 0 && f.url), 'every finding must carry evidence and a URL');
  assert.ok(r.report.overall.score < 50, 'score ' + r.report.overall.score);
  assert.equal(r.report.categories.find((c) => c.key === 'performance').scored, false);
  assert.ok(!r.report.overall.scoredCategories.includes('performance'));
  assert.deepEqual(stages, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(STAGES.length, 10);
  assert.ok(r.report.connections.length >= 2);
  assert.equal(r.report.trafficIntelligence.status, 'unavailable');
  assert.ok(r.report.coverage.pagesFailed.length > 0);
});
await t('strong store: scores high with few issues and passes', async () => {
  const r = await runAudit('https://good.example/', { fetchImpl: goodStore, resolve }, noop);
  assert.equal(r.status, 'completed');
  assert.ok(r.report.overall.score >= 85, 'score ' + r.report.overall.score);
  assert.equal(r.report.counts.critical, 0);
  assert.equal(r.report.counts.high, 0, JSON.stringify(r.report.findings.filter((f) => f.severity === 'high').map((f) => f.id)));
  assert.ok(r.report.passes.length >= 10);
  assert.ok(r.report.passes.some((p) => p.title.includes('Klaviyo')));
});
await t('non-Shopify site is reported honestly, not audited', async () => {
  const r = await runAudit('https://notshop.example/', { fetchImpl: mk({ '/': { body: '<html><title>WP</title><body>wp-content</body></html>' } }), resolve }, noop);
  assert.equal(r.status, 'not_shopify'); assert.equal(r.report, undefined); assert.match(r.message, /does not appear to be powered by Shopify/);
});
await t('password-protected store is flagged', async () => {
  const r = await runAudit('https://locked.example/', { fetchImpl: mk({ '/': { body: '<html><script src="https://cdn.shopify.com/x.js"></script><form action="/password"></form></html>' }, '/products.json': { status: 401, body: '' } }), resolve }, noop);
  assert.equal(r.status, 'password');
});
await t('unreachable site returns a clear failure', async () => {
  const r = await runAudit('https://down.example/', { fetchImpl: async () => { throw new Error('ECONNREFUSED'); }, resolve }, noop);
  assert.equal(r.status, 'unreachable');
});
await t('no PageSpeed key => performance stays unscored and says why', async () => {
  const r = await runAudit('https://good.example/', { fetchImpl: goodStore, resolve }, noop);
  assert.match(r.report.performance.note, /not scored|Not run/i);
  assert.equal(r.report.performance.lab, null);
});
console.log(`\n${pass} checks passed`);
