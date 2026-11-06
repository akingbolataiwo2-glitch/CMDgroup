/* /shopify-store-audit : submit form, then show REAL progress from the backend (no simulated percentages). */
(function () {
  var h = CMD.h, form = document.getElementById('audit-form'), formWrap = document.getElementById('form-wrap'), prog = document.getElementById('progress'), out = document.getElementById('outcome');
  var STAGES = ['Validating store URL', 'Detecting Shopify platform', 'Discovering store pages', 'Analysing page performance signals', 'Evaluating technical SEO', 'Reviewing user experience', 'Checking conversion opportunities', 'Evaluating marketing readiness', 'Connecting related findings', 'Preparing final report'];
  var pollTimer = null, started = 0;

  if (!CMD.configured()) {
    document.getElementById('cfg-note').hidden = false;
    form.querySelector('button[type=submit]').disabled = true;
  }
  // Resume an audit started in this browser (lets customers leave and come back).
  try { var saved = JSON.parse(localStorage.getItem('cmd_audit') || 'null'); if (saved && saved.id && Date.now() - saved.t < 6 * 3600e3 && CMD.configured()) { showProgress(saved.id, saved.token, saved.domain, true); } } catch (e) {}

  function setErr(m) { document.getElementById('form-err').textContent = m || ''; }
  form.addEventListener('submit', function (ev) {
    ev.preventDefault(); setErr('');
    var f = new FormData(form);
    var body = { storeUrl: (f.get('storeUrl') || '').trim(), name: (f.get('name') || '').trim(), email: (f.get('email') || '').trim(), goal: f.get('goal'), consent: !!f.get('consent'), website: f.get('website') || '' };
    if (!body.storeUrl) return setErr('Please enter your Shopify store URL.');
    if (!body.name) return setErr('Please enter your full name.');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(body.email)) return setErr('Please enter a valid business email.');
    if (!body.goal) return setErr('Please choose your primary business goal.');
    if (!body.consent) return setErr('Please tick the consent box so we can run your audit.');
    var btn = form.querySelector('button[type=submit]'); btn.disabled = true; btn.textContent = 'Starting your audit…';
    CMD.call('start-audit', { method: 'POST', body: body }).then(function (r) {
      btn.disabled = false; btn.textContent = 'Audit my store for free';
      if (!r.ok) return setErr((r.data && r.data.error) || 'We could not start your audit. Please try again.');
      var domain = body.storeUrl.replace(/^https?:\/\//i, '').split('/')[0];
      try { localStorage.setItem('cmd_audit', JSON.stringify({ id: r.data.id, token: r.data.token, domain: domain, t: Date.now() })); } catch (e) {}
      showProgress(r.data.id, r.data.token, domain);
    }).catch(function () { btn.disabled = false; btn.textContent = 'Audit my store for free'; setErr('We could not reach the audit service. Please check your connection and try again.'); });
  });

  function showProgress(id, token, domain, resumed) {
    formWrap.hidden = true; out.hidden = true; prog.hidden = false; started = Date.now();
    prog.innerHTML = '';
    prog.appendChild(h('span', { class: 'kicker', text: resumed ? 'Audit in progress' : 'Your audit has started' }));
    prog.appendChild(h('h2', { class: 'sec', text: 'Auditing ' + (domain || 'your store') }));
    prog.appendChild(h('p', { class: 'sub', text: 'These steps reflect what our audit engine is really doing right now. You can leave this page: your report link is saved in this browser and we will email it when it is ready.' }));
    var bar = h('div', { class: 'bar' }, h('i', { style: 'width:2%' })), list = h('ol', { class: 'steps', 'aria-live': 'polite' });
    STAGES.forEach(function (s, i) { list.appendChild(h('li', { 'data-i': i }, [h('span', { class: 'dot', text: String(i + 1) }), h('span', { text: s })])); });
    var note = h('p', { class: 'sub', id: 'slow-note', hidden: true, text: 'This is taking a little longer than usual. The audit keeps running in the background and the report will be emailed to you.' });
    prog.appendChild(bar); prog.appendChild(list); prog.appendChild(note);
    tick(id, token, bar, list, note);
  }

  function tick(id, token, bar, list, note) {
    CMD.call('audit-status?id=' + encodeURIComponent(id) + '&t=' + encodeURIComponent(token)).then(function (r) {
      if (!r.ok) { return finish({ status: 'failed', message: 'We could not find this audit. Please start a new one.' }); }
      var d = r.data, stage = Math.min(d.stage || 0, STAGES.length);
      [].forEach.call(list.children, function (li, i) { li.className = d.status === 'completed' || i < stage ? 'done' : i === stage ? 'now' : ''; if (li.className === 'done') li.firstChild.textContent = '✓'; });
      bar.firstChild.style.width = Math.max(2, Math.round((d.status === 'completed' ? 10 : stage) / 10 * 100)) + '%';
      if (Date.now() - started > 90000) note.hidden = false;
      if (d.status === 'completed') { try { localStorage.removeItem('cmd_audit'); } catch (e) {} location.href = 'audit-report.html?id=' + encodeURIComponent(id) + '&t=' + encodeURIComponent(token); return; }
      if (['failed', 'not_shopify', 'unreachable', 'password'].indexOf(d.status) > -1) return finish(d);
      pollTimer = setTimeout(function () { tick(id, token, bar, list, note); }, 2500);
    }).catch(function () { pollTimer = setTimeout(function () { tick(id, token, bar, list, note); }, 5000); });
  }

  function finish(d) {
    try { localStorage.removeItem('cmd_audit'); } catch (e) {}
    prog.hidden = true; out.hidden = false; out.innerHTML = '';
    var titles = { not_shopify: 'This does not look like a Shopify store', unreachable: 'We could not reach your store', password: 'Your store is password protected', failed: 'The audit could not be completed' };
    out.appendChild(h('span', { class: 'kicker', text: 'Audit result' }));
    out.appendChild(h('h2', { class: 'sec', text: titles[d.status] || 'Audit result' }));
    out.appendChild(h('p', { class: 'sub', text: d.message || '' }));
    var extra = { not_shopify: 'This audit is built specifically for Shopify, so we have not run a Shopify audit on this site. If you sell on another platform or want to move to Shopify, we can still review it manually and tell you what we would improve.', unreachable: 'Check the address is spelled correctly and that the site is online, then try again.', password: 'Remove the storefront password in Shopify (Online Store > Preferences) so shoppers and our audit can see the store, then try again.', failed: 'Please try again in a few minutes.' };
    out.appendChild(h('p', { class: 'sub', text: extra[d.status] || '' }));
    out.appendChild(h('div', { class: 'row', style: 'display:flex;gap:12px;flex-wrap:wrap' }, [
      h('a', { class: 'btn btn-primary', href: 'shopify-store-audit.html', text: 'Try another store' }),
      h('a', { class: 'btn btn-outline', href: 'StoreReview.html', text: 'Request a free manual review' }),
    ]));
  }
})();
