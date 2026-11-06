/* /audit-report : fetch the stored report and render it. All report text goes through textContent (never innerHTML). */
(function () {
  var h = CMD.h, C = CMD.C, root = document.getElementById('report');
  var q = new URLSearchParams(location.search), id = q.get('id'), t = q.get('t');
  var SEV = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', opportunity: 'Opportunity' };
  var SEVC = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)', opportunity: 'var(--sev-opportunity)' };
  var CONF = { verified: 'Verified', likely: 'Likely', indicative: 'Indicative (cannot be fully confirmed from public data)' };
  function msg(title, text) { root.innerHTML = ''; root.appendChild(h('div', { class: 'rep-head' }, [h('h1', { text: title }), h('p', { class: 'sub', text: text }), h('a', { class: 'btn btn-primary', href: 'shopify-store-audit.html', text: 'Run a new audit' })])); }
  if (!id || !t) return msg('Report not found', 'This link is incomplete. Please use the link from your email, or run a new audit.');
  if (!CMD.configured()) return msg('Audit service not connected', 'Set the Supabase values in assets/audit/config.js.');
  var tries = 0;
  (function load() {
    CMD.call('audit-status?id=' + encodeURIComponent(id) + '&t=' + encodeURIComponent(t)).then(function (r) {
      if (!r.ok) return msg('Report not found', 'We could not find this report. The link may be wrong or the report may have expired.');
      var d = r.data;
      if (d.status === 'completed' && d.report) return render(d.report);
      if (['failed', 'not_shopify', 'unreachable', 'password'].indexOf(d.status) > -1) return msg('No report available', d.message || 'This audit could not be completed.');
      if (++tries > 120) return msg('Still working', 'The audit is taking longer than expected. We will email you when it is ready.');
      msg('Your audit is still running', 'Step ' + Math.min((d.stage || 0) + 1, 10) + ' of 10. This page refreshes by itself.'); setTimeout(load, 3000);
    }).catch(function (e) { console.error(e); msg('Connection problem', 'We could not reach the audit service. Please reload the page.'); });
  })();

  function sec(kicker, title, kids) { return h('section', { class: 'block' }, [h('span', { class: 'kicker', text: kicker }), h('h2', { class: 'sec', text: title }), kids]); }
  function scoreColor(s) { return s >= 80 ? 'var(--sev-opportunity)' : s >= 60 ? 'var(--sev-medium)' : s >= 40 ? 'var(--sev-high)' : 'var(--sev-critical)'; }

  function gauge(score) {
    var R = 96, Cc = 2 * Math.PI * R, ns = 'http://www.w3.org/2000/svg';
    function el(n, a) { var e = document.createElementNS(ns, n); for (var k in a) e.setAttribute(k, a[k]); return e; }
    var svg = el('svg', { width: 220, height: 220, viewBox: '0 0 220 220', role: 'img', 'aria-label': 'Overall score ' + score + ' out of 100' });
    svg.appendChild(el('circle', { cx: 110, cy: 110, r: R, fill: 'none', stroke: 'rgba(32,31,29,.12)', 'stroke-width': 14 }));
    svg.appendChild(el('circle', { cx: 110, cy: 110, r: R, fill: 'none', stroke: scoreColor(score), 'stroke-width': 14, 'stroke-linecap': 'round', 'stroke-dasharray': Cc, 'stroke-dashoffset': Cc * (1 - score / 100) }));
    return h('div', { class: 'gauge' }, [svg, h('div', { class: 'num' }, [h('b', { text: String(score) }), h('span', { text: 'out of 100' })])]);
  }

  function finding(f) {
    var ev = f.evidence && f.evidence.length ? h('dd', {}, h('ul', {}, f.evidence.map(function (e) { return h('li', { text: e }); }))) : h('dd', { text: 'No additional evidence recorded.' });
    var row = function (k, v) { return [h('dt', { text: k }), typeof v === 'string' ? h('dd', { text: v }) : v]; };
    var el = h('details', { class: 'finding', style: '--s:' + SEVC[f.severity], 'data-sev': f.severity, 'data-cat': f.category, id: 'f-' + f.id }, [
      h('summary', {}, [h('span', { class: 'sev', style: '--s:' + SEVC[f.severity], text: SEV[f.severity] }), h('h3', { text: f.title }), h('span', { class: 'tagline', text: f.area })]),
      h('div', { class: 'body' }, [h('dl', {}, [].concat(row('What we found', f.what), row('Evidence', ev), row('Why it matters', f.why), row('Likely impact', f.impact), row('Recommended fix', f.fix),
        row('Where', h('dd', {}, h('span', { class: 'u', text: f.url }))), row('Confidence', CONF[f.confidence] || f.confidence)))])]);
    return el;
  }

  function render(R) {
    document.title = 'Shopify Store Audit: ' + R.store.domain + ' | Crest Matrix Digital Group';
    root.innerHTML = '';
    var date = new Date(R.auditedAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    root.appendChild(h('div', { class: 'rep-head' }, [h('span', { class: 'kicker', text: 'Shopify store audit report' }), h('h1', { text: R.store.name || R.store.domain }),
      h('div', { class: 'meta' }, [h('span', { text: R.store.domain }), h('span', { text: 'Audited ' + date })]),
      h('div', { class: 'no-print', style: 'margin-top:16px;display:flex;gap:10px;flex-wrap:wrap' }, [h('button', { class: 'btn btn-outline', type: 'button', text: 'Save as PDF', onclick: function () { window.print(); } }), h('a', { class: 'btn btn-outline', href: 'shopify-store-audit.html', text: 'Audit another store' })])]));

    // Executive summary + dashboard
    var cats = h('div', { class: 'cats' }, R.categories.map(function (c) {
      return h('div', { class: 'cat' + (c.scored ? '' : ' off'), style: '--c:' + (c.scored ? scoreColor(c.score) : 'var(--color-neutral-500)') }, [h('span', { text: c.label + ' (' + c.weight + '%)' }), h('div', { class: 'bar' }, h('i', { style: 'width:' + (c.scored ? c.score : 0) + '%' })), h('em', { text: c.scored ? String(c.score) : 'n/a' }), c.note ? h('small', { text: c.note }) : null]);
    }));
    root.appendChild(sec('Executive summary', 'Where your store stands', [h('p', { class: 'sub', text: R.summary }),
      h('div', { class: 'score-row' }, [gauge(R.overall.score), cats]), h('p', { class: 'sub', text: R.overall.note })]));

    var n = R.counts;
    root.appendChild(h('div', { class: 'grid g5' }, [['Critical', n.critical, 'critical'], ['High', n.high, 'high'], ['Medium', n.medium, 'medium'], ['Low', n.low, 'low'], ['Opportunities', n.opportunity, 'opportunity']].map(function (x) {
      return h('div', { class: 'tile', style: 'border-left:4px solid ' + SEVC[x[2]] }, [h('h3', { text: String(x[1]) }), h('p', { text: x[0] })]);
    })));

    // Findings with filters
    var list = h('div', { id: 'flist' }, R.findings.length ? R.findings.map(finding) : h('p', { class: 'sub', text: 'No issues were detected in the checks we could run.' }));
    var chips = h('div', { class: 'chips no-print' }), active = 'all';
    function chip(label, val) { var b = h('button', { class: 'chip', type: 'button', 'aria-pressed': val === 'all' ? 'true' : 'false', text: label, onclick: function () { active = val; [].forEach.call(chips.children, function (c) { c.setAttribute('aria-pressed', c === b ? 'true' : 'false'); }); [].forEach.call(list.children, function (f) { if (f.dataset) f.hidden = !(val === 'all' || f.dataset.sev === val || f.dataset.cat === val); }); } }); chips.appendChild(b); }
    chip('All (' + R.findings.length + ')', 'all'); ['critical', 'high', 'medium', 'low', 'opportunity'].forEach(function (s) { if (n[s]) chip(SEV[s] + ' (' + n[s] + ')', s); });
    R.categories.forEach(function (c) { var k = R.findings.filter(function (f) { return f.category === c.key; }).length; if (k) chip(c.label, c.key); });
    root.appendChild(sec('Findings', 'Issues, with evidence', [chips, list]));

    if (R.passes && R.passes.length) root.appendChild(sec('Strengths', 'What your store already does well', h('ul', { class: 'list good' }, R.passes.map(function (p) { return h('li', {}, [h('b', { text: p.title }), h('span', { text: p.detail })]); }))));
    if (R.connections && R.connections.length) root.appendChild(sec('Connected problems', "How your store's problems connect", h('ul', { class: 'list' }, R.connections.map(function (c) { return h('li', {}, [h('b', { text: c.title }), h('span', { text: c.text })]); }))));
    if (R.opportunities && R.opportunities.length) root.appendChild(sec('Opportunities', 'Growth opportunities', h('ul', { class: 'list' }, R.opportunities.map(function (c) { return h('li', {}, [h('b', { text: c.title }), h('span', { text: c.text })]); }))));
    if (R.roadmap && R.roadmap.length) root.appendChild(sec('Roadmap', 'Recommended order of work', R.roadmap.map(function (ph, i) {
      return h('details', { class: 'road', open: i === 0 }, [h('summary', { text: ph.phase }), h('ol', {}, ph.items.map(function (it) { return h('li', {}, [h('span', { text: it.title }), h('small', { text: it.why })]); }))]);
    })));

    // Performance + traffic honesty
    var perfNote = R.performance && R.performance.note ? R.performance.note : 'Performance data was not available for this audit.';
    root.appendChild(sec('Data we could not see', 'Performance and traffic', [h('div', { class: 'notice' }, perfNote), h('div', { class: 'notice', style: 'margin-top:10px' }, 'Traffic and sales: ' + R.trafficIntelligence.note)]));

    // Coverage
    var cv = R.coverage, rows = cv.pages.map(function (p) { return h('tr', {}, [h('td', { text: p.path }), h('td', { text: String(p.status) }), h('td', { text: p.ms + ' ms' })]); });
    function ul(items) { return h('ul', {}, items.map(function (i) { return h('li', { text: i }); })); }
    root.appendChild(h('section', { class: 'block method' }, [h('span', { class: 'kicker', text: 'Methodology' }), h('h2', { class: 'sec', text: 'What this audit covered' }),
      h('p', { class: 'sub', text: cv.pagesAnalysed + ' of ' + cv.pagesRequested + ' pages analysed. ' + (cv.catalogSampled ? cv.catalogSampled.note : '') }),
      h('div', { class: 'cols2' }, [h('div', {}, [h('h3', { text: 'Verified' }), ul(cv.verified), h('h3', { text: 'Estimated' }), ul(cv.estimated)]), h('div', {}, [h('h3', { text: 'Unavailable' }), ul(cv.unavailable), h('h3', { text: 'Limitations' }), ul(cv.limitations)])]),
      h('div', { class: 'tbl-wrap' }, h('table', {}, [h('thead', {}, h('tr', {}, [h('th', { text: 'Page' }), h('th', { text: 'Status' }), h('th', { text: 'Fetch time' })])), h('tbody', {}, rows)])),
      h('p', { class: 'sub', text: 'Tools: ' + cv.tools.join(', ') + '.' })]));

    root.appendChild(cta());
  }

  function cta() {
    var ta = h('textarea', { placeholder: 'Anything you want us to focus on? (optional)', 'aria-label': 'Message' }), status = h('p', { role: 'status', style: 'margin-top:10px' });
    function send(kind, label) { return h('button', { class: 'btn btn-primary', type: 'button', text: label, onclick: function (ev) { var b = ev.target; b.disabled = true; CMD.call('request-help', { method: 'POST', body: { id: id, token: t, kind: kind, message: ta.value.slice(0, 1000) } }).then(function (r) { status.textContent = r.ok ? 'Thanks. We have your request and will reply by email.' : ((r.data && r.data.error) || 'Something went wrong. Please use WhatsApp or the contact page.'); b.disabled = false; }).catch(function () { status.textContent = 'Could not send. Please use WhatsApp or the contact page.'; b.disabled = false; }); } }); }
    return h('div', { class: 'cta-band no-print' }, [h('h2', { text: 'Want these fixed?' }), h('p', { text: 'Tell us you would like help and we will review this report with you. Fixes are quoted before any work starts.' }), ta,
      h('div', { class: 'row' }, [send('assistance', 'I want help fixing this'), send('consultation', 'Request a consultation'), h('a', { class: 'btn', href: C.calendly, target: '_blank', rel: 'noopener', text: 'Book a call' }), h('a', { class: 'btn', href: C.whatsapp, target: '_blank', rel: 'noopener', text: 'WhatsApp us' }), h('a', { class: 'btn', href: C.contact, text: 'Contact page' })]), status]);
  }
})();
