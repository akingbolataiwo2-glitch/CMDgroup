/* Shared helpers: safe DOM building (no innerHTML with report data) and API calls. */
(function () {
  var C = window.CMD_AUDIT || {};
  function configured() { return C.api && C.anonKey && C.api.indexOf('YOUR-') === -1 && C.anonKey.indexOf('YOUR-') === -1; }
  function h(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
      else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? '' : v);
    });
    (function add(c) { if (c == null || c === false) return; if (Array.isArray(c)) return c.forEach(add); e.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c))); })(kids);
    return e;
  }
  function call(path, opts) {
    opts = opts || {};
    return fetch(C.api + '/' + path, { method: opts.method || 'GET', headers: { 'content-type': 'application/json', apikey: C.anonKey, authorization: 'Bearer ' + C.anonKey }, body: opts.body ? JSON.stringify(opts.body) : undefined })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, status: r.status, data: j }; }); });
  }
  window.CMD = { C: C, h: h, call: call, configured: configured };
})();
