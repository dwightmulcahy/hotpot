/* "What's new" dialog: after an upgrade, shows the release notes since the version this
   browser last saw (once), from a changelog.json bundled at release time.
   <script src="whats-new.js" data-src="changelog.json" data-key="app.seenVersion" defer></script>
   Any element with [data-whats-new] opens it; window.WhatsNew.open() does too. */
(function () {
  "use strict";
  var me = document.currentScript || {};
  var SRC = (me.dataset && me.dataset.src) || "changelog.json";
  var KEY = (me.dataset && me.dataset.key) || "whatsNew.seenVersion";
  // data-css="whats-new.css": load the styles from a file (for pages whose Content Security
  // Policy blocks inline styles); otherwise they are injected
  var CSS_FILE = me.dataset && me.dataset.css;
  var data = null, dlg = null;

  function vkey(v) { return String(v || "").replace(/^v/, "").split("-")[0].split(".").map(function (n) { return parseInt(n, 10) || 0; }); }
  function older(a, b) { var x = vkey(a), y = vkey(b); for (var i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0); return false; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function item(text, repo) {
    var t = esc(text);
    return repo ? t.replace(/\(#(\d+)\)/g, function (m, n) { return '(<a href="https://github.com/' + esc(repo) + '/pull/' + n + '" target="_blank" rel="noopener">#' + n + "</a>)"; }) : t;
  }
  var WN_CSS =
      "#wn-dlg{position:fixed;inset:0;margin:auto;height:fit-content;box-sizing:border-box;color-scheme:light dark;width:min(640px,calc(100vw - 24px));max-height:80vh;padding:18px 20px;border:1px solid var(--wn-line,#8884);border-radius:12px;background:var(--wn-bg,Canvas);color:var(--wn-text,CanvasText);font:14px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;box-shadow:0 10px 40px #0005}" +
      "#wn-dlg::backdrop{background:#0006}#wn-dlg .wn-hd{display:flex;justify-content:space-between;align-items:center;gap:12px}" +
      "#wn-dlg .wn-hd b{font-size:16px}#wn-dlg button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--wn-line,#8884);padding:6px 14px;background:transparent;color:inherit}" +
      "#wn-dlg .wn-x{border:0;padding:2px 8px;opacity:.7}#wn-dlg .wn-ok{background:var(--wn-accent,#2563eb);border-color:transparent;color:#fff;font-weight:600}" +
      "#wn-dlg .wn-body{overflow:auto;max-height:60vh;margin:10px 0 14px;padding-right:6px}" +
      "#wn-dlg .wn-rel{border-left:3px solid var(--wn-accent,#2563eb);padding:2px 0 2px 12px;margin:0 0 16px}" +
      "#wn-dlg h3{margin:0;font-size:15px}#wn-dlg h3 span{font-weight:400;opacity:.65;margin-left:6px;font-size:13px}" +
      "#wn-dlg h4{margin:8px 0 2px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;opacity:.65}#wn-dlg h4.wn-break{color:#dc2626;opacity:1}" +
      "#wn-dlg ul{margin:2px 0;padding-left:18px}#wn-dlg li{font-size:13px}#wn-dlg a{color:var(--wn-accent,#2563eb)}" +
      "#wn-dlg .wn-int,#wn-dlg .wn-none{font-size:12px;opacity:.65;margin-top:4px}#wn-dlg .wn-ft{display:flex;align-items:center;gap:12px}" + "#wn-dlg .wn-sp{flex:1}";
  function css() {
    if (document.getElementById("wn-style")) return;
    if (CSS_FILE) {
      var l = document.createElement("link"); l.id = "wn-style"; l.rel = "stylesheet"; l.href = CSS_FILE;
      document.head.appendChild(l); return;
    }
    var s = document.createElement("style"); s.id = "wn-style";
    s.textContent = WN_CSS;
    document.head.appendChild(s);
  }
  function show(since) {
    css();
    if (!dlg) {
      dlg = document.createElement("dialog"); dlg.id = "wn-dlg"; dlg.setAttribute("aria-labelledby", "wn-title");
      dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
      document.body.appendChild(dlg);
    }
    var repo = (data && data.repository) || "";
    var all = ((data && data.releases) || []).filter(function (r) { return !since || older(since, r.version); });
    // releases with only internal changes are listed in one line at the end
    var rels = all.filter(function (r) { return (r.sections || []).length; });
    var quiet = all.filter(function (r) { return !(r.sections || []).length; });
    if (!since) { rels = rels.slice(0, 5); quiet = []; }
    var body = !data ? '<p class="wn-none">Release notes aren\'t included in this build.</p>' : rels.map(function (r) {
      var secs = (r.sections || []).map(function (s) {
        return '<h4 class="' + (s.type === "breaking" ? "wn-break" : "") + '">' + esc(s.title) + "</h4><ul>" +
          s.items.map(function (i) { return "<li>" + item(i.text, repo) + "</li>"; }).join("") + "</ul>";
      }).join("") || '<p class="wn-none">No user-facing changes.</p>';
      return '<div class="wn-rel"><h3>v' + esc(r.version) + (r.date ? "<span>" + esc(r.date) + "</span>" : "") + "</h3>" + secs +
        (r.internal ? '<div class="wn-int">+ ' + r.internal + " internal change" + (r.internal === 1 ? "" : "s") + " (build, tests, docs)</div>" : "") + "</div>";
    }).join("") + (quiet.length ? '<p class="wn-int">Also ' + quiet.map(function (r) { return "v" + esc(r.version); }).join(", ") +
      ": internal changes only (build, tests, docs).</p>" : "") || '<p class="wn-none">No release notes yet.</p>';
    dlg.innerHTML = '<div class="wn-hd"><b id="wn-title">' + (since ? "What's new since v" + esc(String(since).replace(/^v/, "")) : "What's new") +
      '</b><button class="wn-x" aria-label="Close">✕</button></div><div class="wn-body">' + body + '</div><div class="wn-ft">' +
      (repo ? '<a href="https://github.com/' + esc(repo) + '/releases" target="_blank" rel="noopener">All releases on GitHub</a>' : "") +
      '<span class="wn-sp"></span><button class="wn-ok">Got it</button></div>';
    dlg.querySelector(".wn-x").onclick = dlg.querySelector(".wn-ok").onclick = function () { dlg.close(); };
    if (typeof dlg.showModal === "function") dlg.showModal(); else dlg.setAttribute("open", "");
  }
  function start() {
    fetch(SRC, { cache: "no-cache" }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }).then(function (d) {
      data = d && d.current ? d : null;
      if (!data) return;
      // triggers marked hidden stay out of sight until there are notes to show
      Array.prototype.forEach.call(document.querySelectorAll("[data-whats-new][hidden]"), function (el) { el.hidden = false; });
      var seen = null;
      try { seen = localStorage.getItem(KEY); localStorage.setItem(KEY, data.current); } catch (e) { return; }
      // first visit: nothing to compare with; after an upgrade: what changed since then
      // ...but only when something users would notice changed
      if (seen && older(seen, data.current) && (data.releases || []).some(function (r) {
        return older(seen, r.version) && (r.sections || []).length;
      })) show(seen);
    });
  }
  document.addEventListener("click", function (e) {
    var t = e.target && e.target.closest && e.target.closest("[data-whats-new]");
    if (t) { e.preventDefault(); show(null); }
  });
  // non-button triggers (e.g. a version badge with role="button") also open on Enter/Space
  document.addEventListener("keydown", function (e) {
    var t = e.target && e.target.closest && e.target.closest("[data-whats-new]");
    if (t && t.tagName !== "BUTTON" && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); show(null); }
  });
  window.WhatsNew = { open: function () { show(null); } };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
