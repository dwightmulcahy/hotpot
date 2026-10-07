from __future__ import annotations

PRODUCTION_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hotpot Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0d1016;--surface:#121720;--surface-2:#171d28;--surface-3:#1b2230;--line:#283140;--line-soft:#202734;--text:#e9edf3;--muted:#8e99aa;--faint:#657184;--good:#78c7a3;--good-bg:#14251f;--warn:#d6ad62;--warn-bg:#2a2215;--bad:#dc7f86;--bad-bg:#2c191d;--info:#84aee8;--info-bg:#162235;--shadow:0 18px 50px rgba(0,0,0,.18)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.45}button,input,select{font:inherit}a{color:var(--info);text-decoration:none}a:hover{text-decoration:underline}code{color:#d6deea;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.muted{color:var(--muted)}.faint{color:var(--faint)}.good{color:var(--good)}.warn{color:var(--warn)}.danger{color:var(--bad)}
.shell{min-height:100vh}.topbar{position:sticky;top:0;z-index:30;background:rgba(13,16,22,.94);backdrop-filter:blur(14px);border-bottom:1px solid var(--line-soft)}.topbar-inner{max-width:1540px;margin:auto;padding:17px 26px 0}.brandline{display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{display:flex;align-items:center;gap:12px;min-width:0}.brand-mark{display:grid;place-items:center;width:38px;height:38px;border:1px solid var(--line);border-radius:11px;background:var(--surface);font-size:20px}.title{font-size:22px;font-weight:760;letter-spacing:-.02em}.subtitle{font-size:12px;color:var(--muted);margin-top:1px}.header-state{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}.status-chip{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:999px;padding:6px 10px;background:var(--surface);font-size:12px;color:var(--muted);white-space:nowrap}.status-chip .dot{width:7px;height:7px;margin:0}.status-chip.ready{color:var(--good);border-color:#2e5547;background:var(--good-bg)}.status-chip.alert{color:var(--warn);border-color:#5b4725;background:var(--warn-bg)}.status-chip.bad{color:var(--bad);border-color:#66353b;background:var(--bad-bg)}
.tabs{display:flex;gap:4px;margin-top:15px;overflow:auto;scrollbar-width:none}.tabs::-webkit-scrollbar{display:none}.tab{appearance:none;border:0;border-bottom:2px solid transparent;background:transparent;color:var(--muted);padding:10px 13px 11px;cursor:pointer;font-weight:650;white-space:nowrap}.tab:hover{color:var(--text)}.tab.active{color:var(--text);border-bottom-color:var(--info)}
main{max-width:1540px;margin:auto;padding:22px 26px 42px}.view{display:none}.view.active{display:block}.view-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:14px}.view-title{font-size:20px;font-weight:720;margin:0}.view-note{font-size:12px;color:var(--muted)}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:11px}.metric-card,.panel{background:var(--surface);border:1px solid var(--line-soft);border-radius:12px;box-shadow:var(--shadow)}.metric-card{padding:15px 16px;min-height:112px;display:flex;flex-direction:column;justify-content:space-between}.metric-label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em;font-weight:700}.metric-value{font-size:31px;line-height:1;font-weight:760;letter-spacing:-.035em;margin:8px 0 5px}.metric-sub{font-size:12px;color:var(--muted)}.metric-card.attention .metric-value{color:var(--warn)}.metric-card.enforced .metric-value{color:var(--good)}.metric-card.degraded .metric-value{color:var(--bad)}
.grid{display:grid;grid-template-columns:minmax(0,1.28fr) minmax(320px,.72fr);gap:12px;margin-top:12px}.grid.equal{grid-template-columns:repeat(2,minmax(0,1fr))}.grid.thirds{grid-template-columns:repeat(3,minmax(0,1fr))}.panel{padding:16px;min-width:0}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.panel h2,.panel h3{margin:0;font-size:14px;font-weight:700;letter-spacing:-.01em}.section-kicker{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);font-weight:750;margin-bottom:3px}.panel-link{appearance:none;border:0;background:transparent;color:var(--info);padding:0;cursor:pointer;font-size:12px}.panel-link:hover{text-decoration:underline}
.attention-card,.enforcement-card,.compact-card{border:1px solid var(--line-soft);background:var(--surface-2);border-radius:10px;padding:12px;margin-top:8px}.attention-card:first-child,.enforcement-card:first-child,.compact-card:first-child{margin-top:0}.attention-card.l4{border-left:3px solid var(--bad)}.attention-card.l3{border-left:3px solid var(--warn)}.attention-top,.compact-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.actor{font-weight:700;overflow-wrap:anywhere}.meta-line{font-size:12px;color:var(--muted);margin-top:4px}.meta-line strong{color:var(--text);font-weight:650}.actions{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-top:9px}.btn{appearance:none;border:1px solid var(--line);background:var(--surface-3);color:var(--text);border-radius:7px;padding:6px 9px;cursor:pointer;font-size:12px;font-weight:650}.btn:hover{border-color:#46536a}.btn.primary{border-color:#446b5b;background:#173126;color:#a5dfc5}.btn.danger{border-color:#683941;background:#2c191d;color:#ef9ca2}.btn.ghost{background:transparent}.btn:disabled{opacity:.45;cursor:not-allowed}
.badge{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:2px 7px;font-size:10px;font-weight:750;text-transform:uppercase;letter-spacing:.045em;white-space:nowrap}.badge.l1{color:#9ca7b7}.badge.l2{color:var(--info);border-color:#365272;background:var(--info-bg)}.badge.l3,.badge.medium{color:var(--warn);border-color:#5b4725;background:var(--warn-bg)}.badge.l4,.badge.high{color:var(--bad);border-color:#66353b;background:var(--bad-bg)}.badge.applied{color:var(--good);border-color:#2e5547;background:var(--good-bg)}.badge.neutral{color:var(--muted)}
.table-wrap{overflow:auto;border:1px solid var(--line-soft);border-radius:9px}table{width:100%;border-collapse:collapse;font-size:12px;min-width:680px}th{position:sticky;top:0;background:var(--surface-2);color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.06em;font-weight:750}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line-soft);vertical-align:top}tbody tr:last-child td{border-bottom:0}tbody tr.clickable{cursor:pointer}tbody tr.clickable:hover td{background:#161c26}.cell-main{font-weight:650;color:var(--text)}.cell-sub{font-size:11px;color:var(--muted);margin-top:2px}.level-cell{white-space:nowrap}.empty{color:var(--muted);font-size:12px;padding:10px 0}.empty.center{text-align:center;padding:28px 12px}
.app-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.app-chip{border:1px solid var(--line-soft);background:var(--surface-2);border-radius:9px;padding:10px;min-width:0}.app-name{display:flex;align-items:center;gap:7px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex:0 0 auto}.dot.ok{background:var(--good)}.dot.down{background:var(--bad)}.app-sub{font-size:11px;color:var(--muted);margin-top:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.control{border:1px solid var(--line);background:var(--surface);color:var(--text);border-radius:8px;padding:7px 9px;font-size:12px;outline:none}.control:focus{border-color:#4c6282}.search{min-width:220px;flex:1}.split-panels{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.kv{display:grid;grid-template-columns:minmax(130px,.65fr) 1.35fr;gap:6px 12px;font-size:12px}.kv div:nth-child(odd){color:var(--muted)}.kv div:nth-child(even){min-width:0;overflow-wrap:anywhere}.list-row{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid var(--line-soft)}.list-row:last-child{border-bottom:0}.list-main{min-width:0}.list-title{font-weight:650;overflow-wrap:anywhere}.list-meta{font-size:11px;color:var(--muted);margin-top:2px}.list-count{font-variant-numeric:tabular-nums;color:var(--muted);white-space:nowrap}
.history-row{display:grid;grid-template-columns:100px minmax(150px,1fr) minmax(120px,.7fr) 140px;gap:9px;padding:8px 0;border-bottom:1px solid var(--line-soft);font-size:12px}.history-row:last-child{border-bottom:0}.history-status{text-transform:capitalize}.history-actor{font-weight:650;overflow-wrap:anywhere}
.drawer-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.46);z-index:80;opacity:0;pointer-events:none;transition:opacity .16s ease}.drawer-backdrop.open{opacity:1;pointer-events:auto}.drawer{position:fixed;top:0;right:0;bottom:0;width:min(560px,94vw);background:#10151d;border-left:1px solid var(--line);z-index:90;transform:translateX(102%);transition:transform .2s ease;box-shadow:-24px 0 60px rgba(0,0,0,.3);overflow:auto}.drawer.open{transform:translateX(0)}.drawer-head{position:sticky;top:0;z-index:2;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:18px;background:rgba(16,21,29,.96);backdrop-filter:blur(12px);border-bottom:1px solid var(--line-soft)}.drawer-title{font-size:18px;font-weight:760;overflow-wrap:anywhere}.drawer-body{padding:18px}.drawer-close{appearance:none;border:1px solid var(--line);background:var(--surface-2);color:var(--muted);width:31px;height:31px;border-radius:8px;cursor:pointer}.drawer-close:hover{color:var(--text)}.drawer-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}.drawer-metric{border:1px solid var(--line-soft);background:var(--surface);border-radius:9px;padding:10px}.drawer-metric b{display:block;font-size:19px}.drawer-metric span{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}.drawer-section{margin-top:17px}.drawer-section h4{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint)}.mini-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.mini-card{border:1px solid var(--line-soft);background:var(--surface);border-radius:9px;padding:10px}.mini-card strong{display:block}.mini-card span{font-size:11px;color:var(--muted)}
.skeleton{height:12px;border-radius:6px;background:linear-gradient(90deg,#171d27,#202835,#171d27);background-size:200% 100%;animation:pulse 1.3s infinite}@keyframes pulse{to{background-position:-200% 0}}
@media(max-width:1120px){.metrics{grid-template-columns:repeat(2,1fr)}.grid,.grid.equal,.grid.thirds,.split-panels{grid-template-columns:1fr}.app-strip{grid-template-columns:repeat(2,1fr)}}
@media(max-width:720px){.topbar-inner,main{padding-left:14px;padding-right:14px}.brandline{align-items:flex-start;flex-direction:column}.header-state{justify-content:flex-start}.metrics{grid-template-columns:1fr 1fr}.metric-card{min-height:96px}.metric-value{font-size:26px}.app-strip{grid-template-columns:1fr}.drawer-metrics{grid-template-columns:repeat(2,1fr)}.history-row{grid-template-columns:80px 1fr}.history-row>:nth-child(3),.history-row>:nth-child(4){display:none}}
@media(max-width:430px){.metrics{grid-template-columns:1fr}.tabs{margin-left:-4px;margin-right:-4px}.tab{padding-left:10px;padding-right:10px}}
</style>
</head>
<body>
<div class="shell">
<header class="topbar">
  <div class="topbar-inner">
    <div class="brandline">
      <div class="brand"><div class="brand-mark">🔥</div><div><div class="title">Hotpot</div><div class="subtitle">Cross-app threat intelligence & response</div></div></div>
      <div class="header-state">
        <span id="healthBadge" class="status-chip"><span class="dot ok"></span>Loading health</span>
        <button id="cloudflareBadge" class="status-chip" data-jump="enforcement" type="button">Cloudflare loading</button>
        <span id="updated" class="status-chip">Loading…</span>
      </div>
    </div>
    <nav class="tabs" aria-label="Dashboard sections">
      <button class="tab active" data-view="overview" type="button">Overview</button>
      <button class="tab" data-view="threats" type="button">Threats</button>
      <button class="tab" data-view="enforcement" type="button">Enforcement</button>
      <button class="tab" data-view="network" type="button">Network</button>
      <button class="tab" data-view="operations" type="button">Operations</button>
    </nav>
  </div>
</header>
<main>
  <section id="view-overview" class="view active">
    <div class="view-head"><div><h1 class="view-title">Security overview</h1><div class="view-note">What needs attention now, followed by the most recent activity.</div></div></div>
    <div id="overviewMetrics" class="metrics"></div>
    <div class="grid equal">
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Action queue</div><h2>Needs your attention</h2></div><button class="panel-link" data-jump="enforcement" type="button">View all →</button></div><div id="overviewAttention"></div></section>
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Cloudflare</div><h2>Active enforcement</h2></div><button class="panel-link" data-jump="enforcement" type="button">Manage →</button></div><div id="overviewEnforcement"></div></section>
    </div>
    <div class="grid">
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Last events</div><h2>Recent activity</h2></div><button class="panel-link" data-jump="threats" type="button">Investigate threats →</button></div><div class="table-wrap"><table><thead><tr><th>Time</th><th>App</th><th>Source</th><th>Category</th><th>Path</th><th>Action</th></tr></thead><tbody id="overviewRecent"></tbody></table></div></section>
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Protected surface</div><h2>Applications</h2></div><button class="panel-link" data-jump="operations" type="button">Operations →</button></div><div id="overviewApps" class="app-strip"></div></section>
    </div>
  </section>

  <section id="view-threats" class="view">
    <div class="view-head"><div><h1 class="view-title">Threats</h1><div class="view-note">Prioritize active attackers, then inspect lifetime behavior in the side drawer.</div></div></div>
    <section class="panel">
      <div class="panel-head"><div><div class="section-kicker">Active window</div><h2>Top offenders</h2></div><div class="toolbar"><input id="threatSearch" class="control search" type="search" placeholder="Search IP, worker, ASN, provider, country…"><select id="threatLevel" class="control"><option value="">All levels</option><option value="4">L4 only</option><option value="3">L3+</option><option value="2">L2+</option></select><select id="threatApp" class="control"><option value="">All apps</option></select></div></div>
      <div class="table-wrap"><table><thead><tr><th>Threat</th><th>Level</th><th>Score</th><th>Hits</th><th>Apps</th><th>Network</th><th>Last seen</th></tr></thead><tbody id="threatTable"></tbody></table></div>
      <div class="view-note" style="margin-top:8px">Click an attacker to open investigation details. Showing the highest-ranked active attackers from the dashboard snapshot.</div>
    </section>
    <section class="panel" style="margin-top:12px"><div class="panel-head"><div><div class="section-kicker">Durable intelligence</div><h2>Lifetime offenders</h2></div></div><div class="table-wrap"><table><thead><tr><th>Threat</th><th>Max level</th><th>Lifetime hits</th><th>Apps</th><th>Categories</th><th>First seen</th><th>Last seen</th></tr></thead><tbody id="lifetimeTable"></tbody></table></div></section>
  </section>

  <section id="view-enforcement" class="view">
    <div class="view-head"><div><h1 class="view-title">Enforcement</h1><div class="view-note">Approval stays manual. Applied Cloudflare rules expire and are removed automatically.</div></div></div>
    <div id="enforcementMetrics" class="metrics"></div>
    <div class="grid equal">
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Pending response</div><h2>Response recommendations</h2></div></div><div id="responses"></div></section>
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Applied rules</div><h2>Active Cloudflare enforcement</h2></div></div><div id="activeEnforcement"></div></section>
    </div>
    <div class="grid equal">
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Guardrails</div><h2>Response policy</h2></div></div><div id="responsePolicy"></div></section>
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Audit trail</div><h2>Recent response history</h2></div><button id="refreshHistory" class="panel-link" type="button">Refresh</button></div><div id="responseHistory"><div class="empty">Open this tab to load recent expired, dismissed, and failed recommendations.</div></div></section>
    </div>
  </section>

  <section id="view-network" class="view">
    <div class="view-head"><div><h1 class="view-title">Network intelligence</h1><div class="view-note">Context only. Geography and provider attribution never change Hotpot threat scores.</div></div></div>
    <div class="grid equal">
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Providers</div><h2>Top networks / ASNs</h2></div></div><div id="networks"></div></section>
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Geography</div><h2>Top countries</h2></div></div><div id="countries"></div></section>
    </div>
    <div class="grid thirds">
      <section class="panel"><div class="panel-head"><h2>Top paths</h2></div><div id="paths"></div></section>
      <section class="panel"><div class="panel-head"><h2>Categories</h2></div><div id="categories"></div></section>
      <section class="panel"><div class="panel-head"><h2>Scanners</h2></div><div id="scanners"></div></section>
    </div>
  </section>

  <section id="view-operations" class="view">
    <div class="view-head"><div><h1 class="view-title">Operations</h1><div class="view-note">Instance health, database durability, retention, and GeoIP attribution.</div></div></div>
    <section class="panel"><div class="panel-head"><div><div class="section-kicker">Instances</div><h2>Protected applications</h2></div></div><div id="apps" class="app-strip"></div></section>
    <div class="grid equal">
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Storage & maintenance</div><h2>Operational health</h2></div></div><div id="system"></div></section>
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Attribution</div><h2>GeoIP / attribution</h2></div></div><div id="geoip"></div></section>
    </div>
    <div class="grid equal">
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Telemetry</div><h2>Dashboard counters</h2></div></div><div id="opsCounters"></div></section>
      <section class="panel"><div class="panel-head"><div><div class="section-kicker">Builds</div><h2>Instance versions</h2></div></div><div id="versions"></div></section>
    </div>
  </section>
</main>
</div>
<div id="drawerBackdrop" class="drawer-backdrop"></div>
<aside id="threatDrawer" class="drawer" aria-hidden="true"><div class="drawer-head"><div><div class="section-kicker">Threat investigation</div><div id="drawerTitle" class="drawer-title">Attacker</div><div id="drawerSubtitle" class="muted"></div></div><button id="drawerClose" class="drawer-close" type="button" aria-label="Close">×</button></div><div id="drawerBody" class="drawer-body"></div></aside>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const attr=esc;
const fmt=n=>new Intl.NumberFormat().format(Number(n||0));
const age=s=>{if(s==null)return 'n/a';s=Math.max(0,Number(s)||0);if(s<120)return Math.round(s)+'s';if(s<7200)return Math.round(s/60)+'m';if(s<172800)return (s/3600).toFixed(1)+'h';return (s/86400).toFixed(1)+'d'};
const when=v=>v?new Date(v).toLocaleString():'never';
const shortWhen=v=>v?new Date(v).toLocaleString([], {month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}):'never';
const timeLeft=v=>{if(!v)return 'n/a';const ms=new Date(v)-Date.now();if(ms<=0)return 'due now';const h=ms/3600000;if(h<1)return Math.ceil(ms/60000)+'m';if(h<48)return h.toFixed(h<10?1:0)+'h';return (h/24).toFixed(1)+'d'};
let snapshot=null;
let historyLoadedAt=0;
let currentDrawerKey=null;

function responseAction(a){return ({watch:'Watch',recommend_challenge:'Managed challenge',recommend_block:'Block 24h',recommend_long_block:'Long block'})[a]||a||'Unknown'}
function sourceName(o){return o?.source_type==='cloudflare-worker'?'Cloudflare Worker · '+(o.worker_zone||'legacy/unknown zone'):(o?.identity_key||o?.actor_key||o?.ip||o?.client_ip||'unknown')}
function levelClass(level){level=Math.max(1,Math.min(4,Number(level)||1));return 'l'+level}
function levelBadge(level,label){level=Math.max(1,Math.min(4,Number(level)||1));return `<span class="badge ${levelClass(level)}">${esc(label||('L'+level))}</span>`}
function networkText(o){const n=o?.network||{};const bits=[];if(n.asn)bits.push('AS'+n.asn);if(n.provider)bits.push(n.provider);if(n.country)bits.push(n.country);else if(n.country_code)bits.push(n.country_code);if(n.city)bits.push(n.city);return bits.join(' · ')||'Unattributed'}
function actorApps(o){const values=o?.apps||[];return values.map(v=>typeof v==='string'?v:(v.instance_name||v.instance_id||'')).filter(Boolean)}
function empty(message){return `<div class="empty">${esc(message)}</div>`}
function compactList(rows,key){return (rows||[]).slice(0,12).map(x=>`<div class="list-row"><div class="list-main"><div class="list-title">${esc(x[key])}</div></div><div class="list-count">${fmt(x.hits)}</div></div>`).join('')||empty('No data yet')}
function viewName(){const h=location.hash.replace('#','');return ['overview','threats','enforcement','network','operations'].includes(h)?h:'overview'}

function showView(name,{updateHash=true}={}){
  if(!['overview','threats','enforcement','network','operations'].includes(name))name='overview';
  document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id==='view-'+name));
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.view===name));
  if(updateHash&&location.hash!=='#'+name)history.replaceState(null,'','#'+name);
  try{localStorage.setItem('hotpot:view',name)}catch(e){}
  if(name==='enforcement')loadResponseHistory(false);
}

async function actionRequest(id,verb){
  const r=await fetch('/api/recommendation/'+encodeURIComponent(id)+'/'+verb,{method:'POST',headers:{'X-Hotpot-Action':verb}});
  let body=null;try{body=await r.json()}catch(e){}
  if(!r.ok){const msg=body?.enforcement_error||body?.error||body?.message||await r.text().catch(()=>null)||('HTTP '+r.status);alert(verb[0].toUpperCase()+verb.slice(1)+' failed: '+msg);return false}
  return true;
}
async function dismissRec(id){if(!confirm('Dismiss this recommendation for the configured cooldown?'))return;if(await actionRequest(id,'dismiss')){await load();await loadResponseHistory(true)}}
async function approveRec(id,label,target,duration){if(!confirm('Approve Cloudflare '+label+' for '+duration+' hours?\n\nTarget: '+target+'\n\nHotpot will create temporary WAF rule(s) only for configured protected hostnames and automatically remove them at expiry.'))return;if(await actionRequest(id,'approve')){await load();await loadResponseHistory(true)}}
async function removeRec(id){if(!confirm('Remove these Hotpot Cloudflare rules now?'))return;if(await actionRequest(id,'remove')){await load();await loadResponseHistory(true)}}

function recommendationCard(x,cf,compact=false){
  const e=x.evidence||{};const level=Number(e.global_level||1);const actor=sourceName({...e,identity_key:x.actor_key});
  const enforceable=['recommend_challenge','recommend_block','recommend_long_block'].includes(x.action);const target=x.target_type==='cloudflare-worker-zone'?'Worker zone '+(x.target_value||''):(x.target_value||'none');
  const approve=enforceable&&cf.configured?`<button class="btn primary" data-rec-action="approve" data-id="${attr(x.recommendation_id)}" data-label="${attr(responseAction(x.action))}" data-target="${attr(target)}" data-duration="${Number(x.duration_hours||0)}" type="button">Approve</button>`:enforceable?'<span class="muted">Cloudflare not configured</span>':'';
  const cls=level>=4?'l4':level>=3?'l3':'';const cats=(e.categories||[]).slice(0,compact?2:4).join(', ');
  return `<article class="attention-card ${cls}"><div class="attention-top"><div><div class="actor">${esc(actor)}</div><div class="meta-line">${levelBadge(level)} <strong>${esc(responseAction(x.action))}</strong> · score ${fmt(e.global_score)} · ${fmt(e.observed_hits)} hits · ${fmt(e.app_count)} apps</div></div><span class="badge ${x.confidence==='high'?'high':x.confidence==='medium'?'medium':'neutral'}">${esc(x.confidence||'')}</span></div>${!compact&&cats?`<div class="meta-line">${esc(cats)}</div>`:''}<div class="meta-line">Target: ${esc(target)}${x.duration_hours?' · '+fmt(x.duration_hours)+'h':''}</div><div class="actions"><button class="btn ghost" data-open-threat="${attr(x.actor_key)}" type="button">Review</button>${approve}<button class="btn ghost" data-rec-action="dismiss" data-id="${attr(x.recommendation_id)}" type="button">Dismiss</button></div></article>`;
}
function enforcementCard(x,compact=false){
  const target=x.target_type==='cloudflare-worker-zone'?'Worker zone '+(x.target_value||''):(x.target_value||'unknown');const ruleCount=(x.enforcement_rules||[]).length;
  return `<article class="enforcement-card"><div class="compact-top"><div><div class="actor">${esc(x.actor_key)}</div><div class="meta-line"><span class="badge applied">Applied</span> <strong>${esc(responseAction(x.action))}</strong></div></div><div class="muted">${esc(timeLeft(x.enforcement_expires_at))}</div></div><div class="meta-line">${esc(target)} · ${fmt(ruleCount)} Cloudflare rule${ruleCount===1?'':'s'} · expires ${esc(shortWhen(x.enforcement_expires_at))}</div>${x.enforcement_error?`<div class="danger meta-line">Removal error: ${esc(x.enforcement_error)}</div>`:''}<div class="actions"><button class="btn ghost" data-open-threat="${attr(x.actor_key)}" type="button">Review</button>${compact?'':`<button class="btn danger" data-rec-action="remove" data-id="${attr(x.recommendation_id)}" type="button">Remove now</button>`}</div></article>`;
}

function renderHeader(d){
  const s=d.summary||{},apps=d.apps||[],healthy=Number(s.healthy_apps||0),total=Number(s.protected_apps||apps.length||0);const bad=total>0&&healthy<total;
  const hb=document.getElementById('healthBadge');hb.className='status-chip '+(bad?'bad':'ready');hb.innerHTML=`<span class="dot ${bad?'down':'ok'}"></span>${bad?healthy+'/'+total+' healthy':'Healthy'}`;
  const cf=d.response?.enforcement||{};const cb=document.getElementById('cloudflareBadge');cb.className='status-chip '+(cf.configured?'ready':'alert');cb.textContent=cf.applied?`${fmt(cf.applied)} active Cloudflare rule${Number(cf.applied)===1?'':'s'}`:(cf.configured?'Cloudflare ready':'Cloudflare not configured');
  document.getElementById('updated').textContent='Updated '+new Date(d.generated_at).toLocaleTimeString();
}
function renderOverview(d){
  const s=d.summary||{},rr=d.response||{},cf=rr.enforcement||{},pending=rr.recommendations||[],active=rr.active_enforcements||[];const apps=Number(s.protected_apps||0),healthy=Number(s.healthy_apps||0);
  const cards=[
    {label:'Active threats',value:fmt(s.level3_plus||0),sub:`${fmt(s.global_level4||0)} at L4`,class:(s.global_level4||0)?'degraded':''},
    {label:'Needs action',value:fmt(s.response_pending||0),sub:`Pending response · ${fmt(s.response_high_priority||0)} high priority`,class:(s.response_pending||0)?'attention':''},
    {label:'Cloudflare',value:fmt(s.response_applied||0),sub:`Applied rules · ${cf.configured?'ready':'not configured'}`,class:(s.response_applied||0)?'enforced':''},
    {label:'Instances',value:`${fmt(healthy)}/${fmt(apps)}`,sub:`${apps&&healthy===apps?'All healthy':'Protected applications'}`,class:apps&&healthy<apps?'degraded':''}
  ];
  document.getElementById('overviewMetrics').innerHTML=cards.map(c=>`<div class="metric-card ${c.class}"><div class="metric-label">${esc(c.label)}</div><div class="metric-value">${esc(c.value)}</div><div class="metric-sub">${esc(c.sub)}</div></div>`).join('');
  document.getElementById('overviewAttention').innerHTML=pending.slice(0,4).map(x=>recommendationCard(x,cf,true)).join('')||empty('Nothing requires approval right now.');
  document.getElementById('overviewEnforcement').innerHTML=active.slice(0,4).map(x=>enforcementCard(x,true)).join('')||empty(cf.configured?'No temporary Cloudflare rules are active.':'Cloudflare enforcement is not configured.');
  document.getElementById('overviewRecent').innerHTML=(d.recent||[]).slice(0,8).map(e=>`<tr><td>${esc(shortWhen(e.ts))}</td><td><span class="cell-main">${esc(e.instance_name)}</span></td><td>${esc(e.client_ip)}</td><td>${esc(e.category)}</td><td><code>${esc(e.path)}</code></td><td>${esc(e.action)}</td></tr>`).join('')||'<tr><td colspan="6" class="muted">No recent activity</td></tr>';
  document.getElementById('overviewApps').innerHTML=renderAppChips(d.apps||[],true);
}
function renderAppChips(apps,compact=false){return apps.map(a=>`<div class="app-chip"><div class="app-name"><span class="dot ${a.healthy?'ok':'down'}"></span>${esc(a.name)}</div><div class="app-sub">${a.healthy?'Ready':esc(a.error||a.upstream_health?.error||'Unavailable')}</div><div class="app-sub">${fmt(a.events)} events · ${fmt(a.unique_ips)} attackers${compact?'':' · '+fmt(a.tarpits_active)+' tarpits'}</div>${compact?'':`<div class="app-sub">${esc(a.version||'unknown')} · ${esc((a.git_sha||'unknown').slice(0,7))}</div>`}</div>`).join('')||empty('No applications configured')}

function renderThreats(d){
  const appSelect=document.getElementById('threatApp');const prior=appSelect.value;const names=(d.apps||[]).map(a=>a.name);appSelect.innerHTML='<option value="">All apps</option>'+names.map(n=>`<option value="${attr(n)}">${esc(n)}</option>`).join('');if(names.includes(prior))appSelect.value=prior;
  renderThreatTables();
}
function threatMatches(o){
  const q=(document.getElementById('threatSearch').value||'').trim().toLowerCase();const min=Number(document.getElementById('threatLevel').value||0);const app=document.getElementById('threatApp').value;const level=Number(o.global_level||o.level||o.max_global_level||1);if(min&&level<min)return false;if(app&&!actorApps(o).includes(app))return false;if(!q)return true;
  const hay=[sourceName(o),networkText(o),...(actorApps(o)),...(o.categories||[]).map(v=>typeof v==='string'?v:(v.category||''))].join(' ').toLowerCase();return hay.includes(q);
}
function renderThreatTables(){if(!snapshot)return;
  const active=(snapshot.top_offenders||[]).filter(threatMatches);document.getElementById('threatTable').innerHTML=active.map(o=>{const level=Number(o.global_level||o.level||1),apps=actorApps(o);return `<tr class="clickable" data-open-threat="${attr(o.identity_key||o.ip)}"><td><div class="cell-main">${esc(sourceName(o))}</div><div class="cell-sub">${o.source_type==='cloudflare-worker'?esc(o.client_ip||'Cloudflare shared address'):''}</div></td><td class="level-cell">${levelBadge(level)}</td><td>${fmt(o.global_score||o.score)}</td><td>${fmt(o.hits)}</td><td><div class="cell-main">${fmt(o.app_count)}</div><div class="cell-sub">${esc(apps.slice(0,2).join(', '))}</div></td><td><div class="cell-main">${esc(networkText(o))}</div></td><td>${esc(shortWhen(o.last_seen))}</td></tr>`}).join('')||'<tr><td colspan="7" class="muted">No threats match the current filters.</td></tr>';
  const lifetime=(snapshot.top_lifetime_offenders||[]).filter(threatMatches);document.getElementById('lifetimeTable').innerHTML=lifetime.map(o=>`<tr class="clickable" data-open-threat="${attr(o.identity_key||o.ip)}"><td><div class="cell-main">${esc(sourceName(o))}</div><div class="cell-sub">${esc(networkText(o))}</div></td><td>${levelBadge(o.max_global_level||o.global_level||1)}</td><td>${fmt(o.lifetime_hits||o.hits)}</td><td>${fmt(o.app_count)}</td><td>${fmt(o.category_count)}</td><td>${esc(shortWhen(o.first_seen))}</td><td>${esc(shortWhen(o.last_seen))}</td></tr>`).join('')||'<tr><td colspan="7" class="muted">No lifetime threats match the current filters.</td></tr>';
}

function renderResponses(d){
  const rr=d.response||{},rows=rr.recommendations||[],p=rr.policy||{},cf=rr.enforcement||{},active=rr.active_enforcements||[],failures=rr.recent_failures||[];
  document.getElementById('responses').innerHTML=rows.map(x=>recommendationCard(x,cf,false)).join('')||empty('No active recommendations');
  document.getElementById('activeEnforcement').innerHTML=active.map(x=>enforcementCard(x,false)).join('')||empty('No active Cloudflare enforcement');
  document.getElementById('enforcementMetrics').innerHTML=[
    ['Pending response',rows.length,`${fmt((rr.summary||{}).high_priority||0)} high priority`],
    ['Applied rules',cf.applied||active.length,`${fmt(cf.overdue_removal||0)} overdue removal`],
    ['Failed approvals',cf.failed||failures.length,`${fmt(cf.removal_errors||0)} removal errors`],
    ['Cloudflare',cf.configured?'Ready':'Setup',`${fmt(cf.target_instances)} instances · ${fmt(cf.zones)} zones`]
  ].map(x=>`<div class="metric-card"><div class="metric-label">${esc(x[0])}</div><div class="metric-value">${esc(x[1])}</div><div class="metric-sub">${esc(x[2])}</div></div>`).join('');
  document.getElementById('responsePolicy').innerHTML=`<div class="kv"><div>Mode</div><div>${p.enabled?'Approval required':'Disabled'}</div><div>Cloudflare</div><div class="${cf.configured?'good':'warn'}">${cf.configured?'Ready':'Not configured'}</div><div>Token</div><div>${cf.token_configured?'Configured':'Missing'}</div><div>Target mappings</div><div>${fmt(cf.target_instances)} instances · ${fmt(cf.zones)} zones</div><div>Active window</div><div>${fmt(p.active_window_hours)} hours</div><div>Stale after</div><div>${fmt(p.stale_minutes)} minutes</div><div>Automatic enforcement</div><div>Off — approval required</div><div>Automatic expiry/removal</div><div>On</div><div>Network/geography scoring</div><div>Off</div></div>${failures.length?`<div class="danger meta-line" style="margin-top:12px">Latest failure: ${esc(failures[0].enforcement_error||'Cloudflare apply failed')}</div>`:''}`;
}
async function loadResponseHistory(force=false){
  const now=Date.now();if(!force&&historyLoadedAt&&now-historyLoadedAt<60000)return;historyLoadedAt=now;const target=document.getElementById('responseHistory');target.innerHTML='<div class="empty">Loading response history…</div>';
  try{const statuses=['expired','dismissed','failed'];const payloads=await Promise.all(statuses.map(async status=>{const r=await fetch('/api/recommendations?status='+status+'&limit=20',{cache:'no-store'});if(!r.ok)throw new Error(status+' '+r.status);return [status,await r.json()]}));const rows=[];for(const [status,p] of payloads)for(const x of (p.recommendations||[]))rows.push({...x,_historyStatus:status});rows.sort((a,b)=>String(b.removed_at||b.dismissed_at||b.updated_at||b.expires_at||b.created_at||'').localeCompare(String(a.removed_at||a.dismissed_at||a.updated_at||a.expires_at||a.created_at||'')));target.innerHTML=rows.slice(0,30).map(x=>`<div class="history-row"><div class="history-status"><span class="badge ${x._historyStatus==='failed'?'high':'neutral'}">${esc(x._historyStatus)}</span></div><div class="history-actor">${esc(x.actor_key)}</div><div>${esc(responseAction(x.action))}</div><div class="muted">${esc(shortWhen(x.removed_at||x.dismissed_at||x.updated_at||x.expires_at||x.created_at))}</div></div>`).join('')||empty('No response history yet.');}
  catch(e){target.innerHTML='<div class="empty danger">Could not load response history.</div>';historyLoadedAt=0}
}

function renderNetwork(d){
  document.getElementById('networks').innerHTML=(d.network_intelligence?.top_networks||[]).map(n=>{const detail=n.asn!=null?'/api/network?asn='+encodeURIComponent(n.asn):'/api/network?provider='+encodeURIComponent(n.provider||'');const apps=(n.top_apps||[]).slice(0,3).map(x=>x.instance_name).join(', ');const cats=(n.top_categories||[]).slice(0,3).map(x=>x.category).join(', ');return `<div class="list-row"><div class="list-main"><div class="list-title">${n.asn!=null?'AS'+esc(n.asn)+' · ':''}${esc(n.provider||'Unknown provider')}</div><div class="list-meta">${fmt(n.attackers)} attackers · ${fmt(n.level3_plus)} L3+ · ${fmt(n.level4)} L4${apps?' · '+esc(apps):''}</div>${cats?`<div class="list-meta">Top probes: ${esc(cats)}</div>`:''}</div><div class="list-count"><a href="${esc(detail)}">${fmt(n.hits)} hits</a></div></div>`}).join('')||empty('No attributed networks yet');
  document.getElementById('countries').innerHTML=(d.network_intelligence?.top_countries||[]).map(c=>{const detail='/api/network?country='+encodeURIComponent(c.country_code||'');const apps=(c.top_apps||[]).slice(0,2).map(x=>x.instance_name).join(', ');return `<div class="list-row"><div class="list-main"><div class="list-title">${esc(c.country||c.country_code||'Unknown')}</div><div class="list-meta">${fmt(c.attackers)} attackers · ${fmt(c.level3_plus)} L3+ · ${fmt(c.level4)} L4${apps?' · '+esc(apps):''}</div></div><div class="list-count"><a href="${esc(detail)}">${fmt(c.hits)} hits</a></div></div>`}).join('')||empty('No attributed countries yet');
  document.getElementById('paths').innerHTML=compactList(d.top_paths,'path');document.getElementById('categories').innerHTML=compactList(d.top_categories,'category');document.getElementById('scanners').innerHTML=compactList(d.top_scanners,'scanner');
}
function renderOperations(d){
  const s=d.summary||{},db=d.database||{},hk=db.last_housekeeping||{},g=d.geoip||{},ga=g.attribution||{},gdb=g.databases||{},asn=gdb.asn||{},city=gdb.city||{},country=gdb.country||{},backlog=ga.backlog_is_lower_bound?fmt(ga.backlog_remaining)+'+':fmt(ga.backlog_remaining);
  document.getElementById('apps').innerHTML=renderAppChips(d.apps||[],false);
  document.getElementById('system').innerHTML=`<div class="kv"><div>Raw events</div><div>${fmt(db.raw_events)}</div><div>Retention</div><div>${fmt(db.retention_days)} days</div><div>Database</div><div>${(Number(db.size_bytes||0)/1048576).toFixed(1)} MB · WAL ${(Number(db.wal_size_bytes||0)/1048576).toFixed(1)} MB</div><div>Source resets</div><div>${fmt(db.source_resets)}</div><div>Maintenance errors</div><div class="${db.maintenance_errors?'warn':''}">${fmt(db.maintenance_errors)}</div><div>Last housekeeping</div><div>${esc(when(hk.at))}</div></div>`;
  document.getElementById('geoip').innerHTML=`<div class="kv"><div>Status</div><div>${g.enabled?'Loaded':'Disabled'}${(g.errors||[]).length?' · '+esc((g.errors||[]).join(', ')):''}</div><div>ASN DB age</div><div>${age(asn.age_seconds)}</div><div>City DB age</div><div>${age(city.age_seconds)}${!city.present&&country.present?' (country DB '+age(country.age_seconds)+')':''}</div><div>Last reload</div><div>${esc(when(g.last_reload_at))} · ${fmt(g.reload_count)} reloads</div><div>Attribution</div><div>${fmt(ga.attributed_attackers)}/${fmt(ga.lifetime_attackers)} lifetime attackers</div><div>Backlog</div><div>${backlog}</div><div>Revision</div><div><code>${esc((g.revision||'n/a').slice(0,80))}</code></div></div>`;
  document.getElementById('opsCounters').innerHTML=`<div class="kv"><div>Events</div><div>${fmt(s.events)}</div><div>Unique attackers</div><div>${fmt(s.unique_ips)}</div><div>Active tarpits</div><div>${fmt(s.active_tarpits)}</div><div>Suppressed</div><div>${fmt(s.suppressed_events||0)}</div><div>Global L3+</div><div>${fmt(s.level3_plus||0)}</div><div>Lifetime attackers</div><div>${fmt(s.lifetime_attackers||0)}</div><div>Database MB</div><div>${fmt(s.database_size_mb||0)}</div></div>`;
  document.getElementById('versions').innerHTML=(d.apps||[]).map(a=>`<div class="list-row"><div class="list-main"><div class="list-title">${esc(a.name)}</div><div class="list-meta">${esc(a.version||'unknown')} · ${esc((a.git_sha||'unknown').slice(0,12))}</div></div><div class="list-count"><span class="badge ${a.healthy?'applied':'high'}">${a.healthy?'ready':'down'}</span></div></div>`).join('')||empty('No applications configured');
}

function openDrawer(){document.getElementById('drawerBackdrop').classList.add('open');document.getElementById('threatDrawer').classList.add('open');document.getElementById('threatDrawer').setAttribute('aria-hidden','false');document.body.style.overflow='hidden'}
function closeDrawer(){document.getElementById('drawerBackdrop').classList.remove('open');document.getElementById('threatDrawer').classList.remove('open');document.getElementById('threatDrawer').setAttribute('aria-hidden','true');document.body.style.overflow='';currentDrawerKey=null}
async function openThreat(key){if(!key)return;currentDrawerKey=key;openDrawer();document.getElementById('drawerTitle').textContent=key;document.getElementById('drawerSubtitle').textContent='Loading investigation…';document.getElementById('drawerBody').innerHTML='<div class="skeleton"></div><div class="skeleton" style="margin-top:10px;width:80%"></div><div class="skeleton" style="margin-top:10px;width:55%"></div>';
  try{const r=await fetch('/api/attacker?key='+encodeURIComponent(key),{cache:'no-store'});if(!r.ok)throw new Error('attacker '+r.status);const d=await r.json();if(currentDrawerKey!==key)return;renderThreatDrawer(d)}catch(e){if(currentDrawerKey===key){document.getElementById('drawerSubtitle').textContent='Investigation unavailable';document.getElementById('drawerBody').innerHTML='<div class="empty danger">Could not load attacker details.</div>'}}
}
function renderThreatDrawer(d){
  const level=Number(d.global_level||d.level||1),life=d.lifetime||{},lifeHits=life.lifetime_hits??d.hits??0;document.getElementById('drawerTitle').textContent=sourceName(d);document.getElementById('drawerSubtitle').innerHTML=`${levelBadge(level)} &nbsp; ${esc(networkText(d))}`;
  const rec=(snapshot?.response?.recommendations||[]).find(x=>x.actor_key===(d.identity_key||d.ip));const cf=snapshot?.response?.enforcement||{};const apps=(d.app_activity||[]),cats=(d.category_activity||[]),lifeApps=(life.apps||[]),lifeCats=(life.categories||[]);const recHtml=rec?`<div class="drawer-section"><h4>Response</h4>${recommendationCard(rec,cf,false)}</div>`:'';
  const appRows=(apps.length?apps:lifeApps).slice(0,8).map(x=>`<div class="mini-card"><strong>${esc(x.instance_name||x.instance_id||'App')}</strong><span>${fmt(x.hits??x.lifetime_hits)} hits${x.last_seen?' · last '+esc(shortWhen(x.last_seen)):''}</span></div>`).join('')||'<div class="empty">No application activity</div>';
  const catRows=(cats.length?cats:lifeCats).slice(0,8).map(x=>`<div class="mini-card"><strong>${esc(x.category||'Unknown')}</strong><span>${fmt(x.hits??x.lifetime_hits)} hits${x.max_severity!=null?' · severity '+fmt(x.max_severity):''}</span></div>`).join('')||'<div class="empty">No category activity</div>';
  const recent=(d.recent||[]).slice(0,12).map(e=>`<tr><td>${esc(shortWhen(e.ts))}</td><td>${esc(e.instance_name)}</td><td><code>${esc(e.path)}</code></td><td>${esc(e.category)}</td></tr>`).join('')||'<tr><td colspan="4" class="muted">No retained recent events</td></tr>';
  document.getElementById('drawerBody').innerHTML=`<div class="drawer-metrics"><div class="drawer-metric"><b>${fmt(d.global_score||d.score)}</b><span>Score</span></div><div class="drawer-metric"><b>${fmt(lifeHits)}</b><span>Lifetime hits</span></div><div class="drawer-metric"><b>${fmt(life.app_count??d.app_count)}</b><span>Apps</span></div><div class="drawer-metric"><b>${fmt(life.category_count??d.category_count)}</b><span>Categories</span></div></div><div class="drawer-section"><h4>Identity & network</h4><div class="kv"><div>Identity</div><div>${esc(d.identity_key||d.ip)}</div><div>Observed IP</div><div>${esc(d.client_ip||d.ip||'n/a')}</div><div>Source type</div><div>${esc(d.source_type||'ip')}</div><div>Network</div><div>${esc(networkText(d))}</div><div>First seen</div><div>${esc(when(life.first_seen||d.first_seen))}</div><div>Last seen</div><div>${esc(when(life.last_seen||d.last_seen))}</div></div></div>${recHtml}<div class="drawer-section"><h4>Applications</h4><div class="mini-grid">${appRows}</div></div><div class="drawer-section"><h4>Categories</h4><div class="mini-grid">${catRows}</div></div><div class="drawer-section"><h4>Recent activity</h4><div class="table-wrap"><table><thead><tr><th>Time</th><th>App</th><th>Path</th><th>Category</th></tr></thead><tbody>${recent}</tbody></table></div></div>`;
}

async function load(){try{
  const r=await fetch('/api/overview',{cache:'no-store'});if(!r.ok)throw new Error('overview '+r.status);const d=await r.json();snapshot=d;renderHeader(d);renderOverview(d);renderThreats(d);renderResponses(d);renderNetwork(d);renderOperations(d);
  if(currentDrawerKey)openThreat(currentDrawerKey);
}catch(e){document.getElementById('updated').textContent='Refresh failed';document.getElementById('healthBadge').className='status-chip bad';document.getElementById('healthBadge').innerHTML='<span class="dot down"></span>Dashboard refresh failed'}}

document.addEventListener('click',e=>{
  const tab=e.target.closest('[data-view]');if(tab){showView(tab.dataset.view);return}
  const jump=e.target.closest('[data-jump]');if(jump){showView(jump.dataset.jump);return}
  const open=e.target.closest('[data-open-threat]');if(open){openThreat(open.dataset.openThreat);return}
  const action=e.target.closest('[data-rec-action]');if(action){const verb=action.dataset.recAction;if(verb==='approve')approveRec(action.dataset.id,action.dataset.label,action.dataset.target,Number(action.dataset.duration||0));else if(verb==='dismiss')dismissRec(action.dataset.id);else if(verb==='remove')removeRec(action.dataset.id);return}
});
document.getElementById('drawerClose').addEventListener('click',closeDrawer);document.getElementById('drawerBackdrop').addEventListener('click',closeDrawer);document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer()});
document.getElementById('threatSearch').addEventListener('input',renderThreatTables);document.getElementById('threatLevel').addEventListener('change',renderThreatTables);document.getElementById('threatApp').addEventListener('change',renderThreatTables);document.getElementById('refreshHistory').addEventListener('click',()=>loadResponseHistory(true));
window.addEventListener('hashchange',()=>showView(viewName(),{updateHash:false}));
let initial=viewName();if(!location.hash){try{const saved=localStorage.getItem('hotpot:view');if(['overview','threats','enforcement','network','operations'].includes(saved))initial=saved}catch(e){}}showView(initial,{updateHash:!!location.hash});
load();setInterval(load,15000);
</script>
</body>
</html>'''