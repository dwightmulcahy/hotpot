(()=>{
  let activeCampaignId=null;

  function campaignTable(){return document.getElementById('campaignTable')}
  function markCampaignRows(){
    const table=campaignTable();if(!table)return;
    table.querySelectorAll('tr').forEach(row=>{
      const code=row.querySelector('code');
      const id=(code?.textContent||'').trim();
      if(!id.startsWith('campaign_'))return;
      row.dataset.campaignId=id;
      row.classList.add('clickable');
      row.title='Open campaign investigation';
      row.setAttribute('tabindex','0');
      row.setAttribute('role','button');
    });
  }

  function metric(label,value){
    return `<div class="drawer-metric"><b>${esc(value)}</b><span>${esc(label)}</span></div>`;
  }

  function renderCampaign(d){
    const drawer=document.getElementById('threatDrawer');if(!drawer)return;
    document.getElementById('drawerTitle').textContent=d.label||d.campaign_id||'Attack campaign';
    document.getElementById('drawerSubtitle').textContent=`${d.actor_count||0} actor(s) · ${d.hits||0} hit(s) · last seen ${shortWhen(d.last_seen)}`;
    const actors=(d.actors_detail||[]).map(a=>{
      const ips=(a.observed_ips||[]).join(', ')||'No retained IP';
      const apps=(a.apps||[]).join(', ')||'No retained app';
      return `<button class="mini-card campaign-actor-card" type="button" data-campaign-actor="${attr(a.actor_key||'')}"><strong>${esc(a.actor_key||'unknown')}</strong><span>${esc(ips)} · ${fmt(a.hits||0)} hit(s) · ${esc(apps)}</span></button>`;
    }).join('')||'<div class="empty">No retained actor details.</div>';
    const paths=(d.top_paths||[]).map(p=>`<div class="list-row"><div class="list-main"><div class="list-title"><code>${esc(p.path||'/')}</code></div></div><div class="list-count">${fmt(p.hits||0)} hits</div></div>`).join('')||'<div class="empty">No retained paths.</div>';
    const timeline=(d.timeline||[]).map(x=>{
      const app=x.instance_name?` · ${esc(x.instance_name)}`:'';
      const actor=x.actor_key?` · ${esc(x.actor_key)}`:'';
      const detail=[x.method,x.path,x.category,x.scanner_family||x.scanner].filter(Boolean).map(esc).join(' · ');
      return `<div class="timeline-item campaign"><span class="timeline-dot"></span><div class="timeline-time">${esc(shortWhen(x.ts))}${app}${actor}</div><div class="timeline-title">${levelBadge(x.escalation_level||1)} ${esc(x.action||'activity')}</div><div class="timeline-detail">${detail}${x.hits>1?' · '+fmt(x.hits)+' represented hits':''}</div></div>`;
    }).join('')||'<div class="empty">No retained campaign timeline activity.</div>';
    const fingerprints=(d.fingerprints||[]).map(x=>`<code>${esc(x)}</code>`).join(', ')||'None retained';
    const scanners=(d.scanners||[]).join(', ')||'Pattern correlation';
    const categories=(d.categories||[]).join(', ')||'Uncategorized';
    const note=d.investigation?.note||'Campaign correlation is observational and does not automatically change actor scoring or Cloudflare enforcement.';

    document.getElementById('drawerBody').innerHTML=`
      <div class="drawer-metrics">${metric('Actors',fmt(d.actor_count||0))}${metric('Hits',fmt(d.hits||0))}${metric('Apps',fmt(d.app_count||0))}${metric('Max level','L'+fmt(d.max_level||1))}</div>
      <div class="drawer-section"><h4>Correlation</h4><div class="kv"><div>Campaign ID</div><div><code>${esc(d.campaign_id||'')}</code></div><div>Scanner</div><div>${esc(scanners)}</div><div>Categories</div><div>${esc(categories)}</div><div>Fingerprints</div><div>${fingerprints}</div><div>First seen</div><div>${esc(shortWhen(d.first_seen))}</div><div>Last seen</div><div>${esc(shortWhen(d.last_seen))}</div></div></div>
      <div class="drawer-section"><h4>Participating actors</h4><div class="mini-grid campaign-actors">${actors}</div>${d.actors_detail_truncated?'<div class="view-note" style="margin-top:8px">Actor list truncated.</div>':''}</div>
      <div class="drawer-section"><h4>Top paths</h4>${paths}</div>
      <div class="drawer-section"><h4>Campaign timeline</h4><div class="timeline">${timeline}</div>${d.timeline_truncated?'<div class="view-note" style="margin-top:8px">Timeline truncated to the most recent retained events.</div>':''}</div>
      <div class="drawer-section"><h4>Response policy</h4><div class="attention-card"><div class="meta-line"><strong>Observational only.</strong> ${esc(note)}</div></div></div>`;
  }

  async function openCampaign(id){
    if(!id)return;
    activeCampaignId=id;
    openDrawer();
    document.getElementById('drawerTitle').textContent=id;
    document.getElementById('drawerSubtitle').textContent='Loading campaign investigation…';
    document.getElementById('drawerBody').innerHTML='<div class="skeleton"></div><div class="skeleton" style="margin-top:10px;width:80%"></div><div class="skeleton" style="margin-top:10px;width:55%"></div>';
    try{
      const r=await fetch('/api/campaign/'+encodeURIComponent(id)+'?limit=250',{cache:'no-store'});
      if(!r.ok)throw new Error('campaign '+r.status);
      const d=await r.json();
      const drawer=document.getElementById('threatDrawer');
      if(activeCampaignId!==id||!drawer?.classList.contains('open'))return;
      renderCampaign(d);
    }catch(e){
      if(activeCampaignId===id){
        document.getElementById('drawerSubtitle').textContent='Campaign investigation unavailable';
        document.getElementById('drawerBody').innerHTML='<div class="empty danger">Could not load campaign details.</div>';
      }
    }
  }

  function activateRow(row){const id=row?.dataset?.campaignId;if(id)openCampaign(id)}

  document.addEventListener('click',e=>{
    const actor=e.target.closest('[data-campaign-actor]');
    if(actor){e.preventDefault();e.stopPropagation();const key=actor.dataset.campaignActor;if(key)openThreat(key);return}
    const row=e.target.closest('#campaignTable tr[data-campaign-id]');
    if(row)activateRow(row);
  });
  document.addEventListener('keydown',e=>{
    if(e.key!=='Enter'&&e.key!==' ')return;
    const row=e.target.closest?.('#campaignTable tr[data-campaign-id]');
    if(!row)return;e.preventDefault();activateRow(row);
  });

  function attach(){
    const table=campaignTable();if(!table)return false;
    markCampaignRows();
    new MutationObserver(markCampaignRows).observe(table,{childList:true,subtree:true});
    return true;
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>{if(!attach())setTimeout(attach,250)});else if(!attach())setTimeout(attach,250);
})();

(()=>{
  let metricWindow='1h',metricPayload=null;
  const metricDefs=[
    ['Request rate','request_rate_per_minute','/min'],
    ['L4 activity','level4_total',''],
    ['Queue depth','telemetry_queue_depth',''],
    ['Spool pending','notification_spool_pending',''],
    ['Upstream saturation','resource_upstream_saturation','%'],
    ['Upstream latency','upstream_latency_ms','ms']
  ];

  function ensureMetricPanel(){
    if(document.getElementById('hotpotMetricTrends'))return;
    const view=document.getElementById('view-operations');if(!view)return;
    const apps=document.getElementById('apps')?.closest('section.panel');
    const panel=document.createElement('section');panel.id='hotpotMetricTrends';panel.className='panel';panel.style.marginTop='12px';
    panel.innerHTML='<div class="panel-head"><div><div class="section-kicker">Operational telemetry</div><h2>Health & traffic trends</h2></div><div class="actions" style="margin-top:0"><button class="btn ghost" data-metric-window="1h">1h</button><button class="btn ghost" data-metric-window="24h">24h</button><button class="btn ghost" data-metric-window="7d">7d</button></div></div><div id="metricTrendGrid" class="mini-grid"><div class="empty">Collecting trend samples…</div></div><div id="metricTrendNote" class="view-note" style="margin-top:9px"></div>';
    if(apps)apps.insertAdjacentElement('afterend',panel);else view.prepend(panel);
  }

  function sparkline(values){
    const width=180,height=42,pad=3;
    if(!values.length)return '<div class="empty">No samples</div>';
    const nums=values.map(v=>Number(v)||0),min=Math.min(...nums),max=Math.max(...nums),span=Math.max(1e-9,max-min);
    const points=nums.map((v,i)=>`${pad+(i*(width-pad*2))/Math.max(1,nums.length-1)},${height-pad-((v-min)*(height-pad*2))/span}`).join(' ');
    return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="trend" style="width:100%;height:42px"><polyline points="${points}" fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`;
  }

  function displayValue(key,value,suffix){
    const n=Number(value)||0;
    if(suffix==='%')return (n*100).toFixed(1)+'%';
    if(suffix==='ms')return n.toFixed(1)+' ms';
    if(suffix==='/min')return n.toFixed(2)+'/min';
    return fmt(Math.round(n));
  }

  function renderMetricTrends(){
    ensureMetricPanel();const target=document.getElementById('metricTrendGrid');if(!target||!metricPayload)return;
    const windowData=metricPayload.windows?.[metricWindow]||{},samples=windowData.samples||[],latest=windowData.latest||{};
    target.innerHTML=metricDefs.map(([label,key,suffix])=>`<div class="mini-card"><strong>${esc(label)}</strong><span>${esc(displayValue(key,latest[key],suffix))} · ${fmt(windowData.points||0)} samples</span><div style="margin-top:8px;color:var(--info)">${sparkline(samples.map(x=>x[key]))}</div></div>`).join('');
    const note=document.getElementById('metricTrendNote');if(note)note.textContent=`${metricWindow} view · ${metricPayload.retention_days||8} day retention · collector errors ${fmt(metricPayload.collector_errors||0)}`;
    document.querySelectorAll('[data-metric-window]').forEach(button=>button.classList.toggle('primary',button.dataset.metricWindow===metricWindow));
  }

  async function loadMetricTrends(){
    ensureMetricPanel();
    try{
      const r=await fetch('/api/metrics/trends',{cache:'no-store'});if(!r.ok)throw new Error('metrics '+r.status);metricPayload=await r.json();renderMetricTrends();
    }catch(e){const target=document.getElementById('metricTrendGrid');if(target)target.innerHTML='<div class="empty danger">Could not load operational trends.</div>'}
  }

  document.addEventListener('click',e=>{const button=e.target.closest('[data-metric-window]');if(!button)return;metricWindow=button.dataset.metricWindow||'1h';renderMetricTrends()});
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',loadMetricTrends);else loadMetricTrends();
  setInterval(loadMetricTrends,30000);
})();

(()=>{
  function addPlanButtons(d){
    const rows=(d.response||{}).recommendations||[];
    const cards=[...document.querySelectorAll('#responses .attention-card')];
    cards.forEach((card,index)=>{
      const row=rows[index]||{};
      if(!['recommend_challenge','recommend_block','recommend_long_block'].includes(row.action))return;
      const actions=card.querySelector('.actions');if(!actions||actions.querySelector('[data-plan-rec]'))return;
      const button=document.createElement('button');button.className='btn ghost';button.type='button';button.dataset.planRec=row.recommendation_id||'';button.textContent='Preview rule';
      const approve=actions.querySelector('[data-rec-action="approve"]');
      if(approve)actions.insertBefore(button,approve);else actions.prepend(button);
    });
  }

  function renderPlan(plan){
    openDrawer();
    document.getElementById('drawerTitle').textContent='Cloudflare enforcement preview';
    document.getElementById('drawerSubtitle').textContent=`${plan.cloudflare_action||'action'} · ${plan.zone_count||0} zone(s) · simulation only`;
    const zones=(plan.zones||[]).map(zone=>`<div class="attention-card"><div class="meta-line"><strong>Zone</strong> ${esc(zone.zone_id||'')}</div><div class="meta-line"><strong>Hosts</strong> ${esc((zone.hosts||[]).join(', '))}</div><div class="meta-line"><strong>Action</strong> ${esc(zone.action||'')}</div><div class="meta-line"><strong>Reference</strong> <code>${esc(zone.ref||'')}</code></div><div style="margin-top:8px"><code style="white-space:pre-wrap;word-break:break-word">${esc(zone.expression||'')}</code></div><div class="meta-line">${esc(zone.expected_effect||'')}</div></div>`).join('')||'<div class="empty">No zone rules would be created.</div>';
    document.getElementById('drawerBody').innerHTML=`<div class="attention-card"><div class="meta-line"><strong>No writes performed.</strong> ${esc(plan.note||'Simulation only.')}</div></div><div class="drawer-section"><h4>Target</h4><div class="kv"><div>Actor</div><div>${esc(plan.actor_key||plan.target_value||'')}</div><div>Target type</div><div>${esc(plan.target_type||'')}</div><div>Recommendation</div><div>${esc(plan.recommendation_action||'')}</div><div>Cloudflare action</div><div>${esc(plan.cloudflare_action||'')}</div><div>Duration</div><div>${esc(plan.duration_hours??'')}h</div><div>Expiry</div><div>${esc(plan.expires_at||'computed when approved')}</div></div></div><div class="drawer-section"><h4>Exact proposed rules</h4>${zones}</div>`;
  }

  async function previewPlan(id){
    if(!id)return;
    openDrawer();document.getElementById('drawerTitle').textContent='Cloudflare enforcement preview';document.getElementById('drawerSubtitle').textContent='Building non-writing plan…';document.getElementById('drawerBody').innerHTML='<div class="skeleton"></div><div class="skeleton" style="margin-top:10px;width:75%"></div>';
    try{
      const r=await fetch('/api/recommendation/'+encodeURIComponent(id)+'/plan',{cache:'no-store'});let body={};try{body=await r.json()}catch(e){}
      if(!r.ok)throw new Error(body.message||body.error||('HTTP '+r.status));renderPlan(body);
    }catch(e){document.getElementById('drawerSubtitle').textContent='Preview unavailable';document.getElementById('drawerBody').innerHTML='<div class="empty danger">'+esc(e.message)+'</div>'}
  }

  const previousRenderResponses=renderResponses;
  renderResponses=function(d){previousRenderResponses(d);addPlanButtons(d)};
  document.addEventListener('click',e=>{const button=e.target.closest('[data-plan-rec]');if(button){e.preventDefault();previewPlan(button.dataset.planRec)}});
})();
