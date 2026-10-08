(()=>{
  const baseThreatDrawer=renderThreatDrawer;
  renderThreatDrawer=function(d){
    baseThreatDrawer(d);
    const body=document.getElementById('drawerBody');
    const rows=d.timeline||[];
    const section=document.createElement('div');section.className='drawer-section';
    const items=rows.map(x=>{
      const principal=x.principal?`<div class="timeline-principal">${esc(x.source||'dashboard')} · ${esc(x.principal)}</div>`:'';
      const level=x.level?` ${levelBadge(x.level)}`:'';
      const app=x.instance_name?` · ${esc(x.instance_name)}`:'';
      return `<div class="timeline-item ${esc(x.kind||'audit')}"><span class="timeline-dot"></span><div class="timeline-time">${esc(shortWhen(x.ts))}${app}</div><div class="timeline-title">${esc(x.title||x.event_type||'Activity')}${level}</div><div class="timeline-detail">${esc(x.detail||'')}</div>${principal}</div>`;
    }).join('');
    section.innerHTML=`<h4>Investigation timeline</h4><div class="timeline">${items||'<div class="empty">No retained timeline activity</div>'}</div>`;
    const responseSection=[...body.querySelectorAll('.drawer-section')].find(el=>el.querySelector('h4')?.textContent==='Response');
    if(responseSection)responseSection.insertAdjacentElement('afterend',section);else body.appendChild(section);
  };

  let notificationLoadedAt=0,notificationLoading=false;
  function ensureNotificationPanel(){
    if(document.getElementById('notificationCenter'))return;
    const anchor=document.getElementById('systemCheck')?.closest('section.panel');if(!anchor)return;
    const panel=document.createElement('section');panel.className='panel';panel.style.marginTop='12px';
    panel.innerHTML='<div class="panel-head"><div><div class="section-kicker">Meaningful alerts</div><h2>Notification center</h2></div><div class="actions" style="margin-top:0"><button id="sendTestNotification" class="btn ghost" type="button">Send test</button><button id="refreshNotifications" class="panel-link" type="button">Refresh</button></div></div><div id="notificationRoutingSummary" class="meta-line" style="margin-bottom:9px"></div><div id="notificationCenter"><div class="empty">Loading notification state…</div></div>';
    anchor.insertAdjacentElement('afterend',panel);
    document.getElementById('refreshNotifications').addEventListener('click',()=>loadNotificationCenter(true));
    document.getElementById('sendTestNotification').addEventListener('click',sendTestNotification);
  }

  async function sendTestNotification(){
    const button=document.getElementById('sendTestNotification');
    if(!confirm('Send a test notification through every configured external channel?'))return;
    button.disabled=true;button.textContent='Sending…';
    try{
      const r=await fetch('/api/notifications/test',{method:'POST',headers:{'X-Hotpot-Action':'notification-test'}});
      let body={};try{body=await r.json()}catch(e){}
      if(!r.ok)throw new Error(body.error||body.message||('HTTP '+r.status));
      alert('Test notification delivered through: '+((body.channels||[]).join(', ')||'none'));
      await loadNotificationCenter(true);
    }catch(e){alert('Test notification failed: '+e.message)}
    finally{button.disabled=false;button.textContent='Send test'}
  }

  async function loadNotificationCenter(force=false){
    ensureNotificationPanel();const target=document.getElementById('notificationCenter');if(!target||notificationLoading)return;
    const now=Date.now();if(!force&&notificationLoadedAt&&now-notificationLoadedAt<12000)return;notificationLoading=true;
    try{
      const r=await fetch('/api/notifications?limit=30',{cache:'no-store'});if(!r.ok)throw new Error('notifications '+r.status);const d=await r.json();notificationLoadedAt=Date.now();
      const c=d.config||{},channels=c.channels||[],rows=d.notifications||[],routing=d.routing||{},health=d.delivery_health||{};
      const mode=c.enabled?(channels.length?`Delivery active · ${channels.join(' + ')}`:'Enabled, but no delivery channel configured'):'External delivery off · recording important events locally';
      const route=k=>((routing[k]||{}).active||[]).join('+')||'dashboard only';
      document.getElementById('notificationRoutingSummary').textContent='Routing: critical → '+route('critical')+' · warning → '+route('warning')+' · info → '+route('info')+(health.last_success_at?' · last success '+shortWhen(health.last_success_at):'')+(health.last_failure_at?' · last failure '+shortWhen(health.last_failure_at):'');
      const header=`<div class="reconcile-summary"><span class="badge ${c.enabled&&channels.length?'pass':'neutral'}">${c.enabled&&channels.length?'active':'local only'}</span><span class="muted">${esc(mode)} · retry ${esc(age(c.retry_seconds||0))}${d.processing_errors?' · '+fmt(d.processing_errors)+' processing error(s)':''}</span></div>`;
      const policy='<div class="meta-line" style="margin-bottom:9px">Alerts: L4 recommendations, high-confidence L3 challenges, Cloudflare apply/removal failures, drift/missing/orphan rules, unhealthy instances, and failed system checks. Routine L1/L2 probes are ignored.</div>';
      const list=rows.map(x=>`<div class="notify-row"><div><span class="badge ${esc(x.severity||'info')}">${esc(x.severity||'info')}</span><div style="margin-top:4px"><span class="badge ${esc(x.status||'recorded')}">${esc(x.status||'recorded')}</span></div></div><div><div class="notify-subject">${esc(x.subject)}</div><div class="cell-sub">${esc(shortWhen(x.created_at))}${x.actor_key?' · '+esc(x.actor_key):''}</div></div><div class="notify-message">${esc(x.message||'')}${x.last_error?'<div class="danger" style="margin-top:3px">'+esc(x.last_error)+'</div>':''}</div><div class="muted">${esc((x.channels||[]).join(', ')||'local')}</div></div>`).join('')||'<div class="empty">No meaningful alert events have been recorded yet.</div>';
      target.innerHTML=header+policy+list;
    }catch(e){target.innerHTML='<div class="empty danger">Could not load notification center.</div>';notificationLoadedAt=0}finally{notificationLoading=false}
  }

  function addEnforcementRepairControls(d){
    const rr=d.response||{},cf=rr.enforcement||{},active=rr.active_enforcements||[];
    const cards=[...document.querySelectorAll('#activeEnforcement .enforcement-card')];
    cards.forEach((card,i)=>{
      const row=active[i]||{},state=row.reconciliation_status||'unchecked';
      if(!['drifted','missing','error'].includes(state))return;
      const actions=card.querySelector('.actions');if(!actions||actions.querySelector('[data-repair-rec]'))return;
      const button=document.createElement('button');button.className='btn primary';button.type='button';button.dataset.repairRec=row.recommendation_id||'';button.textContent='Repair rule';actions.insertBefore(button,actions.lastElementChild||null);
    });

    const r=cf.reconciliation||{},orphans=r.orphans||[],jobs=r.rollback_cleanup_jobs||[];
    const target=document.getElementById('reconciliation');if(!target)return;
    if(orphans.length){
      const section=document.createElement('div');section.className='transaction-actions';section.innerHTML='<div class="meta-line warn" style="margin-top:12px"><strong>Orphan cleanup</strong></div>';
      orphans.forEach(o=>{
        const row=document.createElement('div');row.className='list-row';row.innerHTML=`<div class="list-main"><div class="list-title">${esc(o.ref||o.rule_id||'Hotpot rule')}</div><div class="list-meta">zone ${esc(String(o.zone_id||'').slice(0,12))} · rule ${esc(String(o.rule_id||'').slice(0,12))}</div></div><button class="btn danger" type="button" data-remove-orphan>Remove orphan</button>`;
        row.querySelector('[data-remove-orphan]')._hotpotRule=o;section.appendChild(row);
      });
      target.appendChild(section);
    }
    if(jobs.length){
      const note=document.createElement('div');note.className='meta-line danger';note.style.marginTop='10px';note.textContent=`${jobs.length} durable rollback cleanup job${jobs.length===1?'':'s'} pending`;target.appendChild(note);
    }
  }

  async function runRepair(button){
    const id=button.dataset.repairRec;if(!id)return;
    if(!confirm('Repair this Cloudflare enforcement rule to match the approved Hotpot recommendation?'))return;
    button.disabled=true;button.textContent='Repairing…';
    try{
      const r=await fetch('/api/recommendation/'+encodeURIComponent(id)+'/repair',{method:'POST',headers:{'X-Hotpot-Action':'repair'}});let body={};try{body=await r.json()}catch(e){}
      if(!r.ok)throw new Error(body.error||body.message||('HTTP '+r.status));
      await load();
    }catch(e){alert('Cloudflare repair failed: '+e.message)}finally{button.disabled=false;button.textContent='Repair rule'}
  }

  async function removeOrphan(button){
    const rule=button._hotpotRule||{};
    if(!confirm('Remove this orphaned Hotpot Cloudflare rule? This only removes the selected rule.'))return;
    button.disabled=true;button.textContent='Removing…';
    try{
      const r=await fetch('/api/enforcement/orphan/remove',{method:'POST',headers:{'Content-Type':'application/json','X-Hotpot-Action':'remove-orphan'},body:JSON.stringify(rule)});let body={};try{body=await r.json()}catch(e){}
      if(!r.ok)throw new Error(body.error||body.message||('HTTP '+r.status));
      await load();
    }catch(e){alert('Orphan removal failed: '+e.message)}finally{button.disabled=false;button.textContent='Remove orphan'}
  }

  function ensureCampaignPanel(){
    if(document.getElementById('campaignTable'))return;
    const view=document.getElementById('view-threats');if(!view)return;
    const panel=document.createElement('section');panel.className='panel';panel.style.marginTop='12px';
    panel.innerHTML='<div class="panel-head"><div><div class="section-kicker">Distributed correlation</div><h2>Attack campaigns</h2></div><div id="campaignPolicy" class="meta-line"></div></div><div class="table-wrap"><table><thead><tr><th>Campaign</th><th>Risk</th><th>Actors</th><th>Hits</th><th>Apps</th><th>Scanner / category</th><th>Last seen</th></tr></thead><tbody id="campaignTable"></tbody></table></div><div class="view-note" style="margin-top:8px">Campaigns correlate scanner fingerprints, probe families and timing across distinct actors. ASN, provider and geography are not used and campaign membership does not change an actor score.</div>';
    view.appendChild(panel);
  }

  function renderCampaigns(d){
    ensureCampaignPanel();const target=document.getElementById('campaignTable');if(!target)return;
    const policy=d.campaign_policy||{},rows=d.campaigns||[];
    const summary=document.getElementById('campaignPolicy');
    if(summary)summary.textContent=`${fmt(rows.length)} active · ${fmt(policy.window_minutes||0)}m grouping window · min ${fmt(policy.min_actors||2)} actors`;
    target.innerHTML=rows.map(c=>{
      const paths=(c.top_paths||[]).slice(0,2).map(p=>p.path).join(', ');
      const scanner=(c.scanners||[]).slice(0,2).join(', ')||'pattern match';
      const category=(c.categories||[]).slice(0,2).join(', ')||'uncategorized';
      return `<tr><td><strong>${esc(c.label||c.campaign_id)}</strong><div class="cell-sub"><code>${esc(c.campaign_id)}</code>${paths?' · '+esc(paths):''}</div></td><td>${levelBadge(c.max_level||1)}</td><td>${fmt(c.actor_count)}<div class="cell-sub">${fmt(c.source_ip_count)} IPs</div></td><td>${fmt(c.hits)}<div class="cell-sub">${fmt(c.persisted_events)} retained</div></td><td>${fmt(c.app_count)}<div class="cell-sub">${esc((c.apps||[]).slice(0,3).join(', '))}</div></td><td>${esc(scanner)}<div class="cell-sub">${esc(category)}</div></td><td>${esc(shortWhen(c.last_seen))}</td></tr>`;
    }).join('')||'<tr><td colspan="7" class="empty">No distributed campaigns meet the current correlation threshold.</td></tr>';
  }

  const baseRenderResponses=renderResponses;
  renderResponses=function(d){baseRenderResponses(d);addEnforcementRepairControls(d)};
  document.addEventListener('click',e=>{const repair=e.target.closest('[data-repair-rec]');if(repair){runRepair(repair);return}const orphan=e.target.closest('[data-remove-orphan]');if(orphan)removeOrphan(orphan)});

  const baseRenderThreats=renderThreats;
  renderThreats=function(d){baseRenderThreats(d);renderCampaigns(d)};

  const baseRenderOperations=renderOperations;
  renderOperations=function(d){baseRenderOperations(d);ensureNotificationPanel();loadNotificationCenter(false)};
  ensureNotificationPanel();ensureCampaignPanel();loadNotificationCenter(true);setInterval(()=>loadNotificationCenter(false),30000);
})();