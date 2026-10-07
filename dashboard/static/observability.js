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

  const baseRenderOperations=renderOperations;
  renderOperations=function(d){baseRenderOperations(d);ensureNotificationPanel();loadNotificationCenter(false)};
  ensureNotificationPanel();loadNotificationCenter(true);setInterval(()=>loadNotificationCenter(false),30000);
})();
