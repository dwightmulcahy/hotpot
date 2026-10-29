(()=>{
  const MODES=[
    ['off','Off'],
    ['shadow','Shadow'],
    ['challenge','Auto challenge'],
    ['active','Active']
  ];
  let panel=null;

  function esc(value){
    return String(value??'').replace(/[&<>"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[ch]));
  }
  function age(hours){
    if(hours==null)return 'not started';
    if(hours<24)return Math.round(hours)+'h';
    return (hours/24).toFixed(1)+'d';
  }
  function ensurePanel(){
    if(panel&&document.body.contains(panel))return panel;
    const view=document.getElementById('view-enforcement');
    if(!view)return null;
    panel=document.createElement('section');
    panel.id='autoResponsePanel';
    panel.className='panel';
    panel.style.marginBottom='12px';
    const head=view.querySelector('.view-head');
    if(head&&head.nextSibling)view.insertBefore(panel,head.nextSibling);
    else view.prepend(panel);
    return panel;
  }
  function modeBadge(mode){
    const cls=mode==='off'?'neutral':mode==='shadow'?'warning':mode==='challenge'?'medium':'applied';
    return `<span class="badge ${cls}">${esc(mode)}</span>`;
  }
  function circuitBadge(status){
    const cls=status==='closed'||status==='standby'||status==='shadow'?'healthy':status==='off'?'neutral':'error';
    return `<span class="badge ${cls}">${esc(status||'unknown')}</span>`;
  }
  function render(status){
    const target=ensurePanel();if(!target)return;
    const cfg=status.config||{},counts=status.counts||{},circuit=status.circuit_breaker||{},rejection=status.last_mode_change_rejection||null;
    const buttons=MODES.map(([mode,label])=>`<button class="btn ${status.mode===mode?'primary':'ghost'}" data-auto-mode="${mode}" type="button" ${status.mode===mode?'disabled':''}>${esc(label)}</button>`).join('');
    const shadow=status.mode==='shadow'?`<div>Shadow age</div><div>${esc(age(status.shadow_age_hours))} / ${(status.recommended_shadow_hours||168)/24}d recommended</div>`:'';
    const rejected=rejection?`<div>Last mode-change blocker</div><div class="warn">${esc(rejection.reason||'rejected')}${rejection.checked_at?' · '+esc(new Date(rejection.checked_at).toLocaleString()):''}</div>`:'';
    target.innerHTML=`
      <div class="panel-head">
        <div><div class="section-kicker">Guarded automation</div><h2>Automatic response</h2></div>
        <div>${modeBadge(status.mode)}</div>
      </div>
      <div class="kv">
        <div>Mode</div><div>${esc(status.stages?.[status.mode]||status.mode)}</div>
        <div>Circuit breaker</div><div>${circuitBadge(circuit.status)} ${esc(circuit.reason||'')}</div>
        <div>Hourly limit</div><div>${Number(counts.last_hour||0)} / ${Number(cfg.max_actions_per_hour||0)}</div>
        <div>Daily limit</div><div>${Number(counts.last_24_hours||0)} / ${Number(cfg.max_actions_per_day||0)}</div>
        <div>Shadow candidates</div><div>${Number(counts.shadow_would_apply||0)}</div>
        <div>Verified bots</div><div>${cfg.exclude_verified_bots?'Excluded':'Not excluded'}</div>
        <div>7-day long blocks</div><div>Manual approval only</div>
        ${shadow}
        ${rejected}
      </div>
      <div class="actions" style="margin-top:12px">${buttons}</div>
      <div class="meta-line" style="margin-top:10px">Off is the kill switch. Shadow performs no Cloudflare writes. Auto challenge only applies high-confidence 6-hour managed challenges. Active can also apply high-confidence 24-hour L4 hostname-scoped blocks.</div>`;
  }
  async function loadStatus(){
    try{
      const r=await fetch('/api/auto-response',{cache:'no-store'});
      if(!r.ok)throw new Error('HTTP '+r.status);
      render(await r.json());
    }catch(e){
      const target=ensurePanel();if(target)target.innerHTML=`<div class="danger">Could not load automatic-response status: ${esc(e.message)}</div>`;
    }
  }
  async function setMode(mode){
    if(mode==='active'&&!confirm('Enable guarded automatic response?\n\nThis can automatically create 6-hour challenges and 24-hour L4 hostname-scoped Cloudflare blocks. 7-day zone-wide long blocks remain manual.'))return;
    if(mode==='challenge'&&!confirm('Enable automatic managed challenges?\n\n24-hour blocks and 7-day long blocks will remain manual.'))return;
    if(mode==='off'&&!confirm('Disable all new automatic response actions now?'))return;
    try{
      const r=await fetch('/api/auto-response/mode',{
        method:'POST',
        headers:{'Content-Type':'application/json','X-Hotpot-Action':'auto-response-mode'},
        body:JSON.stringify({mode})
      });
      const raw=await r.text();
      let body=null;try{body=raw?JSON.parse(raw):null}catch(e){}
      if(!r.ok)throw new Error(body?.error||body?.message||raw||('HTTP '+r.status));
      render(body||{});
    }catch(e){alert('Automatic response mode change failed: '+e.message)}
  }
  document.addEventListener('click',event=>{
    const button=event.target.closest('[data-auto-mode]');
    if(button){setMode(button.dataset.autoMode);}
  });
  loadStatus();
  setInterval(loadStatus,15000);
})();
