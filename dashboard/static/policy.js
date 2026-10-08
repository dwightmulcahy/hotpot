(()=>{
  let policyPayload=null;
  let policyLoading=false;
  let currentThreat=null;

  const baseShowView=showView;
  const baseViewName=viewName;
  showView=function(name,{updateHash=true}={}){
    if(name!=='policy')return baseShowView(name,{updateHash});
    ensurePolicyView();
    document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id==='view-policy'));
    document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.view==='policy'));
    if(updateHash&&location.hash!=='#policy')history.replaceState(null,'','#policy');
    try{localStorage.setItem('hotpot:view','policy')}catch(e){}
    loadPolicies(false);
  };
  viewName=function(){
    if(location.hash.replace('#','')==='policy')return 'policy';
    return baseViewName();
  };

  function kindLabel(kind){return ({allow_cidr:'Allow CIDR',suppress_actor:'Suppress actor',suppress_scanner:'Suppress scanner',exclude_category:'Exclude category'})[kind]||kind}
  function impactLabel(value){return String(value||'').replaceAll('_',' ')}
  function isActivePolicy(p){return !!p.enabled&&(!p.expires_at||new Date(p.expires_at)>new Date())}
  function expiryText(p){if(!p.expires_at)return 'Permanent';return (new Date(p.expires_at)>new Date()?'Expires ':'Expired ')+shortWhen(p.expires_at)}
  function exactCidr(ip){if(!ip)return '';if(ip.includes('/'))return ip;return ip.includes(':')?ip+'/128':ip+'/32'}
  function latestScanner(d){
    const timeline=d?.timeline||[];
    const item=timeline.find(x=>x.scanner_family||x.scanner);
    return item?.scanner_family||item?.scanner||d?.last_scanner||'';
  }
  function topCategory(d){
    const values=d?.category_activity||d?.categories||[];
    const first=values[0];
    return typeof first==='string'?first:(first?.category||'');
  }

  function ensurePolicyView(){
    if(!document.querySelector('.tab[data-view="policy"]')){
      const nav=document.querySelector('nav.tabs');
      if(nav){const tab=document.createElement('button');tab.className='tab';tab.dataset.view='policy';tab.type='button';tab.textContent='Policy';nav.appendChild(tab)}
    }
    if(document.getElementById('view-policy'))return;
    const main=document.querySelector('main');if(!main)return;
    const section=document.createElement('section');section.id='view-policy';section.className='view';
    section.innerHTML=`
      <div class="view-head"><div><h1 class="view-title">Policy control plane</h1><div class="view-note">Audited allowlists and suppressions synchronized to each Hotpot. Environment allowlists remain emergency/bootstrap policy.</div></div><div class="actions" style="margin-top:0"><button id="policyReconcile" class="btn ghost" type="button">Reconcile now</button><button id="policyRefresh" class="btn ghost" type="button">Refresh</button></div></div>
      <div class="policy-layout">
        <section class="panel"><div class="panel-head"><div><div class="section-kicker">Controlled change</div><h2>Create policy</h2></div></div>
          <form id="policyForm" class="policy-form">
            <div class="policy-field"><label for="policyKind">Policy type</label><select id="policyKind"><option value="allow_cidr">Allow CIDR</option><option value="suppress_actor">Suppress actor</option><option value="suppress_scanner">Suppress scanner</option><option value="exclude_category">Exclude category</option></select></div>
            <div class="policy-field"><label for="policyValue">Value</label><input id="policyValue" autocomplete="off" required placeholder="203.0.113.25/32"></div>
            <div class="policy-field"><label>Application scope</label><div id="policyApps" class="policy-apps"><span class="muted">Loading applications…</span></div><div class="view-note">No applications selected means all protected applications.</div></div>
            <div class="policy-field"><label for="policyReason">Reason</label><input id="policyReason" maxlength="500" required placeholder="Why this exception is needed"></div>
            <div class="policy-field"><label for="policyNotes">Notes</label><textarea id="policyNotes" maxlength="2000" placeholder="Ticket, investigation context, owner, etc."></textarea></div>
            <div class="policy-field"><label for="policyHours">Expires after hours</label><input id="policyHours" type="number" min="0" max="8760" value="24"><div class="view-note">0 = permanent. Temporary exceptions are preferred.</div></div>
            <button class="btn primary" type="submit">Preview & create</button>
            <div id="policyCreateStatus" class="meta-line"></div>
          </form>
        </section>
        <section class="panel"><div class="panel-head"><div><div class="section-kicker">Distribution</div><h2>Synchronization</h2></div><div id="policySyncSummary" class="meta-line"></div></div><div id="policySync" class="policy-sync-grid"><div class="empty">Loading sync state…</div></div><div class="view-note" style="margin-top:10px">Cores retain the last valid snapshot in persistent storage if the dashboard is unavailable.</div></section>
      </div>
      <section class="panel" style="margin-top:12px"><div class="panel-head"><div><div class="section-kicker">Effective control</div><h2>Policies</h2></div><div id="policyCount" class="meta-line"></div></div><div class="table-wrap"><table class="policy-table"><thead><tr><th>State</th><th>Type</th><th>Value</th><th>Apps</th><th>Reason</th><th>Expiry</th><th></th></tr></thead><tbody id="policyTable"></tbody></table></div></section>
      <div class="grid equal">
        <section class="panel"><div class="panel-head"><div><div class="section-kicker">What-if</div><h2>Evaluate a request</h2></div></div><form id="policyEvaluate" class="policy-form"><div class="policy-field"><label for="evaluateIp">Client IP</label><input id="evaluateIp" placeholder="203.0.113.25"></div><div class="policy-field"><label for="evaluateActor">Actor key</label><input id="evaluateActor" placeholder="203.0.113.25 or cf-worker:zone"></div><div class="policy-field"><label for="evaluateScanner">Scanner family</label><input id="evaluateScanner" placeholder="nuclei"></div><div class="policy-field"><label for="evaluateCategory">Category</label><input id="evaluateCategory" placeholder="secret-discovery"></div><div class="policy-field"><label for="evaluateApp">Application</label><select id="evaluateApp"><option value="">Any application</option></select></div><button class="btn ghost" type="submit">Evaluate policy</button></form><div id="policyEvaluation" class="meta-line" style="margin-top:10px"></div></section>
        <section class="panel"><div class="panel-head"><div><div class="section-kicker">Audit</div><h2>Policy history</h2></div></div><div id="policyAudit"><div class="empty">No policy history yet.</div></div></section>
      </div>`;
    main.appendChild(section);
    document.getElementById('policyKind').addEventListener('change',updatePolicyPlaceholder);
    document.getElementById('policyForm').addEventListener('submit',createPolicy);
    document.getElementById('policyEvaluate').addEventListener('submit',evaluatePolicy);
    document.getElementById('policyRefresh').addEventListener('click',()=>loadPolicies(true));
    document.getElementById('policyReconcile').addEventListener('click',reconcilePolicies);
    updatePolicyPlaceholder();
  }

  function updatePolicyPlaceholder(){
    const kind=document.getElementById('policyKind')?.value;const input=document.getElementById('policyValue');if(!input)return;
    input.placeholder=kind==='allow_cidr'?'203.0.113.25/32':kind==='suppress_actor'?'203.0.113.25 or cf-worker:zone':kind==='suppress_scanner'?'nuclei':'secret-discovery';
  }

  async function jsonResponse(response){
    let body=null;try{body=await response.json()}catch(e){}
    if(!response.ok){throw new Error(body?.error||body?.message||await response.text().catch(()=>null)||('HTTP '+response.status))}
    return body;
  }

  async function loadPolicies(force=false){
    ensurePolicyView();if(policyLoading)return;if(policyPayload&&!force&&Date.now()-(policyPayload._loadedAt||0)<10000){renderPolicies();return}
    policyLoading=true;
    try{const r=await fetch('/api/policies?audit_limit=80',{cache:'no-store'});policyPayload=await jsonResponse(r);policyPayload._loadedAt=Date.now();renderPolicies()}
    catch(e){const table=document.getElementById('policyTable');if(table)table.innerHTML=`<tr><td colspan="7" class="danger">${esc(e.message)}</td></tr>`}
    finally{policyLoading=false}
  }

  function renderPolicies(){
    if(!policyPayload)return;const policies=policyPayload.policies||[],apps=policyPayload.applications||[],sync=policyPayload.sync||{};
    const appsTarget=document.getElementById('policyApps');if(appsTarget){
      const checked=new Set([...appsTarget.querySelectorAll('input:checked')].map(x=>x.value));
      appsTarget.innerHTML=apps.map(a=>`<label class="policy-app"><input type="checkbox" value="${attr(a.id)}" ${checked.has(a.id)?'checked':''}>${esc(a.name)}</label>`).join('')||'<span class="muted">No applications configured.</span>';
    }
    const evalApp=document.getElementById('evaluateApp');if(evalApp){const prior=evalApp.value;evalApp.innerHTML='<option value="">Any application</option>'+apps.map(a=>`<option value="${attr(a.id)}">${esc(a.name)}</option>`).join('');if(apps.some(a=>a.id===prior))evalApp.value=prior}
    document.getElementById('policyCount').textContent=`${fmt(policyPayload.active||0)} active · ${fmt(policies.length)} total`;
    const table=document.getElementById('policyTable');table.innerHTML=policies.map(p=>{
      const active=isActivePolicy(p),appNames=(p.app_ids||[]).map(id=>apps.find(a=>a.id===id)?.name||id);return `<tr><td><span class="badge ${active?'pass':'neutral'}">${active?'active':p.enabled?'expired':'disabled'}</span></td><td>${esc(kindLabel(p.kind))}</td><td><code>${esc(p.value)}</code></td><td>${esc(appNames.join(', ')||'All apps')}</td><td class="policy-reason">${esc(p.reason||'')}<div class="cell-sub">${esc(p.notes||'')}</div></td><td>${esc(expiryText(p))}</td><td>${active?`<button class="btn danger" type="button" data-policy-disable="${attr(p.policy_id)}">Disable</button>`:''}</td></tr>`;
    }).join('')||'<tr><td colspan="7" class="empty">No dashboard-managed policies.</td></tr>';
    renderSync(sync);renderAudit(policyPayload.audit||[]);
  }

  function renderSync(sync){
    const rows=sync.instances||[],target=document.getElementById('policySync');const ok=rows.length&&rows.every(x=>x.in_sync);
    document.getElementById('policySyncSummary').innerHTML=`<span class="badge ${ok?'pass':rows.length?'warning':'neutral'}">${ok?'in sync':rows.length?'drift':'not checked'}</span>`;
    target.innerHTML=rows.map(x=>`<div class="policy-sync-card"><strong>${esc(x.instance_id)}</strong><div class="meta-line"><span class="badge ${x.in_sync?'pass':'warning'}">${x.in_sync?'synced':'drift'}</span> ${x.last_success_at?'last success '+esc(shortWhen(x.last_success_at)):'never synced'}</div><div class="cell-sub">desired ${esc(String(x.desired_revision||'').slice(0,10)||'none')} · applied ${esc(String(x.applied_revision||'').slice(0,10)||'none')}</div>${x.last_error?`<div class="danger cell-sub">${esc(x.last_error)}</div>`:''}</div>`).join('')||'<div class="empty">Policy reconciliation has not run yet.</div>';
  }

  function renderAudit(rows){
    const target=document.getElementById('policyAudit');target.innerHTML=rows.slice(0,40).map(x=>`<div class="list-row"><div class="list-main"><div class="list-title">${esc(x.event_type)} · ${esc(x.principal)}</div><div class="list-meta">${esc(x.message||'')} ${x.policy_id?'· '+esc(x.policy_id):''}</div></div><div class="list-count">${esc(shortWhen(x.created_at))}</div></div>`).join('')||'<div class="empty">No policy history yet.</div>';
  }

  function candidateFromForm(){
    const hours=Math.max(0,Number(document.getElementById('policyHours').value||0));
    return {kind:document.getElementById('policyKind').value,value:document.getElementById('policyValue').value.trim(),app_ids:[...document.querySelectorAll('#policyApps input:checked')].map(x=>x.value),reason:document.getElementById('policyReason').value.trim(),notes:document.getElementById('policyNotes').value.trim(),expires_at:hours?new Date(Date.now()+hours*3600000).toISOString():null};
  }

  async function createPolicy(e){
    e.preventDefault();const button=e.submitter||e.target.querySelector('button[type="submit"]'),status=document.getElementById('policyCreateStatus'),candidate=candidateFromForm();button.disabled=true;status.textContent='Validating policy…';
    try{
      const preview=await jsonResponse(await fetch('/api/policies/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({candidate})}));
      const apps=(preview.applications||[]).join(', ')||'all applications';const impacts=(preview.impacts||[]).map(impactLabel).join(', ');
      const permanent=!preview.candidate.expires_at;
      const text=`Create ${kindLabel(preview.candidate.kind)} policy?\n\nValue: ${preview.candidate.value}\nApps: ${apps}\nReason: ${preview.candidate.reason}\nExpiry: ${permanent?'permanent':when(preview.candidate.expires_at)}\nImpact: ${impacts}\n\nThis will persist the policy and synchronize it to applicable Hotpot instances.`;
      if(!confirm(text)){status.textContent='Policy creation cancelled.';return}
      status.textContent='Creating and synchronizing…';
      const result=await jsonResponse(await fetch('/api/policies',{method:'POST',headers:{'Content-Type':'application/json','X-Hotpot-Action':'policy-create'},body:JSON.stringify(candidate)}));
      status.textContent=result.sync?.in_sync?'Policy created and synchronized.':'Policy created; one or more instances report sync drift.';
      document.getElementById('policyReason').value='';document.getElementById('policyNotes').value='';
      await loadPolicies(true);await load();
    }catch(err){status.innerHTML=`<span class="danger">${esc(err.message)}</span>`}
    finally{button.disabled=false}
  }

  async function disablePolicy(id){
    if(!confirm('Disable this policy and synchronize the updated policy set to affected Hotpot instances?'))return;
    try{await jsonResponse(await fetch('/api/policies/'+encodeURIComponent(id)+'/disable',{method:'POST',headers:{'X-Hotpot-Action':'policy-disable'}}));await loadPolicies(true);await load()}
    catch(e){alert('Policy disable failed: '+e.message)}
  }

  async function reconcilePolicies(){
    const button=document.getElementById('policyReconcile');button.disabled=true;button.textContent='Reconciling…';
    try{const result=await jsonResponse(await fetch('/api/policies/reconcile',{method:'POST',headers:{'X-Hotpot-Action':'policy-reconcile'}}));if(!result.in_sync)alert('Reconciliation completed with drift. Review the per-instance sync status.');await loadPolicies(true)}
    catch(e){alert('Policy reconciliation failed: '+e.message)}finally{button.disabled=false;button.textContent='Reconcile now'}
  }

  async function evaluatePolicy(e){
    e.preventDefault();const payload={client_ip:document.getElementById('evaluateIp').value.trim(),actor_key:document.getElementById('evaluateActor').value.trim(),scanner_family:document.getElementById('evaluateScanner').value.trim(),category:document.getElementById('evaluateCategory').value.trim(),app_id:document.getElementById('evaluateApp').value};const target=document.getElementById('policyEvaluation');target.textContent='Evaluating…';
    try{const result=await jsonResponse(await fetch('/api/policies/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}));target.innerHTML=result.matched?`<div class="policy-impact ${result.impacts?.includes('bypass_deception')?'allow':'suppress'}"><strong>Policy matched.</strong> ${esc((result.impacts||[]).map(impactLabel).join(', '))}<div class="cell-sub">${(result.matches||[]).map(x=>esc(kindLabel(x.kind)+': '+x.value+' — '+(x.reason||''))).join('<br>')}</div></div>`:'<div class="policy-impact"><strong>No dashboard policy matches.</strong> Normal deception, notification, and response policy applies.</div>'}
    catch(err){target.innerHTML=`<span class="danger">${esc(err.message)}</span>`}
  }

  function prefillPolicy({kind,value,reason,appIds=[]}){
    ensurePolicyView();showView('policy');document.getElementById('policyKind').value=kind;updatePolicyPlaceholder();document.getElementById('policyValue').value=value||'';document.getElementById('policyReason').value=reason||'';document.getElementById('policyNotes').value='Created from threat investigation';document.getElementById('policyHours').value='24';
    document.querySelectorAll('#policyApps input').forEach(input=>input.checked=appIds.includes(input.value));document.getElementById('policyValue').focus();
  }

  function renderPlan(plan){
    const zones=(plan.zones||[]).map(z=>`Zone ${z.zone_id}\nHosts: ${(z.hosts||[]).join(', ')}\nAction: ${z.action}\nExpression: ${z.expression}\nRef: ${z.ref}\nEffect: ${z.expected_effect}`).join('\n\n');
    return `${responseAction(plan.recommendation_action)}\nTarget: ${plan.target_type} ${plan.target_value}\nDuration: ${plan.duration_hours}h\nExpires: ${when(plan.expires_at)}\n\n${zones}\n\nNo Cloudflare writes have been performed yet.`;
  }

  async function manualResponse(actorKey,action){
    try{
      const preview=await jsonResponse(await fetch('/api/manual-response/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor_key:actorKey,action})}));
      if(!confirm('Apply this manual Cloudflare response?\n\n'+renderPlan(preview.plan)))return;
      const result=await jsonResponse(await fetch('/api/manual-response/apply',{method:'POST',headers:{'Content-Type':'application/json','X-Hotpot-Action':'manual-response'},body:JSON.stringify({actor_key:actorKey,action})}));
      alert('Manual response applied and verified. '+responseAction(result.plan?.recommendation_action)+' expires '+when(result.plan?.expires_at)+'.');await load();if(currentDrawerKey)await openThreat(currentDrawerKey);
    }catch(e){alert('Manual response failed: '+e.message)}
  }

  async function appendPolicyDecision(d){
    const body=document.getElementById('drawerBody');if(!body)return;const actorKey=d.identity_key||d.ip||d.client_ip||'',clientIp=d.client_ip||d.ip||'',scanner=latestScanner(d),category=topCategory(d);
    const section=document.createElement('div');section.className='drawer-section';section.innerHTML='<h4>Policy decision</h4><div class="meta-line">Evaluating dashboard policy…</div>';body.appendChild(section);
    try{const result=await jsonResponse(await fetch('/api/policies/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_ip:clientIp,actor_key:actorKey,scanner_family:scanner,category})}));const target=section.querySelector('.meta-line');target.innerHTML=result.matched?`<div class="policy-impact ${result.impacts?.includes('bypass_deception')?'allow':'suppress'}"><strong>Matched policy.</strong> ${esc((result.impacts||[]).map(impactLabel).join(', '))}<div class="cell-sub">${(result.matches||[]).map(x=>esc(kindLabel(x.kind)+': '+x.value+' — '+(x.reason||''))).join('<br>')}</div></div>`:'<div class="policy-impact"><strong>No dashboard exemption or suppression applies.</strong> Standard Hotpot policy is active for this actor.</div>'}
    catch(e){section.querySelector('.meta-line').innerHTML=`<span class="danger">Policy evaluation unavailable: ${esc(e.message)}</span>`}
  }

  function appendManualControls(d){
    const body=document.getElementById('drawerBody');if(!body)return;const actorKey=d.identity_key||d.ip||d.client_ip||'',clientIp=d.client_ip||d.ip||'',cfReady=!!snapshot?.response?.enforcement?.configured,appIds=(d.app_activity||[]).map(x=>x.instance_id).filter(Boolean),scanner=latestScanner(d);
    const section=document.createElement('div');section.className='drawer-section';section.innerHTML=`<h4>Manual response</h4><div class="manual-response-grid"><button class="btn ghost" data-manual-response="challenge" data-actor="${attr(actorKey)}" ${cfReady?'':'disabled'}>Challenge</button><button class="btn danger" data-manual-response="block_1h" data-actor="${attr(actorKey)}" ${cfReady?'':'disabled'}>Block 1h</button><button class="btn danger" data-manual-response="block_24h" data-actor="${attr(actorKey)}" ${cfReady?'':'disabled'}>Block 24h</button><button class="btn danger" data-manual-response="long_block" data-actor="${attr(actorKey)}" ${cfReady?'':'disabled'}>Long block</button></div><div class="manual-response-grid" style="margin-top:8px"><button class="btn ghost" data-policy-prefill="allow" type="button">Allowlist</button><button class="btn ghost" data-policy-prefill="actor" type="button">Suppress actor</button>${scanner?'<button class="btn ghost" data-policy-prefill="scanner" type="button">Suppress scanner</button>':''}</div><div class="view-note" style="margin-top:7px">${cfReady?'Every Cloudflare action is previewed before it can be applied.':'Cloudflare enforcement is not configured; policy controls remain available.'}</div>`;
    section.querySelector('[data-policy-prefill="allow"]').addEventListener('click',()=>prefillPolicy({kind:'allow_cidr',value:exactCidr(clientIp),reason:'Manual allowlist from threat investigation',appIds}));
    section.querySelector('[data-policy-prefill="actor"]').addEventListener('click',()=>prefillPolicy({kind:'suppress_actor',value:actorKey,reason:'Manual actor suppression from threat investigation',appIds}));
    const scannerButton=section.querySelector('[data-policy-prefill="scanner"]');if(scannerButton)scannerButton.addEventListener('click',()=>prefillPolicy({kind:'suppress_scanner',value:scanner,reason:'Manual scanner suppression from threat investigation',appIds}));
    body.appendChild(section);
  }

  const baseRenderThreatDrawer=renderThreatDrawer;
  renderThreatDrawer=function(d){currentThreat=d;baseRenderThreatDrawer(d);appendPolicyDecision(d);appendManualControls(d)};

  document.addEventListener('click',e=>{
    const disable=e.target.closest('[data-policy-disable]');if(disable){disablePolicy(disable.dataset.policyDisable);return}
    const manual=e.target.closest('[data-manual-response]');if(manual){manualResponse(manual.dataset.actor,manual.dataset.manualResponse);return}
  });

  function attach(){ensurePolicyView();if(location.hash==='#policy')showView('policy',{updateHash:false});else{try{if(!location.hash&&localStorage.getItem('hotpot:view')==='policy')showView('policy',{updateHash:false})}catch(e){}}loadPolicies(true)}
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',attach);else attach();
})();
