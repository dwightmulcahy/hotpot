(()=>{
  let deploymentPayload=null;
  let deploymentLoading=false;

  const priorShowView=showView;
  const priorViewName=viewName;
  showView=function(name,{updateHash=true}={}){
    if(name!=='deployment')return priorShowView(name,{updateHash});
    ensureDeploymentView();
    document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id==='view-deployment'));
    document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.view==='deployment'));
    if(updateHash&&location.hash!=='#deployment')history.replaceState(null,'','#deployment');
    try{localStorage.setItem('hotpot:view','deployment')}catch(e){}
    loadDeployment(false);
  };
  viewName=function(){
    if(location.hash.replace('#','')==='deployment')return 'deployment';
    return priorViewName();
  };

  function h(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
  function short(value,n=10){const s=String(value||'');return s&&s!=='unknown'?s.slice(0,n):'unknown'}
  function statusBadge(status){const cls=status==='pass'?'pass':status==='fail'?'fail':'warning';return `<span class="badge ${cls}">${h(status)}</span>`}
  function yesNoUnknown(value){return value===true?'yes':value===false?'no':'unknown'}
  function buildText(row){const version=String(row?.version||'unknown');const sha=short(row?.git_sha,10);return `${version} · ${sha}`}
  function dateText(value){if(!value)return 'none';try{return new Date(value).toLocaleString()}catch(e){return String(value)}}

  function ensureDeploymentView(){
    if(!document.querySelector('.tab[data-view="deployment"]')){
      const nav=document.querySelector('nav.tabs');
      if(nav){const tab=document.createElement('button');tab.className='tab';tab.dataset.view='deployment';tab.type='button';tab.textContent='Deployment';nav.appendChild(tab)}
    }
    if(document.getElementById('view-deployment'))return;
    const main=document.querySelector('main');if(!main)return;
    const section=document.createElement('section');section.id='view-deployment';section.className='view';
    section.innerHTML=`
      <div class="view-head"><div><h1 class="view-title">Deployment & upgrades</h1><div class="view-note">Read-only release/config drift inspection with a QNAP-safe rollout plan. Hotpot never gets access to the Docker socket.</div></div><div class="actions" style="margin-top:0"><button id="deploymentBackup" class="btn ghost" type="button">Verified backup now</button><button id="deploymentRefresh" class="btn ghost" type="button">Refresh</button></div></div>
      <div class="metrics">
        <div class="metric-card"><div class="metric-label">Dashboard build</div><div id="deploymentBuild" class="metric-value" style="font-size:22px">…</div><div id="deploymentBuildSub" class="metric-sub">Loading release identity</div></div>
        <div class="metric-card"><div class="metric-label">Healthy cores</div><div id="deploymentHealth" class="metric-value">…</div><div class="metric-sub">Protected instances responding</div></div>
        <div class="metric-card"><div class="metric-label">Config parity</div><div id="deploymentParity" class="metric-value" style="font-size:22px">…</div><div class="metric-sub">Shared hotpot.env fingerprint</div></div>
        <div id="deploymentReadyCard" class="metric-card"><div class="metric-label">Upgrade readiness</div><div id="deploymentReady" class="metric-value" style="font-size:22px">…</div><div id="deploymentReadySub" class="metric-sub">Checking deployment safeguards</div></div>
      </div>
      <section class="panel" style="margin-top:12px"><div class="panel-head"><div><div class="section-kicker">Runtime inventory</div><h2>Instances</h2></div><div id="deploymentInstanceSummary" class="meta-line"></div></div><div class="table-wrap"><table><thead><tr><th>Application</th><th>Health</th><th>Build</th><th>Config</th><th>Policy</th><th>Admin secret</th></tr></thead><tbody id="deploymentInstances"></tbody></table></div></section>
      <div class="deployment-layout">
        <section class="panel"><div class="panel-head"><div><div class="section-kicker">Pre-upgrade gate</div><h2>Readiness checks</h2></div></div><div id="deploymentChecks" class="deployment-checks"><div class="empty">Loading checks…</div></div></section>
        <section class="panel"><div class="panel-head"><div><div class="section-kicker">Recovery</div><h2>Verified backup</h2></div></div><div id="deploymentBackupState" class="deployment-backup-meta"><div class="empty">Loading backup state…</div></div></section>
      </div>
      <section class="panel" style="margin-top:12px"><div class="panel-head"><div><div class="section-kicker">QNAP rollout</div><h2>Upgrade plan</h2></div><div id="deploymentTarget" class="meta-line"></div></div><div id="deploymentMutable"></div><div id="deploymentCommands"><div class="empty">Loading rollout commands…</div></div><div class="view-note" style="margin-top:10px">Commands are advisory and are never executed by the dashboard. Recreate cores one at a time, health-check each, then recreate the dashboard last.</div></section>`;
    main.appendChild(section);
    document.getElementById('deploymentRefresh').addEventListener('click',()=>loadDeployment(true));
    document.getElementById('deploymentBackup').addEventListener('click',runBackup);
    section.addEventListener('click',event=>{
      const button=event.target.closest('[data-copy-command]');if(!button)return;
      const command=button.dataset.copyCommand||'';copyText(command).then(()=>{const before=button.textContent;button.textContent='Copied';setTimeout(()=>button.textContent=before,1000)}).catch(()=>alert('Could not copy command.'));
    });
  }

  async function copyText(text){
    if(navigator.clipboard?.writeText)return navigator.clipboard.writeText(text);
    const area=document.createElement('textarea');area.value=text;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();const ok=document.execCommand('copy');area.remove();if(!ok)throw new Error('copy failed');
  }

  async function responseJson(response){
    let body=null;try{body=await response.json()}catch(e){}
    if(!response.ok)throw new Error(body?.error||body?.message||('HTTP '+response.status));
    return body;
  }

  async function loadDeployment(force=false){
    ensureDeploymentView();if(deploymentLoading)return;if(deploymentPayload&&!force&&Date.now()-(deploymentPayload._loadedAt||0)<10000){renderDeployment();return}
    deploymentLoading=true;
    try{deploymentPayload=await responseJson(await fetch('/api/deployment',{cache:'no-store'}));deploymentPayload._loadedAt=Date.now();renderDeployment()}
    catch(e){document.getElementById('deploymentChecks').innerHTML=`<div class="danger">${h(e.message)}</div>`}
    finally{deploymentLoading=false}
  }

  function renderDeployment(){
    const p=deploymentPayload;if(!p)return;const s=p.summary||{},dash=p.dashboard||{},instances=p.instances||[];
    document.getElementById('deploymentBuild').textContent=String(dash.version||'unknown');
    document.getElementById('deploymentBuildSub').textContent=`SHA ${short(dash.git_sha,12)} · ${dateText(dash.build_date)}`;
    document.getElementById('deploymentHealth').textContent=`${s.healthy??0}/${s.instances??instances.length}`;
    document.getElementById('deploymentParity').textContent=s.shared_config_consistent===true?'Matched':s.shared_config_consistent===false?'Drift':'Unknown';
    const ready=document.getElementById('deploymentReady'),card=document.getElementById('deploymentReadyCard');ready.textContent=p.ready?'Ready':'Attention';card.classList.toggle('enforced',!!p.ready);card.classList.toggle('degraded',!p.ready);document.getElementById('deploymentReadySub').textContent=p.ready?'All pre-upgrade checks pass':'Review failed/warning checks before upgrade';
    document.getElementById('deploymentInstanceSummary').textContent=`identity ${yesNoUnknown(s.identity_ok)} · release parity ${yesNoUnknown(s.release_consistent)}`;
    const tbody=document.getElementById('deploymentInstances');tbody.innerHTML=instances.map(row=>{
      const health=row.reachable&&row.healthy&&row.upstream_healthy!==false;
      const identity=row.identity_ok?'' : `<div class="danger cell-sub">expected ${h(row.id)} · remote ${h(row.remote_instance_id||'unreachable')}</div>`;
      const shared=row.shared_config_fingerprint?short(row.shared_config_fingerprint,10):'unknown';const full=row.config_fingerprint?short(row.config_fingerprint,10):'unknown';
      const policy=row.policy_in_sync===true?'<span class="badge pass">synced</span>':row.policy_in_sync===false?'<span class="badge warning">drift</span>':'<span class="badge neutral">unknown</span>';
      return `<tr><td><div class="cell-main">${h(row.name)}</div><div class="cell-sub"><code>${h(row.id)}</code></div>${identity}</td><td><span class="badge ${health?'pass':'fail'}">${health?'healthy':'attention'}</span>${row.error?`<div class="danger cell-sub">${h(row.error)}</div>`:''}</td><td><div class="cell-main">${h(buildText(row))}</div><div class="cell-sub">${h(dateText(row.build_date))}</div></td><td><div class="deployment-fp">shared ${h(shared)}</div><div class="deployment-fp">full ${h(full)}</div></td><td>${policy}<div class="cell-sub">${h(short(row.policy_revision,10))}</div></td><td><span class="badge ${row.admin_token_source==='file'?'pass':row.admin_token_source==='environment'?'warning':'neutral'}">${h(row.admin_token_source||'unknown')}</span></td></tr>`;
    }).join('')||'<tr><td colspan="6" class="empty">No instances configured.</td></tr>';
    document.getElementById('deploymentChecks').innerHTML=(p.checks||[]).map(check=>`<div class="deployment-check"><div>${statusBadge(check.status)}</div><div class="deployment-check-detail"><strong>${h(check.id)}</strong><br>${h(check.detail)}</div></div>`).join('')||'<div class="empty">No checks available.</div>';
    renderBackup(p.backups||{});renderPlan(p.upgrade_plan||{});
  }

  function renderBackup(backups){
    const latest=backups.latest||{},target=document.getElementById('deploymentBackupState');
    if(!backups.enabled){target.innerHTML='<div><span class="badge warning">disabled</span></div><div>Operational backup scheduling is disabled.</div>';return}
    if(!latest.backup){target.innerHTML='<div><span class="badge fail">missing</span></div><div>No verified operational backup is available.</div>';return}
    target.innerHTML=`<div><span class="badge ${latest.verified?'pass':'fail'}">${latest.verified?'verified':'unverified'}</span> ${latest.present===false?'<span class="badge fail">file missing</span>':''}</div><div><strong>${h(latest.backup)}</strong></div><div>Created: ${h(dateText(latest.created_at))}</div><div>SHA-256: <code>${h(short(latest.sha256,16))}…</code></div><div>Restore check: ${h(latest.restore_verification?.quick_check||latest.quick_check||'unknown')}</div>`;
  }

  function renderPlan(plan){
    document.getElementById('deploymentTarget').textContent=`target ${plan.target_tag||'latest'} · ${plan.compose_file||''}`;
    document.getElementById('deploymentMutable').innerHTML=plan.mutable_tag?'<div class="deployment-warning"><strong>Mutable tag:</strong> latest is convenient, but an immutable release tag is safer for repeatable upgrades and rollback.</div>':'';
    document.getElementById('deploymentCommands').innerHTML=(plan.steps||[]).map((step,index)=>`<div class="deployment-command"><div class="deployment-command-head"><div class="deployment-command-label">${index+1}. ${h(step.label)}</div><button class="btn ghost" type="button" data-copy-command="${h(step.command)}">Copy</button></div><pre>${h(step.command)}</pre></div>`).join('')||'<div class="empty">No upgrade plan configured.</div>';
  }

  async function runBackup(){
    const button=document.getElementById('deploymentBackup');button.disabled=true;button.textContent='Creating verified backup…';
    try{await responseJson(await fetch('/api/backups/run',{method:'POST',headers:{'X-Hotpot-Action':'backup-now'}}));await loadDeployment(true)}
    catch(e){alert('Backup failed: '+e.message)}finally{button.disabled=false;button.textContent='Verified backup now'}
  }

  ensureDeploymentView();
  if(location.hash==='#deployment')showView('deployment',{updateHash:false});
})();
