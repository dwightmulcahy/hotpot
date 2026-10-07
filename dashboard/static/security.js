(()=>{
  const originalFetch=window.fetch.bind(window);
  let sessionPromise=null;

  async function loadSession(force=false){
    if(force)sessionPromise=null;
    if(!sessionPromise){
      sessionPromise=originalFetch('/api/session',{cache:'no-store'})
        .then(async response=>{
          if(!response.ok)throw new Error('session '+response.status);
          return response.json();
        })
        .catch(error=>{sessionPromise=null;throw error});
    }
    return sessionPromise;
  }

  window.fetch=async(input,init={})=>{
    const method=String(init.method||(input instanceof Request?input.method:'GET')).toUpperCase();
    const raw=typeof input==='string'?input:input.url;
    const url=new URL(raw,window.location.href);
    const mutation=url.origin===window.location.origin&&!['GET','HEAD','OPTIONS'].includes(method);
    if(!mutation)return originalFetch(input,init);

    async function send(forceSession=false){
      const session=await loadSession(forceSession);
      const headers=new Headers(init.headers||(input instanceof Request?input.headers:undefined));
      headers.set('X-Hotpot-CSRF',session.csrf_token);
      return originalFetch(input,{...init,headers});
    }

    let response=await send(false);
    if(response.status===401||response.status===403)response=await send(true);
    return response;
  };

  loadSession(false).catch(()=>{});
})();
