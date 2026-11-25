let refreshInFlight: Promise<boolean> | null = null;
async function refreshSession(): Promise<boolean> {
  if (!refreshInFlight) refreshInFlight = fetch('/api/auth/refresh', {method:'POST', credentials:'same-origin', cache:'no-store'}).then(r=>r.ok).catch(()=>false).finally(()=>{refreshInFlight=null});
  return refreshInFlight;
}
export async function api<T>(path:string, options:RequestInit={}, retry=true):Promise<T> {
  const headers=new Headers(options.headers); if(options.body)headers.set('Content-Type','application/json');
  const init:RequestInit={...options, headers, credentials:'same-origin',cache:'no-store'};
  let response=await fetch('/api'+path,init);
  if(response.status===401&&retry&&!path.startsWith('/auth/')&&!path.endsWith('/consume')&&await refreshSession())response=await fetch('/api'+path,init);
  const body=await response.json().catch(()=>({error:'Unexpected API response'}));
  if(!response.ok)throw new Error(body.error||`Request failed (${response.status})`);
  return body as T;
}
export const post=(body:unknown):RequestInit=>({method:'POST',body:JSON.stringify(body)});
export const message=(e:unknown)=>e instanceof Error?e.message:'Unexpected error';
