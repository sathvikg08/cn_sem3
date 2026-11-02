const $=id=>document.getElementById(id);
const navs=[...document.querySelectorAll('.nav')],pages=[...document.querySelectorAll('.page')];
function showPage(name){pages.forEach(p=>p.classList.toggle('hidden',p.id!==name));navs.forEach(n=>n.classList.toggle('active',n.dataset.tab===name));$('page-title').textContent=name==='storage'?'Distributed Storage':'SDN Network Topology';$('page-sub').textContent=name==='storage'?'Inspect file replicas, chunks and integrity across both backup nodes.':'Visualize alternate network paths and demonstrate failure recovery.'}
navs.forEach(n=>n.addEventListener('click',e=>{e.preventDefault();showPage(n.dataset.tab);history.replaceState(null,'','#'+n.dataset.tab)}));
showPage(location.hash==='#topology'?'topology':'storage');
let failed=false;
function event(message){const p=document.createElement('p'),t=document.createElement('time');t.textContent=new Date().toLocaleTimeString();p.append(t,document.createTextNode(message));$('events').prepend(p)}
function setFailure(next){
 failed=next;
 $('l-a1').classList.toggle('failed',failed);$('l-a2').classList.toggle('failed',failed);
 $('l-b1').classList.toggle('route-active',failed);$('l-b2').classList.toggle('route-active',failed);
 $('l-a1').classList.toggle('route-active',!failed);$('l-a2').classList.toggle('route-active',!failed);
 $('network-state').textContent=failed?'● Path A unavailable · Path B selected':'● All links active';
 $('network-state').className=failed?'':'good';
 $('route-state').textContent='Current route: '+(failed?'Path B':'Path A');
 $('active-route').textContent=failed?'Path B':'Path A';
 $('route-description').textContent=failed?'Alternate route selected in this visual demonstration.':'Primary path selected. Traffic can reach the backup network.';
 $('failure-event').textContent=failed?'Path A link disabled':'No failure detected';
 $('failure-description').textContent=failed?'Illustrative controller response: select Path B and install alternate forwarding rules.':'Use the controls to illustrate alternate-path selection.';
 event(failed?'DEMO: Path A marked failed; Path B highlighted as alternate.':'DEMO: Path A restored; primary route highlighted.');
}
$('fail-link').addEventListener('click',()=>setFailure(true));
$('restore-link').addEventListener('click',()=>setFailure(false));
$('refresh').addEventListener('click',async()=>{
 // Optional live integration: if the teammate provides these read-only endpoints,
 // the UI switches out of demo mode and displays their returned server status.
 try{
  const response=await fetch('/api/status',{headers:{Accept:'application/json'}});
  if(!response.ok)throw new Error('status endpoint unavailable');
  const data=await response.json();
  const a=data.servers?.A||data.server_a||{},b=data.servers?.B||data.server_b||{};
  const onlineA=Boolean(a.online??a.status==='online'),onlineB=Boolean(b.online??b.status==='online');
  $('status-a').textContent=onlineA?'ONLINE':'OFFLINE';$('status-a').className='status '+(onlineA?'online':'offline');
  $('status-b').textContent=onlineB?'ONLINE':'OFFLINE';$('status-b').className='status '+(onlineB?'online':'offline');
  $('online-count').innerHTML=`${Number(onlineA)+Number(onlineB)} <i>/ 2</i>`;
  $('controller-status').textContent=data.controller?.connected?'Connected':'Not connected';
  $('mode-pill').textContent='LIVE STATUS';$('mode-pill').style.color='#62dcb5';
  event('Live server status refreshed from /api/status.');
 }catch(err){$('mode-pill').textContent='DEMO DATA';$('mode-pill').style.color='';event('Live status API not found; showing illustrative sample data.');}
});
