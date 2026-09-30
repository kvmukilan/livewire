// Exercises the shipped dashboard script's state transitions without a browser.
// Rendering and device interaction still require separate manual QA.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const html=fs.readFileSync(path.join(__dirname,'../internal/webui/index.html'),'utf8');
const source=html.match(/<script>([\s\S]*?)<\/script>/)[1].replace("selectShape('one');refresh().then(poll).catch(e=>setPill(e.message,'bad'));",'');

function dashboard(){
 const elements=new Map();
 function element(id){if(!elements.has(id))elements.set(id,{value:'',textContent:'',innerHTML:'',content:'csrf',disabled:false,checked:false,dataset:{},style:{},options:[],classList:{toggle(){},add(){},remove(){}},setAttribute(){},addEventListener(){},focus(){},querySelector(){return element(id+'-child')},closest(){return element(id+'-parent')},insertAdjacentHTML(){}});return elements.get(id)}
 const context=vm.createContext({document:{getElementById:element,querySelector:element,querySelectorAll:()=>[],addEventListener(){}},setTimeout,clearTimeout,fetch:async()=>{throw new Error('unexpected network request')}});
 vm.runInContext(source,context);
 for(const [id,value]of Object.entries({pcap:'a.pcap',udpIdle:'30',attempts:'1',attemptGap:'0',secureTimeout:'30',verify:'lenient',targetIP:'127.0.0.1'}))element(id).value=value;
 return {context,element,run:code=>vm.runInContext(code,context)};
}
const result={capture:{packets:5,sessions:1},plan:{entries:[],profile:'functional'},sessions:[],selectedPackets:5,excludedPackets:0,mode:'application',readiness:{supported:true,route:'generic',requirements:['target device IP'],needsInterface:false}};

test('changing capture invalidates an old preview and disables Start',()=>{
 const d=dashboard();d.run('compiled={readiness:{supported:true}};updateControls()');assert.equal(d.element('runBtn').disabled,false);
 d.element('pcap').value='b.pcap';d.element('pcap').onchange();assert.equal(d.run('compiled'),null);assert.equal(d.element('runBtn').disabled,true);
});
test('a late inspection response cannot restore stale state',async()=>{
 const d=dashboard();let resolve;d.context.response=new Promise(r=>resolve=r);d.run('api=()=>response');
 const pending=d.run('compile()');d.element('pcap').value='b.pcap';d.element('pcap').onchange();resolve(result);await pending;
 assert.equal(d.run('compiled'),null);assert.equal(d.element('runBtn').disabled,true);
});
test('failed reinspection clears the previous successful preview',async()=>{
 const d=dashboard();d.run('compiled={readiness:{supported:true}};api=async()=>{throw new Error("invalid capture")};');await d.run('compile()');
 assert.equal(d.run('compiled'),null);assert.equal(d.element('runBtn').disabled,true);assert.match(d.element('formError').textContent,/invalid capture/);
});
test('two rapid Start actions submit only one run',async()=>{
 const d=dashboard();d.context.fixture=result;let submissions=0,resolve;
 d.context.submit=()=>{submissions++;return new Promise(r=>resolve=r)};
 d.run('renderPlan(fixture);compiledKey=JSON.stringify(planRequest());api=()=>submit();poll=async()=>{};');
 const first=d.run('run()');await d.run('run()');assert.equal(submissions,1);assert.equal(d.element('runBtn').disabled,true);resolve({started:true});await first;
});
test('zero gap is sent as zero; session selection cannot silently become all',async()=>{
 const d=dashboard();assert.equal(d.run('nonNegativeMS("attemptGap")'),0);
 d.run('selectedIDs=[]');await d.run('compile()');assert.equal(d.run('compiled'),null);assert.match(d.element('formError').textContent,/Select at least one/);
});

const handshakeOutcome={adapter:'tls-handshake',handshakeCompleted:true,completed:false,applicationReplayCompleted:false,verified:false,matched:false,requests:0,responses:0,reasonCode:'captured_plaintext_unavailable',protocolVersion:'TLS 1.3',peerIdentityChecked:true};
async function renderReports(outcomes,status={done:true,running:false,ok:false,applicationIncomplete:true}){
 const d=dashboard();d.context.reports=outcomes.map(outcome=>({outcome}));
 d.context.status=status;
 d.run("artifactItems=reports.map((_,i)=>i+'.report.json');api=async path=>reports[Number(decodeURIComponent(path.split('=')[1]).split('.')[0])];setPill('run failed','bad');");
 await d.run('renderResult(status)');return d;
}
test('verified handshake-only results show amber application-incomplete details',async()=>{
 for(const count of [1,2]){
  const d=await renderReports(Array.from({length:count},()=>({...handshakeOutcome})));
  assert.equal(d.element('jobPill-child').textContent,'application incomplete');
  assert.equal(d.element('jobPill-child').style.background,'var(--amber)');
  assert.match(d.element('metricLine').textContent,/Fresh TLS handshakes? completed/);
  assert.match(d.element('metricLine').textContent,/TLS 1.3; peer identity verified/);
  assert.match(d.element('metricLine').textContent,/Application replay remains incomplete and unverified/);
 }
});
test('certificate failures and failed earlier attempts remain failed',async()=>{
 const failed={...handshakeOutcome,handshakeCompleted:false,peerIdentityChecked:false,reasonCode:'execution_failed',error:'certificate verification failed'};
 for(const outcomes of [[failed],[failed,{...handshakeOutcome}],[{...handshakeOutcome},{...handshakeOutcome,error:'cleanup failed'}]]){
  const d=await renderReports(outcomes);assert.equal(d.element('jobPill-child').textContent,'run failed');assert.equal(d.element('jobPill-child').style.background,'var(--red)');
 }
});
test('missing reports, cancellation and partial attempts cannot become handshake-only completion',async()=>{
 for(const [outcomes,status] of [
  [[],{done:true,running:false,ok:false,applicationIncomplete:true}],
  [[{...handshakeOutcome}],{done:true,running:false,ok:false,applicationIncomplete:false}],
  [[{...handshakeOutcome}],{done:true,running:false,ok:false}],
  [[{...handshakeOutcome}],{done:false,running:true,ok:false,applicationIncomplete:true}],
 ]){
  const d=await renderReports(outcomes,status);assert.equal(d.element('jobPill-child').textContent,'run failed');assert.equal(d.element('jobPill-child').style.background,'var(--red)');
 }
});
