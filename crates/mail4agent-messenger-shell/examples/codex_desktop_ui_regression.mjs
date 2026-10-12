// Named regression: real courier -> isolated Desktop IPC mock -> installed UI predicates.
// Execution decision: only the three statically inspected pure udn/ddn/fdn functions
// are evaluated, in an empty VM. Never import the Desktop bundle or contact its pipe.
// node codex_desktop_ui_regression.mjs APP_ASAR COURIER_EXE SCRATCH_DIRECTORY
import {openSync,readSync,closeSync,mkdirSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import assert from 'node:assert/strict';
const [asar,courierBin,scratch]=process.argv.slice(2);
if(!asar||!courierBin||!scratch)throw Error('APP_ASAR COURIER_EXE SCRATCH_DIRECTORY required');
const fd=openSync(asar,'r');
function bytes(position,size){const result=Buffer.alloc(size);assert.equal(readSync(fd,result,0,size,position),size);return result;}
const header=bytes(0,16),tree=JSON.parse(bytes(16,header.readUInt32LE(12)).toString());
let entry=tree;
for(const name of ['webview','assets','app-shared-737655e1fb23.js'])entry=entry.files[name];
assert(entry.size<8*1024*1024);
const bundle=bytes(8+header.readUInt32LE(4)+Number(entry.offset),entry.size).toString();
closeSync(fd);
function extract(name){
 const start=bundle.indexOf(`function ${name}(e){`);assert(start>=0);
 let depth=0;
 for(let end=bundle.indexOf('{',start);end<start+1024;end++){
  if(bundle[end]==='{')depth++;
  if(bundle[end]==='}'&&--depth===0)return bundle.slice(start,end+1);
 }
 throw Error('inspected UI function shape changed');
}
const functions=['udn','ddn','fdn'].map(extract).join('\n');
assert(functions.includes('e.text_elements.some('));
const ui=runInNewContext(`${functions};({udn,ddn})`,Object.create(null),{timeout:1000});
let oldPayloadFailed=false;
try{ui.udn([{type:'text',text:'legacy'}]);}catch(error){oldPayloadFailed=error.name==='TypeError';}
assert(oldPayloadFailed,'legacy input must reproduce the renderer predicate failure');
for(const turn of [{params:{input:[{type:'text',text:'legacy'}]},items:[]},
 {params:{input:[]},items:[{type:'userMessage',content:[{type:'text',text:'legacy'}]}]}]){
 let failed=false;try{ui.ddn(turn);}catch(error){failed=error.name==='TypeError';}assert(failed);
}
mkdirSync(scratch,{recursive:true});
const endpoint=process.platform==='win32'?`\\\\.\\pipe\\m4a-desktop-ui-regression-${process.pid}`:join(scratch,`mock-${process.pid}.sock`);
let active=false,starts=0,captured;
const sockets=new Set();
const ipc=createServer(socket=>{
 sockets.add(socket);socket.on('close',()=>sockets.delete(socket));
 let buffer=Buffer.alloc(0);
 const send=value=>{const data=Buffer.from(JSON.stringify(value)),frame=Buffer.alloc(4);frame.writeUInt32LE(data.length);socket.write(Buffer.concat([frame,data]));};
 socket.on('data',chunk=>{
  buffer=Buffer.concat([buffer,chunk]);
  while(buffer.length>=4&&buffer.length>=4+buffer.readUInt32LE(0)){
   const size=buffer.readUInt32LE(0),request=JSON.parse(buffer.subarray(4,4+size));buffer=buffer.subarray(4+size);
   if(request.method==='thread-stream-following-changed'){
    assert.equal(request.params.following,true);
    send({type:'broadcast',method:'thread-stream-state-changed',version:11,sourceClientId:'owner',params:{hostId:'local',conversationId:'existing-thread',change:{type:'snapshot',conversationState:{id:'existing-thread',resumeState:'resumed',threadRuntimeStatus:{type:active?'active':'idle'},turns:[],turnHistory:{kind:'canonical',history:{entitiesByKey:active?{current:{turnId:'active-turn',status:'inProgress'}}:{}}}}}}});
    continue;
   }
   let result;
   if(request.method==='initialize')result={clientId:'courier'};
   else if(request.method==='thread-owner-discovery')result={supportsUntrustedAppInput:true};
   else{
    assert.equal(request.method,'thread-follower-start-turn');assert.equal(active,false);
    assert.equal(request.targetClientId,'owner');assert.equal(request.params.conversationId,'existing-thread');
    captured=request.params.turnStart.request;starts++;
    result={result:{turn:{id:'accepted'}}};
   }
   send({type:'response',requestId:request.requestId,resultType:'success',handledByClientId:'owner',result});
  }
 });
});
await new Promise(resolve=>ipc.listen(endpoint,resolve));
const portServer=createServer();await new Promise(resolve=>portServer.listen(0,'127.0.0.1',resolve));
const port=portServer.address().port;await new Promise(resolve=>portServer.close(resolve));
const courier=spawn(courierBin,['--session','existing-thread','--nick','receiver','--endpoint',`desktop://${endpoint}`,'--bind',`127.0.0.1:${port}`,'--state',join(scratch,`journal-${process.pid}.ids`)],{windowsHide:true,stdio:'ignore'});
try{
 for(let i=0;i<100;i++){
  try{if((await fetch(`http://127.0.0.1:${port}/health`)).ok)break;}catch{}
  await new Promise(resolve=>setTimeout(resolve,100));
 }
 const send=event=>fetch(`http://127.0.0.1:${port}/delivery`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({body:'UI fixture',from_nick:'sender',to:'receiver',event_id:event})});
 const accepted=await send('idle');assert.equal(accepted.status,200);
 assert.deepEqual(captured.input[0].text_elements,[]);
 assert.equal(ui.udn(captured.input),false);
 assert.equal(ui.ddn({params:captured,items:[]}),false);
 assert.equal(ui.ddn({params:{input:[]},items:[{type:'userMessage',content:captured.input}]}),false);
 active=true;
 const busy=await send('busy');assert.equal(busy.status,503);assert.equal(starts,1);
 active=false;
 const retried=await send('busy');assert.equal(retried.status,200);assert.equal(starts,2);
 assert.equal(ui.ddn({params:captured,items:[]}),false);
 console.log(JSON.stringify({scenario:'codex_desktop_ui_regression',legacyPredicateThrows:true,installedUdnPassed:true,installedDdnPassed:true,idleStarts:starts,busyStatus:busy.status,busyEventRetried:true,ownerChatContacted:false}));
}finally{
 const exited=new Promise(resolve=>courier.once('exit',resolve));
 courier.kill();if(courier.exitCode===null)await exited;
 for(const socket of sockets)socket.destroy();
 await new Promise(resolve=>ipc.close(resolve));
}
