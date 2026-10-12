// Named E2E: a live CLI app-server owns an idle thread before delivery.
// Native Node WebSocket; no packages, auth files or downloaded code.
// node codex_courier_live.mjs CODEX_EXE COURIER_EXE SCRATCH_DIRECTORY
import {spawn} from 'node:child_process';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {createServer} from 'node:net';
const [codex, courierBin, scratch] = process.argv.slice(2);
if (!codex || !courierBin || !scratch) throw Error('CODEX_EXE COURIER_EXE SCRATCH_DIRECTORY required');
mkdirSync(scratch, {recursive:true});
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function port() {
    const server = createServer();
    await new Promise(resolve=>server.listen(0, '127.0.0.1', resolve));
    const value = server.address().port;
    await new Promise(resolve=>server.close(resolve));
    return value;
}
const wsPort = await port(), httpPort = await port();
const env = {...process.env};
for (const name of ['NO_COLOR','CI','TERM']) delete env[name];
const server = spawn(codex, ['app-server','--listen',`ws://127.0.0.1:${wsPort}`],
    {env, windowsHide:true, stdio:'ignore'});
let ws, courier;
const pending = new Map(), notices=[];
let nextId=0;
function rpc(method, params) {
    const id=++nextId;
    return new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>{pending.delete(id);reject(Error(`${method} timed out`));},20000);
        pending.set(id,{resolve,reject,timer});
        ws.send(JSON.stringify({id,method,params}));
    });
}
try {
    for(let i=0;i<100;i++) {
        try {
            ws = new WebSocket(`ws://127.0.0.1:${wsPort}`);
            await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
            break;
        } catch { await pause(100); }
    }
    if (!ws || ws.readyState!==1) throw Error('CLI server did not start');
    ws.onmessage=event=>{
        const value=JSON.parse(event.data);
        if (pending.has(value.id)) {
            const call=pending.get(value.id);pending.delete(value.id);clearTimeout(call.timer);
            value.error ? call.reject(Error('RPC refused')) : call.resolve(value.result);
        } else notices.push(value);
    };
    await rpc('initialize',{clientInfo:{name:'mail4agent_live_observer',version:'1'}});
    ws.send(JSON.stringify({method:'initialized'}));
    const started=await rpc('thread/start',{cwd:scratch,approvalPolicy:'never',
        sandbox:'read-only', developerInstructions:'Connector live test. Never use tools. Reply exactly M4A_CLI_LIVE_OK to a delivery probe.'});
    const thread=started.thread.id;
    courier=spawn(courierBin,['--session',thread,'--nick','receiver','--endpoint',
        `ws://127.0.0.1:${wsPort}`,'--bind',`127.0.0.1:${httpPort}`,'--state',join(scratch,'cli-delivered.ids')],
        {env,windowsHide:true,stdio:'ignore'});
    for(let i=0;i<100;i++) {
        try { if((await fetch(`http://127.0.0.1:${httpPort}/health`)).ok) break; } catch {}
        await pause(100);
    }
    const letter={body:'Delivery probe. Reply exactly M4A_CLI_LIVE_OK. No tools.',from_nick:'sender',
        to:'receiver',event_id:`live-${Date.now()}`};
    const send=()=>fetch(`http://127.0.0.1:${httpPort}/delivery`,{method:'POST',
        headers:{'Content-Type':'application/json'},body:JSON.stringify(letter)}).then(async response=>({code:response.status,...await response.json()}));
    const receipt=await send();
    if(receipt.code!==200||receipt.status!=='delivered')throw Error('courier rejected idle delivery');
    const duplicate=await send();
    if(duplicate.status!=='duplicate')throw Error('duplicate was delivered again');
    const exited=new Promise(resolve=>courier.once('exit',resolve));
    courier.kill();await exited;
    courier=spawn(courierBin,['--session',thread,'--nick','receiver','--endpoint',
        `ws://127.0.0.1:${wsPort}`,'--bind',`127.0.0.1:${httpPort}`,'--state',join(scratch,'cli-delivered.ids')],
        {env,windowsHide:true,stdio:'ignore'});
    for(let i=0;i<100;i++) {
        try { if((await fetch(`http://127.0.0.1:${httpPort}/health`)).ok) break; } catch {}
        await pause(100);
    }
    if((await send()).status!=='duplicate')throw Error('restart lost delivery dedupe');
    const deadline=Date.now()+120000;
    while(!notices.some(n=>n.method==='turn/completed')&&Date.now()<deadline)await pause(250);
    const completed=notices.find(n=>n.method==='turn/completed');
    if(completed?.params?.turn?.status!=='completed')throw Error('live turn did not complete');
    const reply=notices.filter(n=>n.method==='item/agentMessage/delta').map(n=>n.params.delta).join('');
    if(!reply.includes('M4A_CLI_LIVE_OK'))throw Error('live reply marker missing');
    if(server.exitCode!==null)throw Error('owner server exited');
    if(notices.filter(n=>n.method==='turn/started').length!==1)throw Error('more than one turn started');
    console.log(JSON.stringify({scenario:'codex_courier_cli_idle',receipt:receipt.status,
        duplicate:duplicate.status,restartDuplicate:true,turnStatus:completed.params.turn.status,replyMarker:true,
        ownerStayedAlive:true,turnsStarted:notices.filter(n=>n.method==='turn/started').length}));
} finally {
    ws?.close();courier?.kill();server.kill();
}
