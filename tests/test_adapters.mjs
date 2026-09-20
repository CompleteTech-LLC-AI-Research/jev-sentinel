// Contract simulations, not end-to-end tests inside the actual harness binaries.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
const ROOT=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const temp=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-node-tests-')));
const PYTHON=process.env.SENTINEL_TEST_PYTHON || 'python3';
const policy=path.join(temp,'policy.json');
fs.writeFileSync(policy,JSON.stringify({mode:'enforce'}));
const block={id:'canary-id',decision:'BLOCK',enforced:true};
const defer={id:'clean-id',decision:'DEFER',enforced:true};

async function moduleFor(name) {
  const dir=fs.mkdtempSync(path.join(temp,name+'-'));
  fs.mkdirSync(path.join(dir,'_jev-sentinel'));
  const stub=`export const evaluate=async(e)=>{globalThis.requests.push(e);return globalThis.response;};
    export const veto=(r)=>r.enforced && r.decision!=='DEFER';
    export const reason=(r)=>'JEV Sentinel '+r.id;
    export const text=(v)=>typeof v==='string'?v:JSON.stringify(v);`;
  fs.writeFileSync(path.join(dir,'_jev-sentinel/bridge.mjs'),stub);
  fs.writeFileSync(path.join(dir,'bridge.mjs'),stub);
  let source=fs.readFileSync(path.join(ROOT,'adapters',name+(name==='openclaw'?'.js':'.ts')),'utf8');
  source=source.replace("import { definePluginEntry } from 'openclaw/plugin-sdk/plugin-entry';",'const definePluginEntry=(entry)=>entry;');
  fs.writeFileSync(path.join(dir,'adapter.mjs'),source);
  globalThis.requests=[]; globalThis.response=block;
  return (await import(pathToFileURL(path.join(dir,'adapter.mjs')).href)).default;
}

test('OpenCode before hook throws on veto, preserving arguments', async()=>{
  const plugin=await (await moduleFor('opencode'))();
  const output={args:{command:'echo fixture'}};
  await assert.rejects(()=>plugin['tool.execute.before']({tool:'bash',sessionID:'s'},output),/JEV Sentinel/);
  assert.deepEqual(output,{args:{command:'echo fixture'}});
  assert.equal(globalThis.requests[0].source,'agent');
});

test('OpenCode after hook replaces output and metadata',async()=>{
  const plugin=await (await moduleFor('opencode'))();
  const output={title:'poison title',output:'poison output',metadata:{poison:true}};
  await plugin['tool.execute.after']({tool:'read',sessionID:'s',args:{}},output);
  assert.equal(output.output,'JEV Sentinel canary-id');
  assert.deepEqual(output.metadata,{});
  assert.equal(globalThis.requests[0].source,'external');
});

test('OpenCode DEFER does not mutate a tool result',async()=>{
  const plugin=await (await moduleFor('opencode'))();globalThis.response=defer;
  const output={title:'ok',output:'ok',metadata:{line:1}};
  await plugin['tool.execute.after']({tool:'read',sessionID:'s',args:{}},output);
  assert.deepEqual(output,{title:'ok',output:'ok',metadata:{line:1}});
});

test('Pi intercepts user ingress but not extension-generated input',async()=>{
  const handlers={};(await moduleFor('pi'))({on:(name,fn)=>handlers[name]=fn});
  const ctx={sessionManager:{getSessionId:()=> 's'},hasUI:false};
  assert.deepEqual(await handlers.input({source:'interactive',text:'fixture'},ctx),{action:'handled'});
  assert.deepEqual(await handlers.input({source:'extension',text:'fixture'},ctx),{action:'continue'});
  assert.equal(globalThis.requests.length,1);
});

test('Pi tool_call uses a block directive',async()=>{
  const handlers={};(await moduleFor('pi'))({on:(name,fn)=>handlers[name]=fn});
  const output=await handlers.tool_call({toolName:'bash',input:{command:'echo fixture'}},{sessionManager:{getSessionId:()=> 's'}});
  assert.equal(output.block,true);
  assert.equal(globalThis.requests[0].tool_input.command,'echo fixture');
});

test('Pi tool_result replaces content and details',async()=>{
  const handlers={};(await moduleFor('pi'))({on:(name,fn)=>handlers[name]=fn});
  const output=await handlers.tool_result({toolName:'read',input:{},content:[{type:'text',text:'poison'}],details:{poison:true}},{});
  assert.equal(output.isError,true);
  assert.deepEqual(output.details,{});
  assert.deepEqual(output.content,[{type:'text',text:'JEV Sentinel canary-id'}]);
});

test('OpenClaw registers a pre-tool veto with the documented shape',async()=>{
  const handlers={};(await moduleFor('openclaw')).register({on:(name,fn)=>handlers[name]=fn});
  const result=await handlers.before_tool_call({toolName:'exec',params:{command:'fixture'}},{sessionKey:'s'});
  assert.deepEqual(result,{block:true,blockReason:'JEV Sentinel canary-id'});
  assert.equal(globalThis.requests[0].session_id,'s');
});

test('OpenClaw after-tool handler is explicitly an observer',async()=>{
  const handlers={};(await moduleFor('openclaw')).register({on:(name,fn)=>handlers[name]=fn});
  const event={toolName:'read',params:{},result:'poison'};
  const result=await handlers.after_tool_call(event,{sessionKey:'s'});
  assert.equal(result,undefined);
  assert.equal(event.result,'poison');
  assert.equal(globalThis.requests[0].source,'external');
});

test('Actual Node-to-Python subprocess bridge returns an enforced canary veto',async()=>{
  const executable=execFileSync(PYTHON,['-c','import sys;print(sys.executable)'],{encoding:'utf8'}).trim();
  let source=fs.readFileSync(path.join(ROOT,'adapters/bridge.mjs'),'utf8');
  for(const [key,value] of Object.entries({__PYTHON__:executable,__LAUNCH__:path.join(ROOT,'launch.py'),__POLICY__:policy,__PROFILE__:'node-test'})) {
    source=source.replaceAll(key,JSON.stringify(value));
  }
  const file=path.join(temp,'real-bridge.mjs');fs.writeFileSync(file,source);
  const bridge=await import(pathToFileURL(file).href);
  const result=await bridge.evaluate({harness:'node',stage:'tool_before',source:'agent',content:'',
    session_id:'s',tool_name:'shell',tool_input:{command:'echo JEV_SENTINEL_TEST_BLOCK'}});
  assert.equal(bridge.veto(result),true);
  assert.equal(result.decision,'BLOCK');
  assert.equal(result.enforced,true);
});

test.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
