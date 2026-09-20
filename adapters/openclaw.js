// JEV Sentinel OpenClaw plugin. Post-call observations cannot reverse side effects.
import { definePluginEntry } from 'openclaw/plugin-sdk/plugin-entry';
import { evaluate, veto, reason, text } from './bridge.mjs';
export default definePluginEntry({
  id:'jev-sentinel', name:'JEV Sentinel',
  description:'Opt-in semantic security assessments and pre-tool vetoes.',
  register(api) {
    api.on('before_tool_call', async (event, ctx) => {
      const r = await evaluate({harness:'openclaw', stage:'tool_before', source:'agent',
        session_id:ctx.sessionKey ?? ctx.sessionId ?? '', tool_name:event.toolName,
        tool_input:event.params, content:''});
      if (veto(r)) return {block:true, blockReason:reason(r)};
    }, {priority:1000});
    api.on('after_tool_call', async (event, ctx) => {
      await evaluate({harness:'openclaw', stage:'tool_after', source:'external',
        session_id:ctx.sessionKey ?? ctx.sessionId ?? '', tool_name:event.toolName,
        tool_input:event.params ?? {}, content:text(event.result)});
      // Observer only: a finding is audited and latches subsequent sensitive calls.
    });
  },
});
