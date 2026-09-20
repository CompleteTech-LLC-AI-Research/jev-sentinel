// JEV Sentinel Pi extension. Does not intercept /compact, /prune, or user_bash.
import { evaluate, veto, reason, text } from './_jev-sentinel/bridge.mjs';
const sid = (ctx) => ctx.sessionManager?.getSessionId?.() ?? '';
export default function JevSentinel(pi) {
  pi.on('input', async (event, ctx) => {
    // Only host-declared interactive/RPC input is eligible to supply a user goal.
    if (event.source !== 'interactive' && event.source !== 'rpc') return {action:'continue'};
    const r = await evaluate({harness:'pi', stage:'ingress', source:'user',
      session_id:sid(ctx), tool_name:'', tool_input:{}, content:event.text});
    if (veto(r)) {
      if (ctx.hasUI && ctx.ui?.notify) ctx.ui.notify(reason(r), 'warning');
      return {action:'handled'};
    }
    return {action:'continue'};
  });
  pi.on('tool_call', async (event, ctx) => {
    const r = await evaluate({harness:'pi', stage:'tool_before', source:'agent',
      session_id:sid(ctx), tool_name:event.toolName, tool_input:event.input, content:''});
    if (veto(r)) return {block:true, reason:reason(r)};
  });
  pi.on('tool_result', async (event, ctx) => {
    const r = await evaluate({harness:'pi', stage:'tool_after', source:'external',
      session_id:sid(ctx), tool_name:event.toolName, tool_input:event.input ?? {},
      content:text({content:event.content, details:event.details})});
    if (veto(r)) return {content:[{type:'text',text:reason(r)}], details:{}, isError:true};
  });
}
