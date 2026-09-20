// JEV Sentinel local OpenCode plugin. No npm dependency or shell execution.
import { evaluate, veto, reason, text } from './_jev-sentinel/bridge.mjs';
export default async function JevSentinel() {
  return {
    'tool.execute.before': async (input, output) => {
      const r = await evaluate({harness:'opencode', stage:'tool_before', source:'agent',
        session_id:input.sessionID ?? '', tool_name:input.tool, tool_input:output.args, content:''});
      if (veto(r)) throw new Error(reason(r));
    },
    'tool.execute.after': async (input, output) => {
      const r = await evaluate({harness:'opencode', stage:'tool_after', source:'external',
        session_id:input.sessionID ?? '', tool_name:input.tool, tool_input:input.args,
        content:text({output:output.output, title:output.title, metadata:output.metadata})});
      if (veto(r)) {
        output.output = reason(r);
        output.title = 'JEV Sentinel quarantine';
        output.metadata = {};
      }
    },
  };
}
