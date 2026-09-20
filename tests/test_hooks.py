import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from jev_sentinel.core import DEFAULT_POLICY, failure_result
from jev_sentinel.hooks import EVENTS, normalize, render
from jev_sentinel.cli import bounded_assessment

ROOT=Path(__file__).resolve().parents[1]

class HookTests(unittest.TestCase):
    def test_native_pretool_veto_shapes(self):
        verdict=failure_result()
        expected={
            'claude':('PreToolUse','hookSpecificOutput'),
            'codex':('PreToolUse','hookSpecificOutput'),
            'gemini':('BeforeTool','decision'),
            'cursor':('preToolUse','permission'),
            'copilot':('preToolUse','permissionDecision'),
        }
        for h,(event,key) in expected.items():
            with self.subTest(harness=h):
                out=render(h,event,verdict)
                self.assertIn(key,out)
                self.assertNotIn('ask',json.dumps(out))
                if h in ('claude','codex'):
                    self.assertEqual(out[key]['permissionDecision'],'deny')
                else:
                    self.assertEqual(out[key],'deny')

    def test_defer_preserves_other_native_authorization(self):
        for h,events in EVENTS.items():
            for e,stage in events.items():
                with self.subTest(h=h,e=e):
                    out=render(h,e,{**failure_result(),'decision':'DEFER'})
                    if h=='cursor' and stage=='tool_before':
                        self.assertEqual(out,{'permission':'allow'})
                    elif h=='cursor' and stage=='ingress':
                        self.assertEqual(out,{'continue':True})
                    else:
                        self.assertEqual(out,{})

    def test_codex_does_not_receive_unsupported_fields(self):
        out=render('codex','PostToolUse',failure_result(),{'tool_name':'mcp__test__read'})
        self.assertNotIn('updatedMCPToolOutput',json.dumps(out))
        self.assertNotIn('updatedToolOutput',json.dumps(out))
        pre=render('codex','PreToolUse',failure_result())
        self.assertNotIn('continue',pre)

    def test_claude_mcp_result_can_be_replaced(self):
        out=render('claude','PostToolUse',failure_result(),{'tool_name':'mcp__test__read'})
        self.assertIn('updatedMCPToolOutput',out['hookSpecificOutput'])

    def test_claude_bash_replacement_requires_known_shape(self):
        raw={'tool_name':'Bash','tool_response':{'stdout':'x','stderr':'','interrupted':False,'isImage':False}}
        out=render('claude','PostToolUse',failure_result(),raw)
        self.assertIn('updatedToolOutput',out['hookSpecificOutput'])
        out=render('claude','PostToolUse',failure_result(),{'tool_name':'Bash','tool_response':'unknown schema'})
        self.assertNotIn('updatedToolOutput',out['hookSpecificOutput'])

    def test_observer_returns_no_fake_veto(self):
        for h in ('cursor','copilot'):
            self.assertEqual(render(h,'postToolUse',failure_result()),{})
        self.assertEqual(render('copilot','userPromptSubmitted',failure_result()),{})

    def test_ingress_payload_cannot_override_provenance(self):
        e=normalize('claude','UserPromptSubmit',{'prompt':'hello','source':'external','harness':'wrong','stage':'egress'},'p')
        self.assertEqual((e['stage'],e['source'],e['harness']),('ingress','user','claude'))

    def test_copilot_string_tool_args_decoded(self):
        e=normalize('copilot','preToolUse',{'toolName':'bash','toolArgs':'{"command":"echo hi"}','sessionId':'s'},'p')
        self.assertEqual(e['tool_input'],{'command':'echo hi'})
        self.assertEqual(e['session_id'],'s')

    def test_missing_result_is_error_not_clean(self):
        with self.assertRaises(ValueError):
            normalize('codex','PostToolUse',{'tool_name':'Bash','tool_input':{}},'p')

    def test_process_watchdog_timeout_returns_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp).resolve()/'policy.json'
            p.write_text(json.dumps({**DEFAULT_POLICY,'mode':'enforce'}))
            with patch('jev_sentinel.cli.subprocess.run',side_effect=subprocess.TimeoutExpired('worker',6)):
                r=bounded_assessment({},p)
            self.assertEqual(r['decision'],'REVIEW')
            self.assertTrue(r['enforced'])

    def test_actual_cli_native_canary_and_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp).resolve()/'policy.json'
            p.write_text(json.dumps({**DEFAULT_POLICY,'mode':'enforce'}))
            args=[sys.executable,'-I',str(ROOT/'launch.py'),'hook','--policy',str(p),
                  '--harness','codex','--event','PreToolUse','--profile','test']
            for body in ('{',json.dumps({'tool_name':'Bash','tool_input':{'command':'echo JEV_SENTINEL_TEST_BLOCK'}})):
                with self.subTest(body=body):
                    r=subprocess.run(args,input=body.encode(),capture_output=True,timeout=10)
                    self.assertEqual(r.returncode,0,r.stderr)
                    out=json.loads(r.stdout)
                    self.assertEqual(out['hookSpecificOutput']['permissionDecision'],'deny')

    def test_cli_oversize_input_is_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp).resolve()/'policy.json'
            p.write_text(json.dumps({**DEFAULT_POLICY,'mode':'enforce'}))
            r=subprocess.run([sys.executable,'-I',str(ROOT/'launch.py'),'check','--policy',str(p)],
                input=b' '*131073,capture_output=True,timeout=10)
            out=json.loads(r.stdout)
            self.assertEqual(out['decision'],'REVIEW')

if __name__=='__main__': unittest.main()
