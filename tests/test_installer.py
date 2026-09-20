import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from jev_sentinel.installer import *

NO_BIN=lambda _:None

class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='sentinel tests with spaces ')
        self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name).resolve()/'home'
        self.state=Path(self.tmp.name).resolve()/'state'

    def targets(self,names='all',profiles=(),which=NO_BIN):
        return select_targets(self.home,names,profiles,use_env=False,which=which)

    def plan(self,targets=None,mode=None,which=NO_BIN):
        return make_plan(targets or self.targets(),self.state,sys.executable,mode,which=which)

    def install(self,targets=None,mode=None):
        ts=targets or self.targets()
        return apply_operations(self.plan(ts,mode),ts,self.state)

    def test_detect_only_existing_roots(self):
        (self.home/'.claude').mkdir(parents=True)
        ts=self.targets('detected')
        self.assertEqual([t.harness for t in ts],['claude'])

    def test_plan_is_read_only(self):
        self.plan()
        self.assertFalse(self.state.exists())
        self.assertFalse(self.home.exists())

    def test_all_nine_installed_and_policy_local_shadow(self):
        manifest=self.install()
        self.assertEqual(len(manifest['targets']),9)
        policy=load_policy(self.state/'policy.json')
        self.assertEqual((policy['backend'],policy['mode']),('local','shadow'))
        self.assertTrue((self.home/'.openclaw/extensions/jev-sentinel/index.js').exists())
        self.assertTrue((self.home/'.hermes/plugins/jev-sentinel/__init__.py').exists())
        self.assertTrue((self.home/'.config/opencode/plugins/jev-sentinel.ts').exists())
        self.assertTrue((self.home/'.pi/agent/extensions/jev-sentinel.ts').exists())

    def test_preserve_existing_native_settings_and_hooks(self):
        path=self.home/'.claude/settings.json'
        path.parent.mkdir(parents=True)
        original={'env':{'FOO':'kept'},'permissions':{'deny':['Bash(rm:*)']},
                  'hooks':{'PreToolUse':[{'matcher':'Read','hooks':[{'type':'command','command':'echo existing'}]}]}}
        path.write_text(json.dumps(original))
        self.install(self.targets('claude'))
        after=json.loads(path.read_text())
        self.assertEqual(after['env'],original['env'])
        self.assertEqual(after['permissions'],original['permissions'])
        self.assertEqual(after['hooks']['PreToolUse'][0],original['hooks']['PreToolUse'][0])
        self.assertEqual(len(after['hooks']['PreToolUse']),2)

    def test_idempotent_no_duplicate_hooks(self):
        ts=self.targets('claude,codex,gemini,cursor,copilot')
        self.install(ts)
        before={str(o.path):file_bytes(o.path) for o in self.plan(ts)}
        self.install(ts)
        after={str(o.path):file_bytes(o.path) for o in self.plan(ts)}
        self.assertEqual(before,after)

    def test_uninstall_restores_exact_original_bytes(self):
        path=self.home/'.claude/settings.json'
        path.parent.mkdir(parents=True)
        original=b'{ "permissions": {"defaultMode": "default"} }\n'
        path.write_bytes(original)
        self.install(self.targets('claude'))
        uninstall(self.state,True)
        self.assertEqual(path.read_bytes(),original)
        self.assertFalse((self.state/'runtime/launch.py').exists())
        self.assertTrue((self.state/'policy.json').exists())

    def test_uninstall_conflict_makes_no_changes(self):
        self.install(self.targets('claude,codex'))
        path=self.home/'.claude/settings.json'
        path.write_text(path.read_text()+'\n')
        codex=self.home/'.codex/hooks.json'
        before=codex.read_bytes()
        with self.assertRaises(ValueError):
            uninstall(self.state,True)
        self.assertEqual(codex.read_bytes(),before)
        self.assertTrue((self.state/'runtime/launch.py').exists())

    def test_json5_refused_without_writes(self):
        path=self.home/'.openclaw/openclaw.json'
        path.parent.mkdir(parents=True)
        original=b'{ // comment\n plugins: {}\n}'
        path.write_bytes(original)
        with self.assertRaises(ValueError):
            self.plan(self.targets('openclaw'))
        self.assertEqual(path.read_bytes(),original)
        self.assertFalse(self.state.exists())

    def test_openclaw_preserves_allowlist_and_disable(self):
        path=self.home/'.openclaw/openclaw.json'
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({'plugins':{'enabled':False,'allow':['existing'],'deny':['jev-sentinel']}}))
        ts=self.targets('openclaw')
        self.install(ts)
        obj=json.loads(path.read_text())
        self.assertFalse(obj['plugins']['enabled'])
        self.assertEqual(obj['plugins']['allow'],['existing','jev-sentinel'])
        self.assertEqual(obj['plugins']['deny'],['jev-sentinel'])
        self.assertTrue(any('inactive' in x for x in ts[0].notes))

    def test_distinct_profiles_are_independently_installed(self):
        a=self.home/'claude-a'; b=self.home/'claude-b'
        ts=self.targets('claude',[f'claude={a}',f'claude={b}'])
        self.assertEqual(len(ts),2)
        self.assertNotEqual(ts[0].profile,ts[1].profile)
        self.install(ts)
        self.assertTrue((a/'settings.json').exists())
        self.assertTrue((b/'settings.json').exists())
        self.assertFalse((self.home/'.claude/settings.json').exists())

    def test_gemini_milliseconds_and_copilot_direct_exec(self):
        ops=self.plan(self.targets('gemini,copilot'))
        gem=json.loads(next(o.content for o in ops if o.path==self.home/'.gemini/settings.json'))
        self.assertEqual(gem['hooks']['BeforeTool'][0]['hooks'][0]['timeout'],12000)
        cop=json.loads(next(o.content for o in ops if o.path==self.home/'.copilot/hooks/jev-sentinel.json'))
        hook=cop['hooks']['preToolUse'][0]
        self.assertEqual(hook['exec'],sys.executable)
        self.assertNotIn('command',hook)
        self.assertEqual(hook['args'][0],'-I')

    def test_posix_paths_with_spaces_are_quoted(self):
        argv=['/folder with spaces/python','-I','/a/launch.py','--profile',"a'b"]
        self.assertEqual(shlex.split(shell_command(argv,False)),argv)

    def test_windows_quoting_and_metacharacter_refusal(self):
        command=shell_command([r'C:\Program Files\Python\python.exe','-I',r'C:\Me & You\launch.py'],True)
        self.assertIn('"C:\\Me & You\\launch.py"',command)
        with self.assertRaises(ValueError):
            shell_command([r'C:\%BAD%\python.exe'],True)

    @unittest.skipIf(os.name=='nt','symlink privilege differs on Windows')
    def test_symlink_destination_rejected(self):
        self.home.mkdir()
        target=self.home/'real';target.mkdir()
        (self.home/'.claude').symlink_to(target,target_is_directory=True)
        with self.assertRaises(ValueError):
            self.targets('claude')

    def test_operator_policy_is_retained_across_reinstall_uninstall(self):
        ts=self.targets('claude')
        self.install(ts)
        p=self.state/'policy.json'
        obj=json.loads(p.read_text());obj['backend']='jev'
        p.write_text(json.dumps(obj))
        self.install(ts)
        uninstall(self.state,True)
        self.assertEqual(json.loads(p.read_text())['backend'],'jev')

    def test_native_enable_failure_rolls_back_files(self):
        path=self.home/'.hermes/config.yaml'
        path.parent.mkdir(parents=True)
        path.write_text('existing: true\n')
        ts=self.targets('hermes')
        ops=self.plan(ts,which=lambda name:'/fake/hermes' if name=='hermes' else None)
        def fail(*args,**kwargs):
            path.write_text('partial: mutation\n')
            return SimpleNamespace(returncode=1)
        with self.assertRaises(ValueError):
            apply_operations(ops,ts,self.state,runner=fail)
        self.assertEqual(path.read_text(),'existing: true\n')
        self.assertFalse((self.home/'.hermes/plugins/jev-sentinel/__init__.py').exists())
        self.assertFalse((self.state/'install-manifest.json').exists())

    def test_native_enable_success_is_backed_up(self):
        path=self.home/'.hermes/config.yaml'
        path.parent.mkdir(parents=True); path.write_text('existing: true\n')
        ts=self.targets('hermes')
        ops=self.plan(ts,which=lambda name:'/fake/hermes' if name=='hermes' else None)
        def enable(argv,**kwargs):
            self.assertEqual(argv[-3:],['plugins','enable','jev-sentinel'])
            self.assertEqual(kwargs['env']['HERMES_HOME'],str(path.parent))
            path.write_text('existing: true\nplugins:\n  enabled: [jev-sentinel]\n')
            return SimpleNamespace(returncode=0)
        apply_operations(ops,ts,self.state,runner=enable)
        uninstall(self.state,True)
        self.assertEqual(path.read_text(),'existing: true\n')

    def test_interrupted_journal_is_preserved(self):
        self.state.mkdir()
        journal=self.state/'transaction.json';journal.write_text('{"important":"recovery"}')
        with self.assertRaises(ValueError):
            apply_operations(self.plan(self.targets('claude')),self.targets('claude'),self.state)
        self.assertEqual(journal.read_text(),'{"important":"recovery"}')

    def test_installed_hook_command_executes_without_source_cwd(self):
        self.install(self.targets('claude'),mode='enforce')
        config=json.loads((self.home/'.claude/settings.json').read_text())
        command=config['hooks']['PreToolUse'][0]['hooks'][0]['command']
        proc=subprocess.run(shlex.split(command),input=json.dumps({'tool_name':'Bash','tool_input':{'command':'echo JEV_SENTINEL_TEST_BLOCK'}}).encode(),
                            cwd=self.tmp.name,capture_output=True,timeout=12)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['hookSpecificOutput']['permissionDecision'],'deny')

if __name__=='__main__':unittest.main()
