"""Network-free, plan-first native adapter installer with backups and safe rollback.

No harness, model, npm package, service, trust approval, or credential is installed.
Run as the harness user, never with sudo simply to reach more profiles.
"""
from __future__ import annotations
import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import time
from typing import Any

from . import __version__
from .cli import atomic
from .core import DEFAULT_POLICY, dumps, load_policy, private_dir, reject_symlinks, strict_json
from .hooks import EVENTS

ROOT = Path(__file__).resolve().parent.parent
HARNESSES = ('openclaw','hermes','opencode','codex','claude','pi','gemini','cursor','copilot')
ALIASES = {'claude-code':'claude','codex-jev':'codex','gemini-cli':'gemini','copilot-cli':'copilot'}
ENV_ROOTS = {'openclaw':'OPENCLAW_STATE_DIR', 'hermes':'HERMES_HOME',
             'opencode':'OPENCODE_CONFIG_DIR','codex':'CODEX_HOME',
             'claude':'CLAUDE_CONFIG_DIR','copilot':'COPILOT_HOME', 'pi':'PI_CODING_AGENT_DIR'}
BINARIES = {'cursor':'cursor-agent'}

@dataclass
class Target:
    harness: str
    root: Path
    detected: bool
    notes: list[str]

    @property
    def profile(self):
        return self.harness + '-' + hashlib.sha256(str(self.root).encode()).hexdigest()[:16]

@dataclass
class Operation:
    path: Path
    content: bytes | None
    kind: str = 'owned'  # shared configs may exist; unknown owned files may not be replaced
    native_command: list[str] | None = None
    native_env: dict[str,str] | None = None


def canonical(name):
    name = ALIASES.get(name, name)
    if name not in HARNESSES:
        raise ValueError('Unknown harness: ' + name)
    return name


def absolute(path):
    value = Path(path).expanduser()
    if not value.is_absolute():
        raise ValueError('Use an absolute path: ' + str(path))
    return Path(os.path.abspath(value))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()


def defaults(home, use_env=True):
    paths = {h: home / ('.' + h) for h in HARNESSES}
    paths['opencode'] = (Path(os.environ.get('XDG_CONFIG_HOME', str(home / '.config'))) if use_env else home / '.config') / 'opencode'
    paths['pi'] = home / '.pi/agent'
    if use_env:
        for h, variable in ENV_ROOTS.items():
            if os.environ.get(variable):
                paths[h] = absolute(os.environ[variable])
    return paths


def select_targets(home, selection='detected', profiles=(), use_env=True, which=shutil.which):
    roots = defaults(home, use_env)
    overrides = {}
    for spec in profiles:
        name, sep, value = spec.partition('=')
        if not sep:
            raise ValueError('--profile must be HARNESS=/absolute/config/root')
        h = canonical(name)
        overrides.setdefault(h, []).append(absolute(value))
    if selection in ('detected', 'auto'):
        chosen = [h for h in HARNESSES if roots[h].is_dir() or which(BINARIES.get(h,h)) or h in overrides]
    elif selection == 'all':
        chosen = list(HARNESSES)
    else:
        chosen = list(dict.fromkeys(canonical(x.strip()) for x in selection.split(',') if x.strip()))
        chosen += [h for h in overrides if h not in chosen]
    targets = []
    for h in chosen:
        for candidate_root in dict.fromkeys(overrides.get(h, [roots[h]])):
            root = absolute(candidate_root)
            reject_symlinks(root)
            found = root.is_dir() or bool(which(BINARIES.get(h,h)))
            notes = []
            if not found:
                notes.append('Harness not detected; explicit target will be staged, not installed or started.')
            if h == 'codex':
                notes.append('Restart and approve the exact hook commands in Codex /hooks; trust is NOT bypassed. Hooks disabled by native policy remain disabled.')
            elif h == 'hermes':
                notes.append('Native hermes plugins enable runs on --apply when the CLI is on PATH; otherwise activation remains pending.')
            else:
                notes.append('Reload/restart the harness and complete any native plugin/hook trust review.')
            if h == 'openclaw' and use_env and os.environ.get('OPENCLAW_CONFIG_PATH') and h not in overrides:
                raise ValueError('OPENCLAW_CONFIG_PATH is set. Use --profile openclaw=/absolute/config/root; this installer requires openclaw.json in that root and does not guess another file.')
            targets.append(Target(h, root, found, notes))
    return targets


def read_object(path):
    reject_symlinks(path)
    if not path.exists():
        return {}
    if path.stat().st_size > 2_000_000:
        raise ValueError('Configuration exceeds 2 MB: ' + str(path))
    try:
        obj = strict_json(path.read_bytes())
    except Exception as e:
        raise ValueError('Refusing to rewrite non-strict JSON/JSON5/JSONC: ' + str(path) + '. Preserve comments and configure this profile separately.') from e
    if not isinstance(obj, dict):
        raise ValueError('Expected a JSON object: ' + str(path))
    return obj


def child_object(parent, key):
    result = parent.setdefault(key, {})
    if not isinstance(result, dict):
        raise ValueError('Expected object at setting: ' + key)
    return result


def child_list(parent, key):
    result = parent.setdefault(key, [])
    if not isinstance(result, list):
        raise ValueError('Expected array at setting: ' + key)
    return result


def shell_command(argv, windows=None):
    windows = os.name == 'nt' if windows is None else windows
    if windows:
        # cmd.exe expands % and ! even when quoted. Refuse unsafe profile paths.
        if any(any(c in a for c in '%!\r\n"') for a in argv):
            raise ValueError('Unsupported Windows shell path characters: %, !, quote, or newline')
        return ' '.join('"' + a + '"' for a in argv)
    return shlex.join(argv)


def substitutions(source, python, launch, policy, profile):
    for marker, value in {'__PYTHON__':python, '__LAUNCH__':str(launch), '__POLICY__':str(policy), '__PROFILE__':profile}.items():
        source = source.replace(marker, json.dumps(value))
    return source


def native_hooks(target, runtime, policy, python):
    h = target.harness
    root = target.root
    path = root / ('hooks/jev-sentinel.json' if h == 'copilot' else ('hooks.json' if h in ('codex','cursor') else 'settings.json'))
    obj = read_object(path)
    if h in ('copilot','cursor'):
        if obj.get('version', 1) != 1:
            raise ValueError('Unsupported native hooks schema version: ' + str(path))
        obj['version'] = 1
    hooks = child_object(obj, 'hooks')
    for event, stage in EVENTS[h].items():
        argv = [python, '-I', str(runtime / 'launch.py'), 'hook', '--policy', str(policy),
                '--harness', h, '--event', event, '--profile', target.profile]
        if h == 'copilot':
            entry = {'type':'command', 'exec':python, 'args':argv[1:], 'timeoutSec':12}
        elif h == 'cursor':
            entry = {'command':shell_command(argv), 'timeout':12}
        else:
            command = {'type':'command', 'command':shell_command(argv), 'timeout':12000 if h == 'gemini' else 12}
            entry = {'hooks':[command]}
            if stage != 'ingress':
                entry['matcher'] = '.*'
        entries = child_list(hooks, event)
        if entry not in entries:
            entries.append(entry)
    if obj.get('disableAllHooks') is True:
        target.notes.append('Native disableAllHooks=true is preserved. This adapter will not run until an operator changes it.')
    return Operation(path, encoded(obj), 'shared')


def adapter_operations(target, runtime, policy, python, which=shutil.which):
    h, root = target.harness, target.root
    if h in EVENTS:
        return [native_hooks(target, runtime, policy, python)]
    def template(name):
        return substitutions((ROOT / 'adapters' / name).read_text(encoding='utf-8'), python, runtime / 'launch.py', policy, target.profile).encode()
    if h in ('opencode','pi'):
        folder = root / ('plugins' if h == 'opencode' else 'extensions')
        return [Operation(folder / 'jev-sentinel.ts', template(h + '.ts')),
                Operation(folder / '_jev-sentinel/bridge.mjs', template('bridge.mjs'))]
    if h == 'hermes':
        folder = root / 'plugins/jev-sentinel'
        ops = [Operation(folder / '__init__.py', template('hermes.py')),
               Operation(folder / 'plugin.yaml', b'name: jev-sentinel\nversion: 0.1.0\ndescription: Typed security assessments and pre-tool vetoes\npython_runtime: external\nprovides_hooks:\n  - pre_tool_call\n  - post_tool_call\n')]
        executable = which('hermes')
        if executable:
            ops.append(Operation(root / 'config.yaml', None, 'shared', [executable,'plugins','enable','jev-sentinel'], {'HERMES_HOME':str(root)}))
        else:
            target.notes.append('ACTIVATION PENDING: run hermes plugins enable jev-sentinel with the selected HERMES_HOME once Hermes is available.')
        return ops
    if h == 'openclaw':
        folder = root / 'extensions/jev-sentinel'
        manifest = {'id':'jev-sentinel','name':'JEV Sentinel',
                    'description':'Typed security assessments and pre-tool vetoes',
                    'activation':{'onStartup':True},
                    'configSchema':{'type':'object','additionalProperties':False,'properties':{}}}
        package = {'name':'jev-sentinel-openclaw','version':__version__,'type':'module',
                   'openclaw':{'extensions':['./index.js']}}
        configpath = root / 'openclaw.json'
        config = read_object(configpath)
        plugins = child_object(config, 'plugins')
        if plugins.get('enabled') is False:
            target.notes.append('Native plugins.enabled=false is preserved: adapter is configured but inactive.')
        deny = plugins.get('deny', [])
        if not isinstance(deny, list):
            raise ValueError('Invalid plugins.deny')
        if 'jev-sentinel' in deny:
            target.notes.append('Native plugins.deny blocks jev-sentinel; denial is preserved.')
        paths = child_list(child_object(plugins, 'load'), 'paths')
        if str(folder) not in paths:
            paths.append(str(folder))
        entry = child_object(child_object(plugins, 'entries'), 'jev-sentinel')
        if entry.get('enabled') is False:
            target.notes.append('Explicit jev-sentinel enabled=false is preserved; operator activation required.')
        else:
            entry['enabled'] = True
        if 'allow' in plugins:
            allow = child_list(plugins, 'allow')
            if 'jev-sentinel' not in allow:
                allow.append('jev-sentinel')
        return [Operation(folder / 'index.js', template('openclaw.js')),
                Operation(folder / 'bridge.mjs', template('bridge.mjs')),
                Operation(folder / 'openclaw.plugin.json', encoded(manifest)),
                Operation(folder / 'package.json', encoded(package)),
                Operation(configpath, encoded(config), 'shared')]
    raise ValueError('Adapter not implemented')


def read_manifest(state):
    path = state / 'install-manifest.json'
    if not path.exists():
        return {'schema_version':1, 'package_version':__version__, 'state':str(state), 'entries':{}, 'targets':[]}
    obj = read_object(path)
    if obj.get('schema_version') != 1 or obj.get('state') != str(state) or not isinstance(obj.get('entries'),dict):
        raise ValueError('Invalid installation manifest')
    return obj


def file_bytes(path):
    reject_symlinks(path)
    if path.exists() and not path.is_file():
        raise ValueError('Not a regular file: ' + str(path))
    return path.read_bytes() if path.exists() else None


def check_conflicts(operations, manifest):
    for op in operations:
        current = file_bytes(op.path)
        old = manifest['entries'].get(str(op.path))
        if old and current is not None and sha(current) != old['installed_sha256']:
            raise ValueError('Managed file changed since installation; refusing to overwrite: ' + str(op.path))
        if old and current is None:
            raise ValueError('Managed file missing; inspect before reinstalling: ' + str(op.path))
        if not old and op.kind == 'owned' and current is not None and current != op.content:
            raise ValueError('Unmanaged file occupies adapter/runtime destination: ' + str(op.path))


def make_plan(targets, state, python, mode=None, which=shutil.which):
    runtime = state / 'runtime'
    if ROOT in state.parents and runtime != ROOT:
        raise ValueError('State directory must not be inside the downloaded source tree')
    policy = state / 'policy.json'
    operations = []
    # A stable, private runtime means deleting the downloaded ZIP does not break hooks.
    for path in sorted(ROOT.rglob('*')):
        rel = path.relative_to(ROOT)
        if not path.is_file() or any(part in ('__pycache__','.git','tests','.github') for part in rel.parts) or path.suffix in ('.pyc','.zip'):
            continue
        if path.is_symlink():
            raise ValueError('Package source must not contain symlinks')
        operations.append(Operation(runtime / rel, path.read_bytes()))
    if policy.exists():
        configured = load_policy(policy)
        if mode is not None and configured['mode'] != mode:
            configured['mode'] = mode
            operations.append(Operation(policy, encoded(configured), 'policy'))
    else:
        configured = copy.deepcopy(DEFAULT_POLICY)
        configured['mode'] = mode or 'shadow'
        operations.append(Operation(policy, encoded(configured), 'policy'))
    for target in targets:
        operations.extend(adapter_operations(target, runtime, policy, python, which))
    names = [str(op.path) for op in operations]
    if len(names) != len(set(names)):
        raise ValueError('Two profiles resolve to the same managed file. Use distinct roots.')
    return operations


def write_manifest(state, manifest):
    atomic(state / 'install-manifest.json', encoded(manifest))


def apply_operations(operations, targets, state, runner=subprocess.run):
    private_dir(state)
    reject_symlinks(state / 'install.lock')
    lock = os.open(state / 'install.lock', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.write(lock, str(os.getpid()).encode())
    os.close(lock)
    before = []
    started_transaction = False
    old_manifest = read_manifest(state)
    manifest = copy.deepcopy(old_manifest)
    journal = state / 'transaction.json'
    try:
        if journal.exists():
            raise ValueError('An interrupted transaction exists; inspect transaction.json and its private backups before proceeding.')
        check_conflicts([o for o in operations if o.kind != 'policy'], manifest)
        transaction = {'started':time.time(), 'entries':[], 'note':'Recovery backups are private. Never overwrite subsequent user edits.'}
        # Snapshot all destinations before any native hook configuration becomes visible.
        for i, op in enumerate(operations):
            raw = file_bytes(op.path)
            mode = stat.S_IMODE(op.path.stat().st_mode) if raw is not None else None
            before.append((op.path, raw, mode))
            backup = state / 'transaction-backups' / (str(i) + '.before')
            if raw is not None:
                atomic(backup, raw)
            transaction['entries'].append({'path':str(op.path),'before_backup':str(backup) if raw is not None else None,
                                          'before_sha256':sha(raw) if raw is not None else None,
                                          'after_sha256':sha(op.content) if op.content is not None else None})
        atomic(journal, encoded(transaction))
        started_transaction = True
        # Runtime and policy operations precede hook/plugin configuration operations.
        for i, op in enumerate(operations):
            original, original_mode = before[i][1:]
            key = str(op.path)
            if op.kind != 'policy' and key not in manifest['entries']:
                backup_name = sha(key.encode()) + '.before'
                if original is not None:
                    atomic(state / 'backups' / backup_name, original)
                manifest['entries'][key] = {'original_exists':original is not None,
                    'backup':backup_name if original is not None else None,
                    'original_mode':original_mode, 'original_sha256':sha(original) if original is not None else None,
                    'installed_sha256':''}
            if file_bytes(op.path) != original:
                raise ValueError('Concurrent configuration edit detected; refusing to overwrite: ' + str(op.path))
            if op.native_command:
                env = dict(os.environ)
                env.update(op.native_env or {})
                result = runner(op.native_command, env=env, capture_output=True, timeout=30)
                updated = file_bytes(op.path)
                transaction['entries'][i]['after_sha256'] = sha(updated) if updated is not None else None
                atomic(journal, encoded(transaction))
                if result.returncode:
                    raise ValueError('Native Hermes enable failed; no output is echoed because configuration may contain secrets.')
                if updated is None:
                    raise ValueError('Hermes enable did not produce config.yaml; verify this Hermes version.')
                transaction['entries'][i]['after_sha256'] = sha(updated)
                atomic(journal, encoded(transaction))
            else:
                if original != op.content:
                    atomic(op.path, op.content)
                updated = op.content
            if op.kind != 'policy':
                manifest['entries'][key]['installed_sha256'] = sha(updated)
        by_profile = {t['profile']:t for t in manifest['targets']}
        for t in targets:
            by_profile[t.profile] = {'harness':t.harness,'root':str(t.root),'profile':t.profile,
                                    'detected':t.detected,'native_runtime_verified':False,'notes':t.notes}
        manifest['targets'] = list(by_profile.values())
        manifest['package_version'] = __version__
        write_manifest(state, manifest)
        journal.unlink()
        shutil.rmtree(state / 'transaction-backups', ignore_errors=True)
        return manifest
    except BaseException:
        # Roll back caught failures. Crash/SIGKILL recovery remains an operator task.
        failures = []
        for i in reversed(range(len(before))):
            path, raw, mode = before[i]
            try:
                current = file_bytes(path)
                current_hash = sha(current) if current is not None else None
                allowed = {sha(raw) if raw is not None else None}
                if started_transaction:
                    allowed.add(transaction['entries'][i]['after_sha256'])
                if current_hash not in allowed:
                    failures.append(str(path))
                    continue  # Preserve a concurrent edit; retain the recovery journal.
                if raw is None:
                    if path.exists():
                        reject_symlinks(path)
                        path.unlink()
                else:
                    atomic(path, raw)
                    if os.name != 'nt' and mode is not None:
                        os.chmod(path, mode)
            except Exception:
                failures.append(str(path))
        if not failures and started_transaction:
            # Restore manifest only if it existed; avoid inventing an installation.
            if old_manifest['entries']:
                write_manifest(state, old_manifest)
            elif (state / 'install-manifest.json').exists():
                (state / 'install-manifest.json').unlink()
            journal.unlink(missing_ok=True)
            shutil.rmtree(state / 'transaction-backups', ignore_errors=True)
        raise
    finally:
        (state / 'install.lock').unlink(missing_ok=True)


def uninstall(state, apply=False):
    manifest = read_manifest(state)
    entries = manifest['entries']
    restores = []
    for path_string, entry in entries.items():
        path = absolute(path_string)
        current = file_bytes(path)
        if current is None or sha(current) != entry['installed_sha256']:
            raise ValueError('Uninstall stopped: managed file changed/missing. No files restored: ' + path_string)
        raw = None
        if entry['original_exists']:
            name = entry['backup']
            if Path(name).name != name:
                raise ValueError('Invalid backup reference')
            raw = file_bytes(state / 'backups' / name)
            if raw is None or sha(raw) != entry['original_sha256']:
                raise ValueError('Original backup missing or corrupt')
        restores.append((path, raw, entry.get('original_mode')))
    report = {'action':'uninstall','apply':apply,'files':len(restores),
              'preserved':['policy.json','events.sqlite3','private backups'],
              'note':'Stop/restart the affected harnesses. Native in-memory code and trust records are not revoked by file rollback.'}
    if not apply:
        return report
    private_dir(state)
    fd = os.open(state / 'install.lock', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    done = []
    try:
        if (state / 'transaction.json').exists():
            raise ValueError('Interrupted transaction must be inspected first')
        for path, raw, mode in reversed(restores):
            # A second check catches edits between preflight and restoration.
            current = file_bytes(path)
            if current is None or sha(current) != entries[str(path)]['installed_sha256']:
                raise ValueError('Concurrent edit detected during uninstall')
            done.append((path,current))
            if raw is None:
                path.unlink()
            else:
                atomic(path, raw)
                if os.name != 'nt' and mode is not None:
                    os.chmod(path,mode)
        (state / 'install-manifest.json').unlink(missing_ok=True)
    except BaseException:
        for path, raw in reversed(done):
            atomic(path,raw)
        raise
    finally:
        (state / 'install.lock').unlink(missing_ok=True)
    return report


def parser():
    p = argparse.ArgumentParser(description='JEV Sentinel: preview by default; --apply writes native integrations')
    p.add_argument('--targets',default='detected',help='detected, all, or comma-separated: ' + ','.join(HARNESSES))
    p.add_argument('--profile',action='append',default=[],help='Repeat HARNESS=/absolute/config/root for alternate profiles')
    p.add_argument('--home',type=Path,help='Home used for default roots; disables environment root overrides')
    p.add_argument('--state-dir',type=Path,help='Runtime, policy, backups and event state; default HOME/.jev-sentinel')
    p.add_argument('--mode',choices=['shadow','enforce'],help='Default shadow for new installations; existing policy otherwise retained')
    p.add_argument('--apply',action='store_true')
    p.add_argument('--uninstall',action='store_true',help='Restore ALL files tracked by this state directory')
    return p


def main(argv=None):
    if sys.version_info < (3,10):
        print('Python 3.10+ is required.',file=sys.stderr)
        return 2
    args = parser().parse_args(argv)
    try:
        home = absolute(args.home or Path.home())
        state = absolute(args.state_dir or home / '.jev-sentinel')
        reject_symlinks(state)
        if args.uninstall:
            print(json.dumps(uninstall(state,args.apply),indent=2))
            return 0
        targets = select_targets(home,args.targets,args.profile,use_env=args.home is None)
        if not targets:
            print(json.dumps({'action':'plan','targets':[], 'changed_files':0,
                 'note':'No harness detected. Select --targets all to stage all adapters, or specify --profile.'},indent=2))
            return 0
        python = str(Path(sys.executable).absolute())
        operations = make_plan(targets,state,python,args.mode)
        manifest = read_manifest(state)
        check_conflicts([o for o in operations if o.kind != 'policy'],manifest)
        report = {'action':'apply' if args.apply else 'plan','state_dir':str(state),
            'mode':args.mode or (load_policy(state / 'policy.json')['mode'] if (state / 'policy.json').exists() else 'shadow'),
            'targets':[{'harness':t.harness,'root':str(t.root),'detected':t.detected,'profile':t.profile,'notes':t.notes} for t in targets],
            'changed_files':sum(file_bytes(o.path) != o.content or o.native_command is not None for o in operations),
            'sentinel_remote_evaluations':0,'model_downloads_requested':0,'native_runtime_verified':False,
            'operations':[{'path':str(o.path),'kind':o.kind,'native_command':o.native_command} for o in operations]}
        if args.apply:
            apply_operations(operations,targets,state)
            report['result'] = 'Files configured. Restart/reload, complete native trust review, and run real-harness canaries before relying on enforcement.'
        print(json.dumps(report,indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({'error':str(exc),'changed':'No successful installation is claimed; inspect transaction.json if rollback was interrupted.'}),file=sys.stderr)
        return 2
