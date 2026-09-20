// Generated with absolute, operator-selected paths. No shell and no listening port.
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
const PYTHON = __PYTHON__;
const LAUNCH = __LAUNCH__;
const POLICY = __POLICY__;
export const PROFILE = __PROFILE__;
function failure() {
  let enforced = true;
  try { enforced = JSON.parse(readFileSync(POLICY, 'utf8')).mode !== 'shadow'; } catch {}
  return {id: randomUUID(), decision:'REVIEW', enforced, reason_codes:['bridge_failure'],
    route:'security_review', message:'JEV Sentinel assessment unavailable; security review required.'};
}
export function veto(result) {
  return result.enforced === true && result.decision !== 'DEFER';
}
export function reason(result) {
  return 'JEV Sentinel requires security review. Event: ' + result.id;
}
export function text(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
export function evaluate(event) {
  let serialized;
  try { serialized = JSON.stringify({...event, profile: PROFILE}); }
  catch { return Promise.resolve(failure()); }
  if (!serialized || Buffer.byteLength(serialized, 'utf8') > 131072) return Promise.resolve(failure());
  return new Promise((resolve) => {
    const child = execFile(PYTHON, ['-I', LAUNCH, 'check', '--policy', POLICY],
      {timeout: 8000, maxBuffer: 65536, windowsHide: true, shell: false},
      (error, stdout) => {
        if (error) return resolve(failure());
        try {
          const r = JSON.parse(stdout);
          if (!['DEFER','REVIEW','BLOCK','QUARANTINE'].includes(r.decision) ||
              typeof r.enforced !== 'boolean' || typeof r.id !== 'string') throw new Error('schema');
          resolve(r);
        } catch { resolve(failure()); }
      });
    // Child death may race a write. The callback above owns the decision.
    child.stdin.on('error', () => {});
    child.stdin.end(serialized);
  });
}
