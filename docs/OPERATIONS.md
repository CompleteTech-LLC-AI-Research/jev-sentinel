# Operations, canaries and recovery

## Activation sequence

Inspect the install plan and selected profile roots. Apply into the correct user
and execution environment. Restart or reload each harness. Complete native trust
review, especially Codex `/hooks`; do not bypass it. Check local shadow events
before enabling remote Jev or enforcing decisions. Decide what data may leave the
machine, supply credentials to the actual host process, then configure backend
and mode explicitly. A successful install report is not a protection certificate.

There is no universal version probe or active smoke test in `doctor`. Doctor
reports only policy configuration, interpreter, remote-consent presence and API-key
presence. It never prints the key, makes an API request, or marks native runtime
verification as complete. Actual binary versions and activation success must be
recorded by the operator alongside canary evidence.

## Deterministic plumbing canaries

The literal `JEV_SENTINEL_TEST_BLOCK` is an intentional diagnostic trigger. It is
not a real attack classifier benchmark. Use a disposable session and harmless
commands only. Do not add real secrets or destructive commands to canaries.

1. In shadow mode, submit a benign prompt and a prompt containing the canary; inspect
   the outbox to verify that the adapter is called without interrupting work.
2. In enforce mode, ask for a harmless `echo JEV_SENTINEL_TEST_BLOCK`. An ingress
   gate may stop the prompt first. For an independent pre-tool check, temporarily
   add the exact shell tool name reported by that host to `denied_tools`, then ask
   for a plain harmless echo. It must not run. Revert the policy afterward.
3. Put an injection-looking test string in a disposable local fixture, then ask
   the agent to read it. On transformation-capable adapters, verify the replacement
   rather than the fixture text reaches model-visible output. On observer-only
   adapters, expect an incident and, when session identity is available, a latch
   restricting subsequent tools—not retroactive removal of the result.

For example, the shared stdin test (not a native activation test) is:

```sh
python "$HOME/.jev-sentinel/runtime/launch.py" check \
  < examples/tool-before.json
```

The JSON should contain decision BLOCK; `enforced` reflects current policy. A zero
exit code alone is never an allow signal. Deleting a local fixture or starting a
new isolated test session is safer than resetting a production latch during tests.
Canary outcomes depend on the hook actually loading, the host tool path, native
approval mode, and other installed plugins. Test each profile separately.

## Policy and escalation

The policy is explicit JSON in the state directory. Use the `policy` subcommand
for mode/backend/model changes; edit other known fields deliberately and validate
with doctor. Unknown policy keys are errors. There is no input-controlled policy
file path, endpoint, threshold, override, or allowed-tool list.

`denied_tools` is a global exact-name denial list. `read_only_tools` is an initially
empty map from harness name to exact tool names exempted from the taint latch.
Do not label a general shell, a tool that returns secrets, or a mutating multi-mode
tool read-only. Tool-name classification cannot replace argument/destination
validation and ordinary capabilities. When a session is tainted, all tools are
sensitive by default. This may prevent the original task continuing until review.

`require_goal_for_sensitive_actions=true` requires an available user-goal snapshot.
This will deliberately deny sensitive calls in adapters that do not capture an
authenticated ingress goal. It is a deployment choice, not an automatic fix for
missing provenance. Goals are semantic evidence, not independently proven consent.

After resolving an incident, a trusted operator may remove a latch and its goal:

```sh
python "$HOME/.jev-sentinel/runtime/launch.py" clear-session \
  --session-ref HASH_FROM_OUTBOX --confirm
```

Use the complete 64-character session reference. This does not replay an action,
grant tool permissions, or clear pending audit events. The next operation still
passes its semantic and native authorization checks. Do not allow a model to call
this administrative interface as a normal tool.

A read-only security reviewer can consume `outbox` or an explicitly configured
webhook. Its job is to propose an explanation or a safer action. Do not expose API
keys, administrator mail, arbitrary shell, unrestricted egress or permission-editing
APIs to that reviewer. `examples/custom_host.py` provides a callback integration
pattern without silently spawning a privileged agent.

## Restore and interrupted transactions

Normal uninstall preflights every tracked path and original backup. Any changed
or missing managed file aborts before restoration. A successful uninstall restores
original file bytes and removes files that were originally absent. It intentionally
leaves policy, audit data, private backups and some empty directories. Remove those
manually only after retention/recovery requirements have been considered.

If installation is interrupted, stop the affected harnesses and inspect
`transaction.json`, `transaction-backups/`, `backups/`, `install-manifest.json`, and
any `install.lock`. Preserve copies with private permissions. Check the recorded
before/after SHA-256 values against current files; do not restore a file with an
unexpected current hash or discard later user edits. A native Hermes enable may
have changed configuration before its result was observed, so an unknown after
hash requires manual inspection. Lock files are not automatically considered stale.
There is deliberately no unsafe force-uninstall or force-recovery switch.

If a caught exception restored all known files, the temporary journal is removed.
If restoration conflicts with concurrent edits, recovery evidence remains. A native
CLI may create unrelated state outside the tracked config file; that state is not
claimed to be transactionally restored. Restart/reload the host after recovery.

## Deployment beyond one user

Repeat installation in each container, server or account, using explicit roots
and separate state directories as required. Do not mount an unrestricted writable
security control plane into the same container that executes arbitrary agent code.
For strict isolation, keep policy/runtime/config read-only to the agent and perform
sensitive operations through a separately authenticated broker. This package does
not provision that broker, managed policy, native sandbox, network restrictions,
service supervision or an agent fleet manager. It also does not bypass cloud hooks
or silently alter `/compact`, `/prune`, permissions, memory policy or model settings.
