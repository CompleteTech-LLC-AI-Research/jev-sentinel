# Security model and limitations

JEV Sentinel is a reference sensor/veto layer. It is not a complete authorization
system, a sandbox, a proof of user intent, a malware scanner, or a jailbreak-proof
reference monitor. No security efficacy percentage is claimed by this release.

## Trusted computing base

The native harness, adapter registration, fixed Python interpreter, deployed
runtime, operator policy, credential source, host-provided provenance, and
ordinary tool authorization must be trusted. Untrusted prompts, files, MCP data,
RAG passages, repository content, tool results, and model judgments do not grant
permissions. The normalized JSON protocol is a local caller API, not an
authenticated network boundary. A forged source/session supplied by a hostile
caller is not authenticated by this package.

The same OS user can typically alter runtime/policy/hook files, inherit credentials,
modify the SQLite database, or call tools outside the harness. Private file modes
are protection from other ordinary users, not from the agent running as that user.
Use a separate-identity broker and read-only mounted control plane for stronger
isolation. This installer does not provision UIDs, Windows ACLs, containers,
seccomp, firewall rules, managed settings, or a capability-enforcing tool broker.
New Unix state directories are private and new state files use mode 0600. Existing
ancestor permissions are not comprehensively remediated; Windows relies on inherited
ACLs, which must be reviewed by the operator.

## Judgments are not grants

DEFER means no additional Sentinel veto, not safe or authorized. Deterministic
operator tool denials and external memory-write denials cannot be overridden by
low Jev probabilities. REVIEW blocks at supported pre-action hooks in enforce
mode; it does not automatically upgrade to a stronger model with more privileges.
A specialist reviewer should receive minimal evidence and read-only capabilities.
A human/operator must independently authorize any later action. Clearing a latch
is not tool authorization and does not automatically replay a blocked operation.

The default local detector is a handful of illustrative patterns. It can miss
obfuscated, multilingual, indirect and multi-step attacks and can flag benign
quoted examples. The pinned Jev model and question battery also require adversarial
application-specific evaluation. The provisional review/block thresholds 0.35/0.80
are policy starting points, not calibrated production security thresholds. Low
model probability cannot establish that a destination or command is authorized.

## Missing surfaces

Native hooks are only as complete as their dispatch paths. Hosted tools, shell
continuations, user shell shortcuts, failed-tool results, attachments, background
operations, extensions, subagents, cloud sessions, and later plugin transformations
may require separate integration. Tool results may already be truncated by a host.
The layer cannot detect content the host never supplies. Binary/image/audio/video
classification and comprehensive source-to-sink dataflow tracking are not included.

A post-tool result filter cannot undo commands, writes, API calls or transmissions.
Post-hook feedback does not necessarily hide the original result. Async observation
can race a following action; SQLite latches are not a linearizable reference
monitor for concurrent tools. A native hook crash, skipped callback, timeout,
untrusted-definition skip or disabled plugin may allow actions despite a local
watchdog. Real-host tests are mandatory for the exact deployed version and mode.

## Data handling

Jev is inactive without backend selection, TYPESAFE_API_KEY, and the explicit
JEV_SENTINEL_ALLOW_REMOTE=1 flag. Remote requests contain bounded selected content,
action arguments, app purpose, provenance labels, and an available goal snapshot.
They do not include full transcripts or automatically read files from transcript
paths. Best-effort redaction cannot guarantee removal of all secrets or private
content. Review TypeSafe's applicable data terms before enabling remote traffic.
No privacy assertion here replaces those terms.

Event records hold metadata and SHA-256 fingerprints; they do not hold raw prompt
or tool data. Fingerprints may reveal low-entropy information through guessing.
Goal snapshots do contain redacted user text, up to 4096 bytes, held locally for
at most 24 hours (purged on subsequent database use). Longer goals become unknown
instead of silently becoming truncated authorization context. Event metadata is
retained for seven days; expired entries are removed when the store is used.
Retention is bounded to approximately 20,000 events and 2,000 sessions. A session
latch expires after 24 hours without session activity. Backups can contain existing
harness credentials/settings and are deliberately retained until the operator
removes them. API keys are never written to generated native settings.

Alert dispatch is explicit, metadata-only, HTTPS-only, and directed to an operator
argument, never a model-provided URL. Environment proxies and redirects are disabled
for Sentinel HTTP calls. Optional HMAC does not encrypt messages; HTTPS provides
transport security. Dispatcher retries require a new invocation, and delivery is
at-least-once, so receivers must deduplicate incident IDs. Network failure can
leave alerts pending. A catastrophic bridge/database failure may produce a native
veto without a durable audit entry; this package does not include independent
supervision or a heartbeat system.

## Resource and operational limits

One remote call per assessment, no retries on the critical tool path, 500 calls
per UTC day per state directory by default, bounded event/state/response sizes,
a 6-second Python worker watchdog, and an 8-second JavaScript/Python plugin bridge
budget. Native outer hook budgets are configured where supported, but host-level
policies can still be shorter. The daily cap is a request budget, not a dollar
budget. The direct in-process core.assess API does not provide the separate-process
watchdog; prefer the SDK or stdin launcher at adversarial application boundaries.

The installer rejects unexpected JSON schemas, JSON5/JSONC, duplicate keys,
non-finite numbers, and symlink/junction destinations. Those checks do not prevent
same-UID filesystem races. Multi-file installation is not globally atomic. Caught
failures trigger restoration where content hashes still match known transaction
states; a crash, timeout during native enable, or concurrent edit can require
manual recovery. The private transaction journal and backups must be inspected,
not blindly replayed. The self-contained release checksum detects accidental
payload corruption; it is not an independently signed supply-chain attestation.
