# Native adapter contracts and coverage

Reference date: 2026-09-19. These are upstream API contracts and package behavior,
not a verified binary-version support matrix. Actual host versions must be tested
locally; an adapter file's existence does not prove that its hook was loaded.

## Locations, discovery and profiles

| Target | Default configuration root | Files written relative to root |
|---|---|---|
| `openclaw` | `~/.openclaw` / `OPENCLAW_STATE_DIR` | `extensions/jev-sentinel/{index.js,bridge.mjs,openclaw.plugin.json,package.json}`; merge `openclaw.json` |
| `hermes` | `~/.hermes` / `HERMES_HOME` | `plugins/jev-sentinel/{__init__.py,plugin.yaml}`; native CLI enables plugin in `config.yaml` |
| `opencode` | `${XDG_CONFIG_HOME:-~/.config}/opencode` / `OPENCODE_CONFIG_DIR` | `plugins/jev-sentinel.ts`, `plugins/_jev-sentinel/bridge.mjs` |
| `codex` | `~/.codex` / `CODEX_HOME` | merge `hooks.json` |
| `claude` | `~/.claude` / `CLAUDE_CONFIG_DIR` | merge `settings.json` |
| `pi` | `~/.pi/agent` / `PI_CODING_AGENT_DIR` | `extensions/jev-sentinel.ts`, `extensions/_jev-sentinel/bridge.mjs` |
| `gemini` | `~/.gemini` | merge `settings.json` |
| `cursor` | `~/.cursor` | merge `hooks.json` |
| `copilot` | `~/.copilot` / `COPILOT_HOME` | `hooks/jev-sentinel.json` |

`--profile HARNESS=/absolute/root` overrides the corresponding default, can be
repeated, and is also suitable for supported project-specific configuration roots.
The profile identity includes a hash of that exact root, preventing normal session
IDs from colliding across profiles. This is namespacing, not cryptographic identity.

Detection checks conventional configuration directories and CLI executables on
PATH. Cursor detection uses `cursor-agent`; a GUI-only installation without a
configuration directory can require an explicit target. Aliases: `claude-code`,
`codex-jev`, `gemini-cli`, and `copilot-cli`. Choosing `codex-jev` does not modify a
Codex fork: it selects the current Codex hooks adapter.

A custom `OPENCLAW_CONFIG_PATH` is not guessed. Use an explicit profile with the
supported `openclaw.json` layout or manually integrate the generated plugin.
Symlink/junction configuration roots are refused; resolve and verify the intended
real location outside the installer before selecting a different explicit root.

## OpenClaw

The plugin uses the public `definePluginEntry` SDK entry point and typed `api.on`
callbacks. Before-tool checks return `{block:true, blockReason:...}` and do not
rewrite parameters or grant permissions. The plugin is placed on `plugins.load.paths`.
An existing allowlist is extended rather than replaced; no new allowlist is
created that would unexpectedly disable other plugins. Existing global/plugin
disables and denylist entries remain in force and are reported.

After-tool callbacks are observations and may overlap later events. Their return
value is not treated as tool-result replacement. SQLite latching only affects a
later action after the observation commits, and therefore is not a serialized
security boundary. This package does not install synchronous `tool_result_persist`
rewrites or message-sending hooks. Some nested/native runner paths have narrower
contracts. No trusted original-user-goal snapshot is captured by this adapter.

Reload/restart the actual process; inspect with:

```sh
openclaw plugins inspect jev-sentinel --runtime --json
```

The installer does not run the gateway or change sender, tool, sandbox or approval
policies. Native hook runtime budgets can be shorter than the bridge budget;
verify them rather than assuming all async observations completed.

## Hermes

The Python directory plugin declares `python_runtime: external`, so Sentinel
requests no dependency installation into Hermes's own environment. It accepts
future keyword arguments and registers actual `pre_tool_call` and `post_tool_call`
callbacks. REVIEW and BLOCK become the documented pre-tool block directive;
Sentinel does not invent a new escalation return shape.

On `--apply`, an available local CLI runs `hermes plugins enable jev-sentinel`
with the selected `HERMES_HOME`. The existing `config.yaml` is backed up and
tracked. If the CLI is absent, the plugin is only staged and activation is
reported as pending. This local native command's own telemetry or side effects
are controlled by Hermes, not by Sentinel. No native plugin override privilege
is requested, and no custom YAML parser rewrites existing configuration.

Post-tool hook results are ignored by Hermes. Findings are local observations
and latches keyed by `task_id` when supplied; no guarantee is made that this ID
spans an entire conversation. No trusted user-goal snapshot is captured. Native
plugin callback crashes may be logged and skipped; catching bridge errors does
not make unloaded hooks or the host's own error policy fail closed.

## OpenCode

Local plugin discovery installs no npm dependency and does not touch package.json.
The before hook evaluates the actual `output.args` and throws on an enforced veto.
The after hook inspects output/title/metadata and replaces those fields on a
finding. Other plugins can mutate data later; host plugin composition and order
must be tested. Attachments not represented in these fields are not scanned.
This adapter does not hook chat.message and therefore has no original-goal snapshot.
A blocked action does not grant a privileged retry or alternate tool.

## Codex

The installer merges `hooks.json` and leaves `config.toml` unchanged. Current
non-managed hooks need **exact-definition hash trust approval in `/hooks`**.
Staging a file never bypasses that review; native disabled hooks stay disabled.
The installer does not enable the dangerous hook-trust bypass option.

UserPromptSubmit captures the host-delivered user prompt. PreToolUse returns only
the supported nested deny shape; it never sends `ask`, `continue`, or an allow
that could interfere with normal authorization. PostToolUse adds feedback and a
local latch, not Claude-only MCP replacement fields.

Current documented coverage includes Bash/unified exec, apply_patch, MCP, and
many local function tools. Hosted WebSearch is outside this path. `write_stdin`
does not rerun PreToolUse for an existing exec session. Some specialized paths opt
out. Invalid/unsupported hook results can be treated as hook failure with the tool
continuing, so the exact schemas and real runtime canaries matter.

## Claude Code

The installer adds UserPromptSubmit, PreToolUse and PostToolUse entries. It never
changes permissions, sandbox configuration, compact behavior, plugin settings,
or existing hook entries. Pre-tool results defer normally or deny; they never
explicitly grant permissions.

PostToolUse `decision:block` supplies feedback but by itself leaves original
output visible. For MCP tools the adapter returns `updatedMCPToolOutput`; for Bash
with the documented structured output it returns `updatedToolOutput` in the known
Bash shape. Other built-in results get feedback/latch only. Older hosts may ignore
new replacement fields, and schema-mismatched replacements may be ignored. No
failed-tool-result or streaming final-output hook is installed.

## Pi

The extension listens to `input`, `tool_call`, and `tool_result`. Only input whose
source is host-declared interactive or RPC supplies a goal; extension-injected
input does not. A denied input returns handled, a denied call returns a block,
and quarantined results replace both content and details with an error indicator.
The extension does not intercept `user_bash`, `!`/`!!` shell shortcuts, extension
commands, or compaction. Those are distinct host surfaces, not covered here.

## Gemini CLI

BeforeAgent and BeforeTool use native deny responses. AfterTool deny can withhold
a response from model context but cannot undo the tool's already-completed side
effects. Hook timeout configuration is **milliseconds**, so this adapter uses
12000 rather than the 12-second value used by other CLI hooks. The separate
worker watchdog normally responds sooner. No AfterAgent loop/retry hook is added.

## Cursor

The JSON format uses flat hook lists and `version:1`. beforeSubmitPrompt uses
`continue`; preToolUse uses `permission:allow|deny`. The apparent `ask` option is
not treated as an implemented approval workflow. PostToolUse is observation/latch
in this reference adapter, even though current Cursor APIs offer MCP replacement.
No narrower shell/MCP failClosed-specific hooks are installed. A local setup does
not install settings on a separate cloud-agent machine, and some hosted/startup
paths have different hook coverage.

## Copilot CLI

The adapter uses direct `exec` plus an `args` array rather than a shell command.
Only preToolUse returns a flat permissionDecision deny. userPromptSubmitted and
postToolUse supply observations/latches; their outputs are not claimed to block
initial user input or undo a tool.

This is the **local CLI** format. Cloud-agent hooks use repository configuration
and a different execution environment; global local hooks and direct exec are not
automatically a cloud installation. Current timeout handling can fail open even
when ordinary pre-tool hook execution failures block. A Python watchdog does not
protect against the host killing or skipping the entire hook process.
