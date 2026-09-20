# Primary-source API references

Contract review date: 2026-09-19. These URLs explain the API shapes used here.
They are moving documentation, not a claim that a particular locally installed
binary has been verified. No upstream repository or plugin binary is downloaded
by the installer. No unsupported configuration key is intended as a substitute
for a documented native hook contract.

| Component | Primary reference | Contract used |
|---|---|---|
| TypeSafe HTTP API | https://docs.typesafe.ai/api | POST /v1/systemone; typed Noul questions; answers[name].noul |
| Jev model identity | https://docs.typesafe.ai/models | Pinned jev-1.13.0; text-only inputs; versioned response identity |
| OpenClaw tool policy | https://docs.openclaw.ai/plugins/hooks/tool-policy | before_tool_call event and block/blockReason output |
| OpenClaw hook reference | https://docs.openclaw.ai/plugins/hooks/reference | after_tool_call observer; async overlap; synchronous persistence hooks are distinct |
| OpenClaw plugin packaging | https://docs.openclaw.ai/plugins/building-plugins | definePluginEntry, plugin manifest and package entry |
| Hermes plugins | https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/ | Python plugins, native enable, external Python runtime, pre/post callback signatures |
| OpenCode plugins | https://opencode.ai/docs/plugins/ | Local plugin discovery and pre-tool veto by exception |
| OpenCode plugin types | https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/plugin/src/index.ts | tool.execute.before/after exact input and output fields |
| Codex hooks | https://developers.openai.com/codex/hooks/ | Native event schemas, hooks.json discovery, exact-definition trust and tool-path exclusions |
| Codex documentation destination | https://learn.chatgpt.com/docs/hooks | Current redirect destination of the Codex hooks reference |
| Claude Code hooks | https://code.claude.com/docs/en/hooks | PreToolUse deny; PostToolUse feedback; MCP and built-in replacement shapes |
| Pi extensions | https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/coding-agent/docs/extensions.md | input source, tool_call block, tool_result transformation |
| Gemini CLI hooks | https://geminicli.com/docs/hooks/reference/ | BeforeAgent/BeforeTool/AfterTool; deny; millisecond timeout units |
| Cursor hooks | https://cursor.com/docs/hooks | Flat version-1 configuration; preToolUse allow/deny; postToolUse output fields |
| Copilot hooks | https://docs.github.com/en/copilot/reference/hooks-reference | Local CLI direct exec/args, preToolUse permissionDecision, cloud/local distinction |

The code is a new reference implementation, not an upstream-endorsed security
product. Test fixtures simulate these contracts and real local subprocesses; they
do not prove current native runtime activation or classifier effectiveness. The
66 Python tests and 9 Node tests recorded for this build do not include live Jev
calls or a prompt-injection benchmark dataset. See the test report for scope.
