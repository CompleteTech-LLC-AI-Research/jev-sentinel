"""Translate documented native hook envelopes without sharing decision schemas."""
from __future__ import annotations
from .core import strict_json

EVENTS = {
    "claude": {"UserPromptSubmit": "ingress", "PreToolUse": "tool_before", "PostToolUse": "tool_after"},
    "codex": {"UserPromptSubmit": "ingress", "PreToolUse": "tool_before", "PostToolUse": "tool_after"},
    "gemini": {"BeforeAgent": "ingress", "BeforeTool": "tool_before", "AfterTool": "tool_after"},
    "cursor": {"beforeSubmitPrompt": "ingress", "preToolUse": "tool_before", "postToolUse": "tool_after"},
    "copilot": {"userPromptSubmitted": "ingress", "preToolUse": "tool_before", "postToolUse": "tool_after"},
}


def as_text(value):
    if isinstance(value, str):
        return value
    import json
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def normalize(harness: str, event_name: str, data: dict, profile: str) -> dict:
    if not isinstance(data, dict):
        raise ValueError("hook payload must be object")
    stage = EVENTS[harness][event_name]
    args = data.get("tool_input", data.get("toolArgs", {}))
    if isinstance(args, str):
        args = strict_json(args)
    if not isinstance(args, dict):
        raise ValueError("tool arguments must be object")
    if stage == "ingress":
        if not isinstance(data.get("prompt"), str):
            raise ValueError("prompt field missing")
        content = data["prompt"]
    elif stage == "tool_after":
        keys = ("tool_response", "toolResult", "tool_output", "tool_result")
        matches = [key for key in keys if key in data]
        if not matches:
            raise ValueError("tool result field missing")
        content = as_text(data[matches[0]])
    else:
        content = ""  # Inspect actual arguments, not model-authored explanatory text.
    return {
        "stage": stage, "harness": harness, "profile": profile,
        "source": "user" if stage == "ingress" else ("external" if stage == "tool_after" else "agent"),
        "content": content,
        "session_id": data.get("session_id") or data.get("sessionId") or data.get("conversation_id") or "",
        "tool_name": data.get("tool_name", data.get("toolName", "")),
        "tool_input": args,
    }


def render(harness: str, event_name: str, verdict: dict, raw: dict | None = None) -> dict:
    stage = EVENTS[harness][event_name]
    veto = verdict["enforced"] and verdict["decision"] != "DEFER"
    reason = verdict["message"] + " Event: " + verdict["id"]
    if harness == "cursor":
        if stage == "ingress":
            return {"continue": not veto, **({"user_message": reason} if veto else {})}
        if stage == "tool_before":
            # Cursor requires a permission field; no argument/permission rewrite.
            return {"permission": "deny" if veto else "allow", **({"user_message": reason, "agent_message": reason} if veto else {})}
        return {}  # Observation only. SQLite latch restricts subsequent tools.
    if harness == "copilot":
        return {"permissionDecision": "deny", "permissionDecisionReason": reason} if veto and stage == "tool_before" else {}
    if not veto:
        return {}  # Never return permissionDecision=allow in Claude/Codex.
    if harness == "gemini":
        return {"decision": "deny", "reason": reason}
    if stage == "ingress":
        return {"decision": "block", "reason": reason}
    if stage == "tool_before":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}
    out = {"decision": "block", "reason": reason, "hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": reason}}
    # Claude can replace MCP responses, but not arbitrary built-in tool results.
    if harness == "claude" and (raw or {}).get("tool_name", "").startswith("mcp__"):
        out["hookSpecificOutput"]["updatedMCPToolOutput"] = {"content": [{"type": "text", "text": reason}], "isError": True}
    # Only replace a built-in result whose documented output shape we know.
    # Older Claude versions may ignore this field: test the loaded runtime.
    if harness == "claude" and (raw or {}).get("tool_name") == "Bash":
        original = (raw or {}).get("tool_response")
        if isinstance(original, dict) and {"stdout","stderr","interrupted","isImage"} <= set(original):
            out["hookSpecificOutput"]["updatedToolOutput"] = {
                "stdout":reason, "stderr":"", "interrupted":False, "isImage":False}
    return out
