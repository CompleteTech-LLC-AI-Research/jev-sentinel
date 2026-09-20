"""JEV Sentinel Hermes plugin. All runtime dependencies are Python standard library."""
import json
from pathlib import Path
import subprocess
import uuid
PYTHON = __PYTHON__
LAUNCH = __LAUNCH__
POLICY = __POLICY__
PROFILE = __PROFILE__

def _evaluate(stage, tool_name, args, task_id, content):
    event = {"harness":"hermes", "profile":PROFILE, "stage":stage,
             "source":"agent" if stage == "tool_before" else "external",
             "session_id":task_id or "", "tool_name":tool_name,
             "tool_input":args, "content":content}
    try:
        data = json.dumps(event, ensure_ascii=False, allow_nan=False).encode()
        if len(data) > 131072:
            raise ValueError("event limit")
        child = subprocess.run([PYTHON, "-I", LAUNCH, "check", "--policy", POLICY],
                               input=data, capture_output=True, timeout=8)
        if child.returncode or len(child.stdout) > 65536:
            raise ValueError("worker failed")
        result = json.loads(child.stdout)
        if result.get("decision") not in ("DEFER", "REVIEW", "BLOCK", "QUARANTINE") or type(result.get("enforced")) is not bool:
            raise ValueError("invalid result")
        return result
    except Exception:
        enforced = True
        try:
            enforced = json.loads(Path(POLICY).read_text(encoding="utf-8"))["mode"] != "shadow"
        except Exception:
            pass
        return {"decision":"REVIEW", "enforced":enforced, "id":uuid.uuid4().hex}

def pre_tool_call(tool_name, args, task_id=None, **kwargs):
    result = _evaluate("tool_before", tool_name, args, task_id, "")
    if result["enforced"] and result["decision"] != "DEFER":
        return {"action":"block", "message":"JEV Sentinel requires security review. Event: " + result["id"]}
    return None

def post_tool_call(tool_name, args, result, task_id=None, **kwargs):
    content = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
    _evaluate("tool_after", tool_name, args, task_id, content)
    # Hermes ignores this hook's return value. Never claim to withhold its output.
    return None

def register(ctx):
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
