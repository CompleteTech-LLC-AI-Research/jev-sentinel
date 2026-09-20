"""Bounded command-line entry points; stdout is always protocol JSON."""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import urllib.parse

from .core import (MAX_INPUT, DEFAULT_POLICY, DECISIONS, Store, assess, dumps,
                   failure_result, load_policy, post_json, private_dir, reject_symlinks, strict_json)
from .hooks import EVENTS, normalize, render

ROOT = Path(__file__).resolve().parent.parent


def atomic(path: Path, raw: bytes):
    private_dir(path.parent)
    reject_symlinks(path)
    fd, name = tempfile.mkstemp(prefix=".sentinel-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_stdin():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("oversize_input")
    return strict_json(raw)


def is_enforced(policy_path: Path):
    try:
        return load_policy(policy_path)["mode"] == "enforce"
    except Exception:
        return True  # A corrupt/missing policy must not silently disable a gate.


def bounded_assessment(event: dict, policy: Path) -> dict:
    """Process watchdog covers DNS, HTTP reads, malformed responses and DB delays."""
    try:
        result = subprocess.run([sys.executable, "-I", str(ROOT / "launch.py"), "worker", "--policy", str(policy)],
                                input=dumps(event).encode(), capture_output=True, timeout=6, cwd=str(ROOT))
        if result.returncode or len(result.stdout) > 65536:
            raise ValueError("worker_failed")
        reply = strict_json(result.stdout)
        if not isinstance(reply, dict) or reply.get("decision") not in DECISIONS or type(reply.get("enforced")) is not bool:
            raise ValueError("worker_invalid")
        return reply
    except Exception:
        # The underlying harness may still fail open if it kills this launcher.
        return failure_result("worker_error_or_timeout", is_enforced(policy))


def parser():
    p = argparse.ArgumentParser(description="JEV Sentinel local security middleware")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("worker", "check", "hook", "doctor", "outbox", "dispatch", "policy", "clear-session"):
        q = sub.add_parser(name)
        q.add_argument("--policy", type=Path, default=Path.home() / ".jev-sentinel/policy.json")
        if name == "hook":
            q.add_argument("--harness", choices=sorted(EVENTS), required=True)
            q.add_argument("--event", required=True)
            q.add_argument("--profile", default="default")
        if name in ("outbox", "dispatch"):
            q.add_argument("--limit", type=int, default=20)
        if name == "dispatch":
            q.add_argument("--url", required=True, help="Operator-controlled HTTPS alert destination")
            q.add_argument("--allow-network", action="store_true")
        if name == "policy":
            q.add_argument("--mode", choices=["shadow", "enforce"])
            q.add_argument("--backend", choices=["local", "jev"])
            q.add_argument("--model")
        if name == "clear-session":
            q.add_argument("--session-ref", required=True)
            q.add_argument("--confirm", action="store_true")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    policy_path = Path(os.path.abspath(args.policy))
    try:
        if args.command == "hook":
            if args.event not in EVENTS[args.harness]:
                raise ValueError("unsupported native event")
            raw = {}
            try:
                raw = read_stdin()
                event = normalize(args.harness, args.event, raw, args.profile)
                verdict = bounded_assessment(event, policy_path)
            except Exception:
                verdict = failure_result("invalid_native_envelope", is_enforced(policy_path))
            print(dumps(render(args.harness, args.event, verdict, raw if isinstance(raw, dict) else {})))
            return 0
        if args.command == "check":
            try:
                verdict = bounded_assessment(read_stdin(), policy_path)
            except Exception:
                verdict = failure_result("invalid_input", is_enforced(policy_path))
            print(dumps(verdict))
            return 0  # The caller MUST inspect decision+enforced, not just exit code.
        policy = load_policy(policy_path)
        if args.command == "doctor":
            report = {"mode": policy["mode"], "backend": policy["backend"], "model": policy["model"],
                      "remote_consent": os.environ.get("JEV_SENTINEL_ALLOW_REMOTE") == "1",
                      "api_key_present": bool(os.environ.get("TYPESAFE_API_KEY")),
                      "runtime": str(ROOT), "python": sys.version.split()[0],
                      "native_runtime_verified": False,
                      "note": "Configuration inspection only. Run a harmless canary through each real harness after restart/trust review."}
            print(dumps(report))
            return 0
        if args.command == "policy":
            for key in ("mode", "backend", "model"):
                if getattr(args, key) is not None:
                    policy[key] = getattr(args, key)
            # Validate without risking the existing policy.
            with tempfile.TemporaryDirectory() as tmp:
                candidate = Path(tmp) / "policy.json"
                candidate.write_text(dumps(policy), encoding="utf-8")
                load_policy(candidate)
            atomic(policy_path, (json.dumps(policy, indent=2) + "\n").encode())
            print(dumps({"updated": str(policy_path), "mode": policy["mode"], "backend": policy["backend"], "remote_calls_made": 0}))
            return 0
        store = Store(policy_path.parent)
        try:
            if args.command == "worker":
                try:
                    verdict = assess(read_stdin(), policy, store)
                except Exception:
                    verdict = failure_result("assessment_failed", policy["mode"] == "enforce")
                print(dumps(verdict))
            elif args.command in ("outbox", "dispatch"):
                if not 1 <= args.limit <= 100:
                    raise ValueError("limit must be 1..100")
                rows = store.db.execute("SELECT id,summary FROM events WHERE pending=1 ORDER BY created LIMIT ?", (args.limit,)).fetchall()
                if args.command == "outbox":
                    print(dumps([strict_json(row[1]) for row in rows]))
                else:
                    parsed = urllib.parse.urlsplit(args.url)
                    if not args.allow_network or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                        raise ValueError("explicit --allow-network and HTTPS destination without credentials required")
                    delivered = []
                    for event_id, summary in rows:
                        body = summary.encode()
                        headers = {"Content-Type": "application/json", "Idempotency-Key": event_id}
                        signing_key = os.environ.get("JEV_SENTINEL_WEBHOOK_KEY")
                        if signing_key:
                            headers["X-Sentinel-Signature"] = "sha256=" + hmac.new(signing_key.encode(), body, hashlib.sha256).hexdigest()
                        post_json(args.url, body, headers, 3)
                        store.db.execute("UPDATE events SET pending=0 WHERE id=?", (event_id,))
                        store.db.commit()
                        delivered.append(event_id)
                    print(dumps({"delivered": delivered, "delivery": "at-least-once; receiver must deduplicate Idempotency-Key"}))
            elif args.command == "clear-session":
                if not args.confirm or len(args.session_ref) != 64:
                    raise ValueError("explicit --confirm and valid session_ref required")
                store.db.execute("DELETE FROM sessions WHERE id=?", (args.session_ref,))
                store.db.commit()
                print(dumps({"cleared": args.session_ref}))
            return 0
        finally:
            store.close()
    except Exception as exc:
        # No exception details from HTTP/credentials/untrusted inputs are emitted.
        print(dumps({"error": type(exc).__name__, "message": "Operation failed. Inspect configuration locally; no raw input is echoed."}), file=sys.stderr)
        return 2
