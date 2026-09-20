"""Integration pattern for custom agent orchestration (no services are started).

The host supplies authorize_exact_action and execute_exact_action. This file does
not authorize operations, retry denied calls, launch a privileged reviewer, or
trust a review model's proposed permission changes.
"""
from typing import Callable
from jev_sentinel.sdk import Sentinel, SecurityReviewRequired

def guarded_tool(guard: Sentinel, tool: str, arguments: dict,
                 authorize_exact_action: Callable[[str,dict], bool],
                 execute_exact_action: Callable[[str,dict], object],
                 enqueue_restricted_review: Callable[[dict], None]):
    try:
        guard.before_tool(tool, arguments)
    except SecurityReviewRequired as error:
        # Metadata only. The queue consumer must not gain write/network/secret tools.
        v = error.verdict
        enqueue_restricted_review({'id':v['id'], 'route':v['route'],
                                   'reason_codes':v['reason_codes'], 'session_ref':v['session_ref']})
        return {'status':'pending_security_review'}
    if not authorize_exact_action(tool, arguments):
        return {'status':'denied_by_host'}
    # A production broker must bind authorization to the exact immutable arguments
    # and serialize/check conflicting operations; this example is not such a broker.
    return {'status':'executed', 'result':execute_exact_action(tool, arguments)}
