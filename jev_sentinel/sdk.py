"""Bounded Python entry point for custom agents, RAG, memory and output gates."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from .cli import bounded_assessment

class SecurityReviewRequired(RuntimeError):
    def __init__(self, verdict: dict):
        self.verdict = verdict
        super().__init__('JEV Sentinel requires security review; event ' + verdict['id'])

class Sentinel:
    """Construct this in trusted host code, never from retrieved instructions.

    `DEFER` means only that Sentinel adds no veto. It is not native authorization.
    Use distinct profile/session identities for separate principals. Call user_goal
    only for authenticated user input, not tool output or model-authored summaries.
    """
    def __init__(self, policy: str | Path, *, harness: str, profile: str, session_id: str):
        self.policy = Path(policy).absolute()
        self.harness, self.profile, self.session_id = harness, profile, session_id

    def check(self, stage: str, *, source: str, content: str = '',
              tool_name: str = '', tool_input: dict[str, Any] | None = None) -> dict:
        return bounded_assessment({'stage':stage, 'harness':self.harness, 'profile':self.profile,
            'session_id':self.session_id, 'source':source, 'content':content,
            'tool_name':tool_name, 'tool_input':{} if tool_input is None else tool_input}, self.policy)

    @staticmethod
    def require_no_veto(verdict: dict) -> None:
        if verdict['enforced'] and verdict['decision'] != 'DEFER':
            raise SecurityReviewRequired(verdict)

    def user_goal(self, prompt: str) -> dict:
        result = self.check('ingress', source='user', content=prompt)
        self.require_no_veto(result)
        return result

    def before_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict:
        result = self.check('tool_before', source='agent', tool_name=tool_name, tool_input=arguments)
        self.require_no_veto(result)
        return result

    def external_context(self, content: str) -> tuple[str | None, dict]:
        """Quarantine the whole untrusted item; never manufacture a trusted rewrite."""
        result = self.check('context', source='external', content=content)
        accepted = not (result['enforced'] and result['decision'] != 'DEFER')
        return (content if accepted else None, result)

    def memory_write(self, content: str, *, authorized_by_user: bool = False) -> dict:
        result = self.check('memory', source='user' if authorized_by_user else 'external', content=content)
        self.require_no_veto(result)
        return result

    def output(self, content: str, *, destination: str) -> dict:
        result = self.check('egress', source='agent', content=content,
                            tool_input={'destination':destination})
        self.require_no_veto(result)
        return result
