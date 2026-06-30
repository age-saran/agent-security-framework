"""Tests for the govern() wrapper across the five decisions."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_security.governance import (
    GovernanceDeferred,
    GovernanceDenied,
    GovernanceStepUpRequired,
    govern,
)
from agent_security.policy.models import (
    PolicyAction,
    PolicyCondition,
    PolicyDecision,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_POLICY = str(REPO_ROOT / "examples" / "policies" / "production.yaml")


def _doc(*rules: PolicyRule) -> PolicyDocument:
    return PolicyDocument(name="t", rules=list(rules))


def test_allow_executes() -> None:
    policy = _doc(
        PolicyRule(
            name="allow-read",
            conditions=[PolicyCondition(field="action.type", operator=PolicyOperator.EQUALS, value="read")],
            action=PolicyAction.ALLOW,
        )
    )

    @govern(policy=policy, agent_ring=1)
    def read_thing(path: str) -> str:
        return f"read:{path}"

    assert read_thing("/a") == "read:/a"


def test_deny_raises() -> None:
    @govern(policy=PROD_POLICY)
    def delete_file(path: str) -> str:
        return "deleted"

    with pytest.raises(GovernanceDenied) as exc:
        delete_file("/etc/passwd")
    assert exc.value.decision.action is PolicyAction.DENY


def test_step_up_without_handler_raises() -> None:
    @govern(policy=PROD_POLICY, agent_ring=1)
    def send_email(to: str, body: str) -> str:
        return "sent"

    with pytest.raises(GovernanceStepUpRequired) as exc:
        send_email("a@b.com", "hi")
    assert "manager" in exc.value.approvers


def test_step_up_approved_executes() -> None:
    class Approver:
        def request_approval(self, decision: PolicyDecision, context: dict):
            return type("R", (), {"approved": True})()

    @govern(policy=PROD_POLICY, agent_ring=1, step_up_handler=Approver())
    def send_email(to: str, body: str) -> str:
        return "sent"

    assert send_email("a@b.com", "hi") == "sent"


def test_step_up_rejected_denies() -> None:
    class Rejector:
        def request_approval(self, decision: PolicyDecision, context: dict):
            return type("R", (), {"approved": False})()

    @govern(policy=PROD_POLICY, agent_ring=1, step_up_handler=Rejector())
    def send_email(to: str, body: str) -> str:
        return "sent"

    with pytest.raises(GovernanceDenied):
        send_email("a@b.com", "hi")


def test_modify_rewrites_params() -> None:
    policy = _doc(
        PolicyRule(
            name="redact",
            conditions=[PolicyCondition(field="tool_name", operator=PolicyOperator.EQUALS, value="post")],
            action=PolicyAction.MODIFY,
            modify_params={"channel": "#redacted"},
        )
    )

    @govern(policy=policy, agent_ring=1)
    def post(message: str, channel: str = "#general") -> str:
        return f"{channel}:{message}"

    assert post("hello", channel="#public") == "#redacted:hello"


def test_defer_raises() -> None:
    policy = _doc(
        PolicyRule(
            name="defer-it",
            conditions=[PolicyCondition(field="tool_name", operator=PolicyOperator.EQUALS, value="batch")],
            action=PolicyAction.DEFER,
        )
    )

    @govern(policy=policy, agent_ring=1)
    def batch() -> str:
        return "done"

    with pytest.raises(GovernanceDeferred):
        batch()


def test_audit_sink_called() -> None:
    seen: list[PolicyDecision] = []

    class Sink:
        def log_decision(self, context: dict, decision: PolicyDecision):
            seen.append(decision)

    @govern(policy=PROD_POLICY, audit_sink=Sink())
    def delete_file(path: str) -> str:
        return "x"

    with pytest.raises(GovernanceDenied):
        delete_file("/x")
    assert len(seen) == 1
    assert seen[0].action is PolicyAction.DENY


async def test_async_function_allowed() -> None:
    policy = _doc(
        PolicyRule(
            name="allow-read",
            conditions=[PolicyCondition(field="action.type", operator=PolicyOperator.EQUALS, value="read")],
            action=PolicyAction.ALLOW,
        )
    )

    @govern(policy=policy, agent_ring=1)
    async def read_async(path: str) -> str:
        return f"read:{path}"

    assert await read_async("/a") == "read:/a"


async def test_async_function_denied() -> None:
    @govern(policy=PROD_POLICY)
    async def delete_file(path: str) -> str:
        return "x"

    with pytest.raises(GovernanceDenied):
        await delete_file("/x")
