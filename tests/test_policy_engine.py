"""Tests for the policy engine, models, and loader."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_security.policy import (
    PolicyAction,
    PolicyEvaluator,
    load_policies,
    load_policy,
)
from agent_security.policy.models import (
    PolicyCondition,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_POLICY = REPO_ROOT / "examples" / "policies" / "production.yaml"


@pytest.fixture
def evaluator() -> PolicyEvaluator:
    return PolicyEvaluator([load_policy(PROD_POLICY)])


def test_policy_loads_and_validates() -> None:
    doc = load_policy(PROD_POLICY)
    assert isinstance(doc, PolicyDocument)
    assert doc.api_version == "governance.toolkit/v1"
    assert doc.defaults.action is PolicyAction.DENY
    assert any(r.name == "block-destructive-ops" for r in doc.rules)


def test_deny_destructive(evaluator: PolicyEvaluator) -> None:
    d = evaluator.evaluate_tool_call("delete_file", {"path": "/etc/passwd"})
    assert d.action is PolicyAction.DENY
    assert d.matched_rule == "block-destructive-ops"


def test_allow_read(evaluator: PolicyEvaluator) -> None:
    d = evaluator.evaluate_tool_call("web_search", {"q": "weather"}, agent_ring=1)
    assert d.action is PolicyAction.ALLOW


def test_pdpa_thai_id_block(evaluator: PolicyEvaluator) -> None:
    d = evaluator.evaluate_tool_call("store_record", {"note": "id 1-1234-12345-12-1 here"})
    assert d.action is PolicyAction.DENY
    assert d.matched_rule == "pdpa-pii-detection"
    assert "pdpa" in d.tags


def test_pdpa_cross_border_step_up(evaluator: PolicyEvaluator) -> None:
    d = evaluator.evaluate(
        {
            "tool_name": "transfer_data",
            "action": {"type": "write"},
            "agent": {"ring": 1},
            "destination": {"country": "US"},
        }
    )
    assert d.action is PolicyAction.STEP_UP
    assert "dpo@company.com" in d.approvers


def test_ring3_write_blocked(evaluator: PolicyEvaluator) -> None:
    d = evaluator.evaluate_tool_call("update_record", {"x": "1"}, agent_ring=3)
    assert d.action is PolicyAction.DENY
    assert d.matched_rule == "ring3-read-only"


def test_ring1_write_falls_through_to_default(evaluator: PolicyEvaluator) -> None:
    # A privileged-ring write with no explicit allow rule => fail-closed default.
    d = evaluator.evaluate_tool_call("update_record", {"x": "1"}, agent_ring=1)
    assert d.action is PolicyAction.DENY
    assert d.matched_rule is None  # default applied


def test_priority_wins() -> None:
    doc = PolicyDocument(
        name="t",
        rules=[
            PolicyRule(
                name="low-allow",
                conditions=[PolicyCondition(field="tool_name", operator=PolicyOperator.EQUALS, value="x")],
                action=PolicyAction.ALLOW,
                priority=1,
            ),
            PolicyRule(
                name="high-deny",
                conditions=[PolicyCondition(field="tool_name", operator=PolicyOperator.EQUALS, value="x")],
                action=PolicyAction.DENY,
                priority=10,
            ),
        ],
    )
    d = PolicyEvaluator([doc]).evaluate({"tool_name": "x"})
    assert d.matched_rule == "high-deny"


def test_fail_closed_on_bad_regex() -> None:
    doc = PolicyDocument(
        name="t",
        rules=[
            PolicyRule(
                name="bad",
                conditions=[PolicyCondition(field="input_text", operator=PolicyOperator.MATCHES, value="(")],
                action=PolicyAction.ALLOW,
            )
        ],
    )
    d = PolicyEvaluator([doc]).evaluate({"input_text": "abc"})
    # Bad regex => condition false => no match => default deny.
    assert d.action is PolicyAction.DENY


def test_empty_evaluator_denies() -> None:
    assert PolicyEvaluator().evaluate({"tool_name": "x"}).action is PolicyAction.DENY


def test_load_policies_directory() -> None:
    docs = load_policies(PROD_POLICY.parent)
    assert any(d.name == "production-enterprise" for d in docs)


def test_throughput_benchmark(evaluator: PolicyEvaluator) -> None:
    """Sanity perf check: should comfortably exceed 10k evals/sec."""
    n = 5000
    start = time.perf_counter()
    for _ in range(n):
        evaluator.evaluate_tool_call("web_search", {"q": "x"}, agent_ring=1)
    elapsed = time.perf_counter() - start
    rate = n / elapsed
    assert rate > 10_000, f"only {rate:,.0f} evals/sec"
