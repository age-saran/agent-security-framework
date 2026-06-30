"""PolicyEvaluator — deterministic, fail-closed policy evaluation.

Evaluation order:
1. External backends (OPA/Rego, Cedar, ...) in registration order. The first
   backend that returns a non-``None`` decision wins.
2. In-memory YAML rules. The highest-priority matching rule wins; ties break by
   declaration order (earlier rule wins).
3. Document defaults (``deny`` unless overridden).

Any unexpected error during evaluation yields a DENY decision — the gate must
never fail open.
"""

from __future__ import annotations

import re
import time
from typing import Any

from agent_security.policy.backends import IPolicyBackend
from agent_security.policy.models import (
    PolicyAction,
    PolicyCondition,
    PolicyDecision,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)

_MISSING = object()


def _resolve_field(context: dict, dotted: str) -> Any:
    """Resolve a dotted path like ``agent.ring`` from a nested dict."""
    cur: Any = context
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _evaluate_condition(cond: PolicyCondition, context: dict) -> bool:
    actual = _resolve_field(context, cond.field)
    op = cond.operator
    expected = cond.value

    # A missing field can only satisfy negative operators (not_in / not_equals).
    if actual is _MISSING:
        return op in (PolicyOperator.NOT_IN, PolicyOperator.NOT_EQUALS)

    try:
        if op is PolicyOperator.IN:
            return actual in expected
        if op is PolicyOperator.NOT_IN:
            return actual not in expected
        if op is PolicyOperator.EQUALS:
            return actual == expected
        if op is PolicyOperator.NOT_EQUALS:
            return actual != expected
        if op is PolicyOperator.MATCHES:
            return re.search(str(expected), str(actual)) is not None
        if op is PolicyOperator.CONTAINS:
            return expected in actual
        if op is PolicyOperator.STARTS_WITH:
            return str(actual).startswith(str(expected))
        if op is PolicyOperator.GT:
            return actual > expected
        if op is PolicyOperator.LT:
            return actual < expected
        if op is PolicyOperator.GTE:
            return actual >= expected
        if op is PolicyOperator.LTE:
            return actual <= expected
    except (TypeError, ValueError, re.error):
        # Type mismatch (e.g. comparing str > int) => condition does not match.
        return False
    return False


def _rule_matches(rule: PolicyRule, context: dict) -> bool:
    """A rule matches when ALL of its conditions hold (empty == always)."""
    return all(_evaluate_condition(c, context) for c in rule.conditions)


class PolicyEvaluator:
    """Stateless evaluator over one or more policy documents."""

    def __init__(
        self,
        policies: list[PolicyDocument] | PolicyDocument | None = None,
        backends: list[IPolicyBackend] | None = None,
    ) -> None:
        if policies is None:
            policies = []
        elif isinstance(policies, PolicyDocument):
            policies = [policies]
        self._policies = policies
        self._backends = backends or []
        # Pre-sort all rules by descending priority, preserving declaration order.
        indexed: list[tuple[int, int, PolicyRule, PolicyDocument]] = []
        for doc in policies:
            for idx, rule in enumerate(doc.rules):
                indexed.append((rule.priority, idx, rule, doc))
        indexed.sort(key=lambda t: (-t[0], t[1]))
        self._sorted_rules = [(r, d) for _, _, r, d in indexed]

    def evaluate(self, context: dict) -> PolicyDecision:
        """Evaluate ``context``. Fail-closed: any error returns DENY."""
        start = time.perf_counter()
        try:
            # 1. External backends.
            for backend in self._backends:
                decision = backend.evaluate(context)
                if decision is not None:
                    decision.metadata.setdefault("backend", backend.name)
                    decision.evaluation_time_ms = (time.perf_counter() - start) * 1000
                    return decision

            # 2. YAML rules (already priority-sorted).
            for rule, doc in self._sorted_rules:
                if _rule_matches(rule, context):
                    return PolicyDecision(
                        action=rule.action,
                        matched_rule=rule.name,
                        description=rule.description,
                        approvers=list(rule.approvers),
                        modify_params=dict(rule.modify_params),
                        tags=list(rule.tags),
                        policy_version=doc.version,
                        evaluation_time_ms=(time.perf_counter() - start) * 1000,
                    )

            # 3. Defaults (fail-closed).
            default_action = (
                self._policies[0].defaults.action if self._policies else PolicyAction.DENY
            )
            default_version = self._policies[0].version if self._policies else ""
            return PolicyDecision(
                action=default_action,
                matched_rule=None,
                description="No rule matched; applied policy default.",
                policy_version=default_version,
                evaluation_time_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 — fail-closed by design.
            return PolicyDecision(
                action=PolicyAction.DENY,
                matched_rule=None,
                description="Evaluation error; denied (fail-closed).",
                metadata={"error": type(exc).__name__, "detail": str(exc)},
                evaluation_time_ms=(time.perf_counter() - start) * 1000,
            )

    def evaluate_tool_call(
        self,
        tool_name: str,
        args: dict | None = None,
        agent_id: str = "",
        agent_ring: int = 3,
        action_type: str | None = None,
        extra: dict | None = None,
    ) -> PolicyDecision:
        """Build a standard context from a tool call and evaluate it."""
        args = args or {}
        context: dict[str, Any] = {
            "tool_name": tool_name,
            "args": args,
            "agent": {"id": agent_id, "ring": agent_ring},
            "agent_id": agent_id,
            "action": {"type": action_type or _infer_action_type(tool_name)},
        }
        # Surface common string args for regex-based rules (e.g. PII detection).
        text_parts = [str(v) for v in args.values() if isinstance(v, str)]
        if text_parts:
            context["input_text"] = " ".join(text_parts)
        if extra:
            context.update(extra)
        return self.evaluate(context)


_READ_PREFIXES = ("read", "get", "list", "query", "search", "fetch", "describe", "find")
_WRITE_PREFIXES = ("write", "update", "create", "send", "delete", "drop", "set", "put", "exec")


def _infer_action_type(tool_name: str) -> str:
    """Heuristic action classification from a tool name."""
    lowered = tool_name.lower()
    for prefix in _READ_PREFIXES:
        if lowered.startswith(prefix) or f"_{prefix}" in lowered:
            return "read"
    for prefix in _WRITE_PREFIXES:
        if lowered.startswith(prefix) or f"_{prefix}" in lowered:
            return "write"
    return "unknown"
