"""Pluggable policy backend interface.

The default engine evaluates YAML rules in-memory. External engines (OPA/Rego,
AWS Cedar, ...) can be plugged in by implementing :class:`IPolicyBackend` and
passing instances to :class:`~agent_security.policy.engine.PolicyEvaluator`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_security.policy.models import PolicyDecision


@runtime_checkable
class IPolicyBackend(Protocol):
    """A backend returns a decision, or ``None`` to defer to the next backend."""

    @property
    def name(self) -> str:
        """Short identifier used in audit metadata."""
        ...

    def evaluate(self, context: dict) -> PolicyDecision | None:
        """Evaluate ``context``. Return ``None`` to abstain."""
        ...
