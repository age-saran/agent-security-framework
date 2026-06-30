"""Governance control-flow exceptions.

These are raised by :func:`agent_security.governance.gate.govern` to make a
denied or gated action *structurally impossible* to proceed past — the caller
must explicitly handle the exception.
"""

from __future__ import annotations

from agent_security.policy.models import PolicyDecision


class GovernanceError(Exception):
    """Base class for all governance control-flow exceptions."""

    def __init__(self, message: str, decision: PolicyDecision) -> None:
        super().__init__(message)
        self.decision = decision


class GovernanceDenied(GovernanceError):
    """Policy denied the action. Execution must not proceed."""

    def __init__(self, decision: PolicyDecision) -> None:
        rule = decision.matched_rule or "default"
        super().__init__(f"Action denied by policy (rule={rule}).", decision)


class GovernanceStepUpRequired(GovernanceError):
    """Human approval required before the action can proceed."""

    def __init__(
        self,
        decision: PolicyDecision,
        approval_url: str | None = None,
    ) -> None:
        self.approvers = list(decision.approvers)
        self.approval_url = approval_url
        approvers = ", ".join(self.approvers) or "configured approvers"
        super().__init__(f"Step-up approval required from: {approvers}.", decision)


class GovernanceDeferred(GovernanceError):
    """Action queued for asynchronous / batch review."""

    def __init__(self, decision: PolicyDecision, queue_id: str | None = None) -> None:
        self.queue_id = queue_id
        super().__init__("Action deferred for batch review.", decision)
