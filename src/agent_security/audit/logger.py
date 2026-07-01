"""AuditLogger — builds and chains audit entries, writes them to a sink."""

from __future__ import annotations

import uuid
from typing import Any

from agent_security.audit.models import GENESIS_HASH, AuditEntry, compute_entry_hash
from agent_security.audit.sink import GovernanceEventSink, InMemoryEventSink
from agent_security.policy.models import PolicyDecision


class AuditLogger:
    """Chains audit entries (Merkle) and persists them via a sink.

    ``log_decision(context, decision)`` matches the gate's ``AuditSink``
    protocol, so an AuditLogger can be passed straight into ``govern()``.
    """

    def __init__(self, sink: GovernanceEventSink | None = None) -> None:
        self._sink = sink or InMemoryEventSink()
        existing = self._sink.all_entries()
        self._last_hash = existing[-1].entry_hash if existing else GENESIS_HASH

    @property
    def sink(self) -> GovernanceEventSink:
        return self._sink

    def _finalize(self, entry: AuditEntry) -> AuditEntry:
        entry.previous_hash = self._last_hash
        entry.entry_hash = compute_entry_hash(entry)
        self._sink.write(entry)
        self._last_hash = entry.entry_hash
        return entry

    def log_decision(
        self,
        context: dict[str, Any],
        decision: PolicyDecision,
        *,
        trust_score: int = 0,
        parent_agent_id: str | None = None,
    ) -> AuditEntry:
        agent = context.get("agent", {}) if isinstance(context.get("agent"), dict) else {}
        agent_id = context.get("agent_id") or agent.get("id", "")
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            parent_agent_id=parent_agent_id,
            event_type="tool_call",
            tool_name=context.get("tool_name", ""),
            tool_args=context.get("args", {}) or {},
            decision=decision.action.value,
            matched_rule=decision.matched_rule,
            policy_version=decision.policy_version,
            trust_score=trust_score,
            privilege_ring=int(agent.get("ring", 3)),
            compliance_tags=list(decision.tags),
            partition_key=agent_id or "default",
        )
        return self._finalize(entry)

    def log_spawn(
        self,
        parent_id: str,
        child_id: str,
        delegated_scope: list[str],
    ) -> AuditEntry:
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            agent_id=child_id,
            parent_agent_id=parent_id,
            event_type="spawn",
            tool_name="spawn_subagent",
            tool_args={"delegated_scope": delegated_scope},
            decision="allow",
            partition_key=parent_id or "default",
        )
        return self._finalize(entry)

    def verify_integrity(self, entries: list[AuditEntry] | None = None) -> bool:
        if entries is None:
            return self._sink.verify_chain()
        from agent_security.audit.sink import _verify

        return _verify(entries)

    def query_by_agent(self, agent_id: str, limit: int = 100) -> list[AuditEntry]:
        return self._sink.query({"agent_id": agent_id}, limit)

    def query_by_compliance(self, tag: str, limit: int = 100) -> list[AuditEntry]:
        return self._sink.query({"compliance_tags": tag}, limit)
