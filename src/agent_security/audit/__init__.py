"""Audit layer — tamper-evident, Merkle-chained decision log."""

from agent_security.audit.logger import AuditLogger
from agent_security.audit.models import AuditEntry, compute_entry_hash
from agent_security.audit.sink import (
    CompositeEventSink,
    FileEventSink,
    GovernanceEventSink,
    InMemoryEventSink,
)

__all__ = [
    "AuditEntry",
    "compute_entry_hash",
    "AuditLogger",
    "GovernanceEventSink",
    "FileEventSink",
    "InMemoryEventSink",
    "CompositeEventSink",
]
