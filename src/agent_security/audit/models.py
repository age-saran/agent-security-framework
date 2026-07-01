"""Audit entry model and Merkle-chain hashing."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

GENESIS_HASH = "0" * 64


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditEntry(BaseModel):
    """A single tamper-evident audit record in the Merkle chain."""

    model_config = ConfigDict(extra="forbid")

    id: str
    timestamp: datetime = Field(default_factory=_utcnow)
    agent_id: str = ""
    parent_agent_id: str | None = None
    event_type: str = "tool_call"  # tool_call | delegation | spawn | kill
    tool_name: str = ""
    tool_args: dict[str, Any] = Field(default_factory=dict)
    decision: str = ""  # PolicyAction value
    matched_rule: str | None = None
    policy_version: str = ""
    trust_score: int = 0
    privilege_ring: int = 3
    compliance_tags: list[str] = Field(default_factory=list)
    previous_hash: str = GENESIS_HASH
    entry_hash: str = ""
    partition_key: str = ""

    def content_dict(self) -> dict[str, Any]:
        """Deterministic content used for hashing (excludes entry_hash)."""
        data = self.model_dump(mode="json", exclude={"entry_hash"})
        return data


def compute_entry_hash(entry: AuditEntry) -> str:
    """SHA-256 over canonical JSON of the entry content + previous_hash.

    ``previous_hash`` is already part of the content, so each hash commits to
    the entire prior chain — tampering with any earlier entry breaks every
    subsequent hash.
    """
    payload = json.dumps(entry.content_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
