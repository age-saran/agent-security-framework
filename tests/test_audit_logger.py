"""Tests for the Merkle-chained audit logger and sinks."""

from __future__ import annotations

import contextlib
from pathlib import Path

from agent_security.audit import AuditLogger, FileEventSink, InMemoryEventSink
from agent_security.governance import GovernanceDenied, govern
from agent_security.policy.models import PolicyAction, PolicyDecision

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD = str(REPO_ROOT / "examples" / "policies" / "production.yaml")


def _decision(action=PolicyAction.ALLOW, rule="r", tags=None):
    return PolicyDecision(action=action, matched_rule=rule, tags=tags or [], policy_version="1.0")


def _ctx(agent_id="did:agent:x", ring=1, tool="query_db"):
    return {"tool_name": tool, "args": {"q": "1"}, "agent_id": agent_id, "agent": {"id": agent_id, "ring": ring}}


def test_chain_integrity_1000_entries():
    logger = AuditLogger(InMemoryEventSink())
    for i in range(1000):
        logger.log_decision(_ctx(tool=f"t{i}"), _decision())
    assert logger.verify_integrity() is True
    assert len(logger.sink.all_entries()) == 1000


def test_tamper_breaks_chain():
    sink = InMemoryEventSink()
    logger = AuditLogger(sink)
    for i in range(10):
        logger.log_decision(_ctx(tool=f"t{i}"), _decision())
    # Tamper with a stored entry.
    sink.all_entries()[5].tool_args = {"q": "HACKED"}
    assert logger.verify_integrity() is False


def test_file_sink_roundtrip(tmp_path: Path):
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(FileEventSink(p))
    logger.log_decision(_ctx(), _decision(action=PolicyAction.DENY, tags=["pdpa"]))
    # New logger reloads from disk and continues the chain.
    logger2 = AuditLogger(FileEventSink(p))
    logger2.log_decision(_ctx(tool="another"), _decision())
    assert logger2.verify_integrity() is True
    assert len(logger2.sink.all_entries()) == 2


def test_log_spawn_and_queries():
    logger = AuditLogger(InMemoryEventSink())
    logger.log_decision(_ctx(agent_id="a", tool="read"), _decision(tags=["soc2"]))
    logger.log_spawn(parent_id="a", child_id="a.1", delegated_scope=["read:data"])
    logger.log_decision(_ctx(agent_id="a.1", tool="read"), _decision(tags=["pdpa"]))
    assert len(logger.query_by_agent("a.1")) == 2  # spawn event + tool_call
    assert len(logger.query_by_compliance("pdpa")) == 1
    assert logger.verify_integrity() is True


def test_gate_integration_logs_decision():
    logger = AuditLogger(InMemoryEventSink())

    @govern(policy=PROD, audit_sink=logger)
    def delete_file(path: str) -> str:
        return "x"

    with contextlib.suppress(GovernanceDenied):
        delete_file("/etc/passwd")
    entries = logger.sink.all_entries()
    assert len(entries) == 1
    assert entries[0].decision == "deny"
    assert entries[0].tool_name == "delete_file"
    assert logger.verify_integrity() is True
