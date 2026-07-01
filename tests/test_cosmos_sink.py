"""CosmosEventSink tests using an injected fake container (no Azure needed)."""

from __future__ import annotations

from agent_security.audit import AuditLogger
from agent_security.audit.cosmos_sink import CosmosEventSink
from agent_security.policy.models import PolicyAction, PolicyDecision


class FakeContainer:
    """Minimal stand-in for an Azure Cosmos container client."""

    def __init__(self):
        self.items: list[dict] = []

    def upsert_item(self, item):
        self.items = [i for i in self.items if i["id"] != item["id"]]
        self.items.append(item)

    def query_items(self, query, parameters=None, enable_cross_partition_query=False):
        if parameters:
            pid = next((p["value"] for p in parameters if p["name"] == "@id"), None)
            if pid is not None:
                return [i for i in self.items if i["id"] == pid]
        return sorted(self.items, key=lambda i: i["timestamp"])


def _ctx(tool="query_db"):
    return {"tool_name": tool, "args": {"q": "1"}, "agent_id": "a", "agent": {"id": "a", "ring": 1}}


def _dec():
    return PolicyDecision(action=PolicyAction.ALLOW, matched_rule="r", policy_version="1.0")


def test_cosmos_write_and_chain():
    sink = CosmosEventSink(container_client=FakeContainer())
    logger = AuditLogger(sink)
    for i in range(50):
        logger.log_decision(_ctx(tool=f"t{i}"), _dec())
    assert len(sink.all_entries()) == 50
    assert sink.verify_chain() is True


def test_cosmos_read_by_id():
    sink = CosmosEventSink(container_client=FakeContainer())
    logger = AuditLogger(sink)
    entry = logger.log_decision(_ctx(), _dec())
    got = sink.read(entry.id)
    assert got is not None and got.id == entry.id
