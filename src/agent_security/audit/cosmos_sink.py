"""Azure Cosmos DB audit sink — primary production backend.

The azure-cosmos dependency is imported lazily so the module (and the rest of
the framework) imports fine without the ``azure`` extra installed. A container
client may be injected directly for testing.
"""

from __future__ import annotations

from typing import Any

from agent_security.audit.models import AuditEntry
from agent_security.audit.sink import _verify


class CosmosEventSink:
    """Persists audit entries to an Azure Cosmos DB container.

    Partitioning uses ``partition_key`` (agent_id / tenant_id). Entries are
    immutable; the Merkle chain provides tamper-evidence on top of Cosmos.
    """

    def __init__(
        self,
        connection_string: str | None = None,
        database: str = "agentsecurity",
        container: str = "audit",
        *,
        container_client: Any = None,
    ) -> None:
        if container_client is not None:
            self._container = container_client
            return
        try:
            from azure.cosmos import CosmosClient, PartitionKey  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "CosmosEventSink requires the 'azure' extra: pip install "
                "agent-security-framework[azure]"
            ) from exc
        if not connection_string:
            raise ValueError("connection_string is required for CosmosEventSink")
        client = CosmosClient.from_connection_string(connection_string)
        db = client.create_database_if_not_exists(database)
        self._container = db.create_container_if_not_exists(
            id=container, partition_key=PartitionKey(path="/partition_key")
        )

    def write(self, entry: AuditEntry) -> None:
        self._container.upsert_item(entry.model_dump(mode="json"))

    def read(self, entry_id: str) -> AuditEntry | None:
        query = "SELECT * FROM c WHERE c.id = @id"
        items = list(
            self._container.query_items(
                query=query,
                parameters=[{"name": "@id", "value": entry_id}],
                enable_cross_partition_query=True,
            )
        )
        return AuditEntry.model_validate(items[0]) if items else None

    def all_entries(self) -> list[AuditEntry]:
        items = list(
            self._container.query_items(
                query="SELECT * FROM c ORDER BY c.timestamp ASC",
                enable_cross_partition_query=True,
            )
        )
        return [AuditEntry.model_validate(i) for i in items]

    def query(self, filters: dict, limit: int = 100) -> list[AuditEntry]:
        clauses, params = [], []
        for i, (k, v) in enumerate(filters.items()):
            if k == "compliance_tags":
                clauses.append(f"ARRAY_CONTAINS(c.compliance_tags, @p{i})")
            else:
                clauses.append(f"c.{k} = @p{i}")
            params.append({"name": f"@p{i}", "value": v})
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        query = f"SELECT * FROM c{where} ORDER BY c.timestamp ASC OFFSET 0 LIMIT {int(limit)}"
        items = list(
            self._container.query_items(
                query=query, parameters=params, enable_cross_partition_query=True
            )
        )
        return [AuditEntry.model_validate(i) for i in items]

    def verify_chain(self) -> bool:
        return _verify(self.all_entries())
