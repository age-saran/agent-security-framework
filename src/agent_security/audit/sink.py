"""Pluggable audit sinks — where Merkle-chained entries are persisted."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from agent_security.audit.models import AuditEntry, compute_entry_hash


@runtime_checkable
class GovernanceEventSink(Protocol):
    """A destination for audit entries (sync API)."""

    def write(self, entry: AuditEntry) -> None: ...
    def read(self, entry_id: str) -> AuditEntry | None: ...
    def all_entries(self) -> list[AuditEntry]: ...

    def query(self, filters: dict, limit: int = 100) -> list[AuditEntry]:
        results = []
        for e in self.all_entries():
            if all(getattr(e, k, None) == v or v in (getattr(e, k, []) or []) for k, v in filters.items()):
                results.append(e)
            if len(results) >= limit:
                break
        return results

    def verify_chain(self) -> bool:
        return _verify(self.all_entries())


def _verify(entries: list[AuditEntry]) -> bool:
    prev = None
    for e in entries:
        if compute_entry_hash(e) != e.entry_hash:
            return False
        if prev is not None and e.previous_hash != prev.entry_hash:
            return False
        prev = e
    return True


class InMemoryEventSink:
    """Simple list-backed sink — tests and development."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def write(self, entry: AuditEntry) -> None:
        self._entries.append(entry)

    def read(self, entry_id: str) -> AuditEntry | None:
        return next((e for e in self._entries if e.id == entry_id), None)

    def all_entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def query(self, filters: dict, limit: int = 100) -> list[AuditEntry]:
        out = []
        for e in self._entries:
            ok = True
            for k, v in filters.items():
                actual = getattr(e, k, None)
                if isinstance(actual, list):
                    if v not in actual:
                        ok = False
                        break
                elif actual != v:
                    ok = False
                    break
            if ok:
                out.append(e)
            if len(out) >= limit:
                break
        return out

    def verify_chain(self) -> bool:
        return _verify(self._entries)


class FileEventSink(InMemoryEventSink):
    """Append-only JSONL sink. Loads existing entries on init."""

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self._path = Path(path)
        if self._path.exists():
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._entries.append(AuditEntry.model_validate_json(line))

    def write(self, entry: AuditEntry) -> None:
        super().write(entry)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(entry.model_dump_json() + "\n")


class CompositeEventSink:
    """Fan-out to multiple sinks (e.g. Cosmos + file backup)."""

    def __init__(self, sinks: list[GovernanceEventSink]) -> None:
        self._sinks = sinks

    def write(self, entry: AuditEntry) -> None:
        for s in self._sinks:
            s.write(entry)

    def read(self, entry_id: str) -> AuditEntry | None:
        for s in self._sinks:
            found = s.read(entry_id)
            if found is not None:
                return found
        return None

    def all_entries(self) -> list[AuditEntry]:
        return self._sinks[0].all_entries() if self._sinks else []

    def query(self, filters: dict, limit: int = 100) -> list[AuditEntry]:
        return self._sinks[0].query(filters, limit) if self._sinks else []

    def verify_chain(self) -> bool:
        return all(s.verify_chain() for s in self._sinks)
