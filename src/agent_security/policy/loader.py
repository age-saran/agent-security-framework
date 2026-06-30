"""YAML policy loading and validation for ``governance.toolkit/v1``."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_security.policy.models import API_VERSION, PolicyDocument


class PolicyValidationError(ValueError):
    """Raised when a YAML policy fails schema validation."""


def _parse_document(data: dict[str, Any], source: str) -> PolicyDocument:
    if not isinstance(data, dict):
        raise PolicyValidationError(f"{source}: top-level YAML must be a mapping")
    api_version = data.get("apiVersion", data.get("api_version"))
    if api_version not in (None, API_VERSION):
        raise PolicyValidationError(
            f"{source}: unsupported apiVersion {api_version!r} (expected {API_VERSION!r})"
        )
    try:
        return PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyValidationError(f"{source}: {exc}") from exc


def load_policy(path: str | os.PathLike[str]) -> PolicyDocument:
    """Load and validate a single YAML policy file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"policy file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return _parse_document(data, str(p))


def load_policies(directory: str | os.PathLike[str]) -> list[PolicyDocument]:
    """Load every ``*.yaml`` / ``*.yml`` policy in a directory.

    Returned documents are sorted by descending document version string so that
    callers merging rules see the most recent policy first. Individual rule
    priority still governs evaluation order inside :class:`PolicyEvaluator`.
    """
    d = Path(directory)
    if not d.is_dir():
        raise NotADirectoryError(f"not a directory: {d}")
    docs: list[PolicyDocument] = []
    for f in sorted(d.iterdir()):
        if f.suffix.lower() in (".yaml", ".yml"):
            docs.append(load_policy(f))
    return docs


class PolicyWatcher:
    """Poll-based hot-reload helper for development.

    Tracks mtimes of watched files; :meth:`poll` reloads changed files and
    returns the set of paths that were reloaded.
    """

    def __init__(self, paths: list[str | os.PathLike[str]]) -> None:
        self._paths = [Path(p) for p in paths]
        self._mtimes: dict[Path, float] = {}
        self.documents: dict[Path, PolicyDocument] = {}
        self.poll()  # prime

    def poll(self) -> list[Path]:
        changed: list[Path] = []
        for p in self._paths:
            if not p.is_file():
                continue
            mtime = p.stat().st_mtime
            if self._mtimes.get(p) != mtime:
                self.documents[p] = load_policy(p)
                self._mtimes[p] = mtime
                changed.append(p)
        return changed
