"""Generate compliance evidence bundles for auditors."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_security.audit.models import AuditEntry
from agent_security.compliance.checker import ComplianceChecker, Control


def generate_evidence(
    checker: ComplianceChecker,
    standards: dict[str, list[Control]],
    audit_entries: list[AuditEntry] | None = None,
    chain_verified: bool | None = None,
) -> dict[str, Any]:
    """Build a machine-readable evidence document.

    ``standards`` maps a standard name to its control list, e.g.
    ``{"soc2": soc2.CONTROLS, "pdpa": pdpa.CONTROLS}``.
    """
    audit_entries = audit_entries or []
    coverage = {name: checker.summary(controls) for name, controls in standards.items()}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework_version": "0.3.0",
        "capabilities": sorted(checker.capabilities),
        "coverage": coverage,
        "audit": {
            "entry_count": len(audit_entries),
            "chain_verified": chain_verified,
            "compliance_tags_seen": sorted(
                {t for e in audit_entries for t in e.compliance_tags}
            ),
        },
    }
