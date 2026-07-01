"""PDPA (Thailand) — Personal Data Protection Act B.E. 2562 controls & helpers."""

from __future__ import annotations

import re
from typing import Any

from agent_security.compliance.checker import Control

# Thai National ID: 1-2345-67890-12-3 (13 digits, grouped 1-4-5-2-1).
THAI_NATIONAL_ID = re.compile(r"\b\d{1}-?\d{4}-?\d{5}-?\d{2}-?\d{1}\b")

CONTROLS: list[Control] = [
    Control("PDPA-S19", "Consent before processing personal data",
            ("policy_enforcement",), ("pdpa",)),
    Control("PDPA-S24", "Lawful basis / PII detection before use",
            ("pii_detection",), ("pdpa",)),
    Control("PDPA-S28", "Cross-border transfer controls",
            ("cross_border_control", "step_up_approval"), ("pdpa",)),
    Control("PDPA-S37", "Security measures — audit & integrity",
            ("audit_trail", "audit_merkle_chain"), ("pdpa",)),
    Control("PDPA-S37-LOC", "Data localization (TH data stays in TH)",
            ("data_localization_control",), ("pdpa",)),
    Control("PDPA-S30", "Right to erasure support",
            ("audit_trail",), ("pdpa",)),
]


class PDPAComplianceRule:
    """Runtime helpers enforcing PDPA obligations.

    Enforces: consent verification before PII processing, cross-border transfer
    controls, and DPO notification signals. Data localization and 72-hour breach
    tracking are policy-driven and audited via the standard audit trail.
    """

    DEFAULT_DPO = "dpo@company.com"

    @staticmethod
    def contains_thai_pii(text: str | None) -> bool:
        return bool(text) and THAI_NATIONAL_ID.search(str(text)) is not None

    @staticmethod
    def has_consent(context: dict[str, Any]) -> bool:
        consent = context.get("consent") or context.get("data_subject", {}).get("consent")
        return bool(consent)

    @classmethod
    def requires_cross_border_approval(cls, context: dict[str, Any]) -> bool:
        """True when data leaves Thailand and needs DPO step-up approval."""
        if context.get("tool_name") != "transfer_data":
            return False
        dest = context.get("destination", {})
        country = dest.get("country") if isinstance(dest, dict) else None
        return country is not None and country != "TH"
