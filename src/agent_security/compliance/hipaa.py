"""HIPAA Security Rule — technical safeguards (45 CFR 164.312)."""

from __future__ import annotations

from agent_security.compliance.checker import Control

CONTROLS: list[Control] = [
    Control("164.312(a)(1)", "Access control to PHI",
            ("policy_enforcement", "ring_access_control"), ("hipaa",)),
    Control("164.312(b)", "Audit controls / activity logging",
            ("audit_trail", "audit_merkle_chain"), ("hipaa",)),
    Control("164.312(c)(1)", "Integrity — PHI not improperly altered",
            ("audit_immutable_store",), ("hipaa",)),
    Control("164.312(d)", "Person/entity authentication",
            ("identity_crypto",), ("hipaa",)),  # gap until Phase 3
    Control("164.312(e)(1)", "Transmission security / PII detection",
            ("pii_detection",), ("hipaa",)),
]
