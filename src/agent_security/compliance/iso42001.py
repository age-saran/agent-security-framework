"""ISO/IEC 42001 (AI management system) — representative control mapping."""

from __future__ import annotations

from agent_security.compliance.checker import Control

CONTROLS: list[Control] = [
    Control("A.6.2", "AI system operational controls / policy enforcement",
            ("policy_enforcement",), ("iso42001",)),
    Control("A.6.2.4", "Human oversight of AI actions",
            ("step_up_approval",), ("iso42001",)),
    Control("A.7.4", "Logging and traceability of AI decisions",
            ("audit_trail", "audit_merkle_chain"), ("iso42001",)),
    Control("A.8.3", "Fail-safe / fail-closed behaviour",
            ("fail_closed_default",), ("iso42001",)),
    Control("A.9.2", "Accountability via agent identity",
            ("identity_crypto",), ("iso42001",)),  # gap until Phase 3
]
