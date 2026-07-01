"""SOC 2 (Trust Services Criteria) control mapping — subset CC6.1–CC9.1."""

from __future__ import annotations

from agent_security.compliance.checker import Control

CONTROLS: list[Control] = [
    Control("CC6.1", "Logical access controls restrict privileged operations",
            ("policy_enforcement", "ring_access_control"), ("soc2",)),
    Control("CC6.2", "Access requires authorization / approval",
            ("step_up_approval",), ("soc2",)),
    Control("CC6.3", "Sensitive actions require additional approval",
            ("step_up_approval",), ("soc2",)),
    Control("CC7.2", "Security events are logged and monitored",
            ("audit_trail",), ("soc2",)),
    Control("CC7.3", "Audit records are protected from tampering",
            ("audit_merkle_chain", "audit_immutable_store"), ("soc2",)),
    Control("CC8.1", "Changes are controlled (fail-closed default)",
            ("fail_closed_default",), ("soc2",)),
    Control("CC9.1", "Risk mitigation via emergency termination",
            ("kill_switch",), ("soc2",)),  # gap until Phase 5
]
