"""Compliance layer — control coverage for SOC 2, ISO 42001, HIPAA, PDPA."""

from agent_security.compliance import hipaa, iso42001, pdpa, soc2
from agent_security.compliance.checker import (
    ComplianceChecker,
    Control,
    ControlResult,
)
from agent_security.compliance.evidence import generate_evidence
from agent_security.compliance.pdpa import PDPAComplianceRule

STANDARDS = {
    "soc2": soc2.CONTROLS,
    "iso42001": iso42001.CONTROLS,
    "hipaa": hipaa.CONTROLS,
    "pdpa": pdpa.CONTROLS,
}

__all__ = [
    "Control",
    "ControlResult",
    "ComplianceChecker",
    "PDPAComplianceRule",
    "generate_evidence",
    "STANDARDS",
    "soc2",
    "iso42001",
    "hipaa",
    "pdpa",
]
