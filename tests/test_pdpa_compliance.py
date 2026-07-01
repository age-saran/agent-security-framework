"""PDPA (Thailand) helper and compliance-coverage tests."""

from __future__ import annotations

from agent_security.compliance import (
    STANDARDS,
    ComplianceChecker,
    PDPAComplianceRule,
    generate_evidence,
)


def test_thai_pii_detection():
    assert PDPAComplianceRule.contains_thai_pii("id 1-1234-12345-12-1 here") is True
    assert PDPAComplianceRule.contains_thai_pii("1123412345121") is True  # unhyphenated
    assert PDPAComplianceRule.contains_thai_pii("just text") is False
    assert PDPAComplianceRule.contains_thai_pii(None) is False


def test_cross_border_requires_approval():
    assert PDPAComplianceRule.requires_cross_border_approval(
        {"tool_name": "transfer_data", "destination": {"country": "US"}}
    ) is True
    assert PDPAComplianceRule.requires_cross_border_approval(
        {"tool_name": "transfer_data", "destination": {"country": "TH"}}
    ) is False
    assert PDPAComplianceRule.requires_cross_border_approval(
        {"tool_name": "read_data"}
    ) is False


def test_consent():
    assert PDPAComplianceRule.has_consent({"consent": True}) is True
    assert PDPAComplianceRule.has_consent({"data_subject": {"consent": True}}) is True
    assert PDPAComplianceRule.has_consent({}) is False


def test_pdpa_fully_covered():
    checker = ComplianceChecker()
    summary = checker.summary(STANDARDS["pdpa"])
    assert summary["covered"] == summary["total"]
    assert summary["coverage_pct"] == 100.0


def test_soc2_has_kill_switch_gap():
    checker = ComplianceChecker()
    summary = checker.summary(STANDARDS["soc2"])
    gap_ids = {g["id"] for g in summary["gaps"]}
    assert "CC9.1" in gap_ids  # kill_switch not built until Phase 5
    assert summary["coverage_pct"] < 100.0


def test_evidence_bundle():
    checker = ComplianceChecker()
    ev = generate_evidence(checker, {"pdpa": STANDARDS["pdpa"], "soc2": STANDARDS["soc2"]},
                           audit_entries=[], chain_verified=True)
    assert "pdpa" in ev["coverage"]
    assert ev["coverage"]["pdpa"]["coverage_pct"] == 100.0
    assert ev["audit"]["chain_verified"] is True
