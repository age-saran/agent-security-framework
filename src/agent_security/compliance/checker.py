"""Compliance coverage checker.

Maps each control of a standard to the framework capabilities it requires, then
reports which controls are covered by the currently-built capabilities and which
are still gaps. This is a *coverage* check (does the framework provide the
control), not a runtime attestation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Control:
    """One control requirement from a compliance standard."""

    id: str
    title: str
    requires: tuple[str, ...]  # capability keys that satisfy this control
    tags: tuple[str, ...] = ()


@dataclass
class ControlResult:
    control: Control
    covered: bool
    missing: list[str] = field(default_factory=list)


# Capabilities the framework provides. Phase 1–2 are built; later phases flip
# their flags on as they land.
DEFAULT_CAPABILITIES: set[str] = {
    # Phase 1
    "policy_enforcement",
    "fail_closed_default",
    "ring_access_control",
    "step_up_approval",
    "pii_detection",
    "compliance_tagging",
    # Phase 2
    "audit_trail",
    "audit_merkle_chain",
    "audit_immutable_store",
    "data_localization_control",
    "cross_border_control",
    # not yet: identity_crypto (P3), delegation_chain (P3),
    # kill_switch (P5), sandbox_isolation (P5)
}


class ComplianceChecker:
    """Evaluate control coverage of one or more standards."""

    def __init__(self, capabilities: set[str] | None = None) -> None:
        self.capabilities = capabilities or set(DEFAULT_CAPABILITIES)

    def check(self, standard_controls: list[Control]) -> list[ControlResult]:
        results = []
        for c in standard_controls:
            missing = [r for r in c.requires if r not in self.capabilities]
            results.append(ControlResult(control=c, covered=not missing, missing=missing))
        return results

    def summary(self, standard_controls: list[Control]) -> dict:
        results = self.check(standard_controls)
        covered = sum(1 for r in results if r.covered)
        total = len(results)
        return {
            "total": total,
            "covered": covered,
            "coverage_pct": round(100 * covered / total, 1) if total else 0.0,
            "gaps": [
                {"id": r.control.id, "title": r.control.title, "missing": r.missing}
                for r in results
                if not r.covered
            ],
        }
