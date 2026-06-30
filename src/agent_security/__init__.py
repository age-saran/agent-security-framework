"""Agent Security Framework — Enterprise agent governance.

Public API is exposed lazily so that importing the top-level package does not
require optional submodules (which land in later phases) to exist yet.
"""

from __future__ import annotations

__version__ = "0.1.0"

# Phase 1+ will populate these. Listed here so the public surface is documented
# and `from agent_security import X` works once the modules land.
__all__ = [
    "__version__",
    # policy (Phase 1)
    "PolicyAction",
    "PolicyDecision",
    "PolicyDocument",
    "PolicyRule",
    "PolicyCondition",
    "PolicyOperator",
    "PolicyEvaluator",
    # governance (Phase 1)
    "govern",
    "GovernanceDenied",
    "GovernanceStepUpRequired",
    "GovernanceDeferred",
]


def __getattr__(name: str) -> object:
    """Lazily resolve public symbols from their submodules (PEP 562).

    Avoids import errors at package-import time for modules not yet implemented.
    """
    _map = {
        "PolicyAction": ("agent_security.policy.models", "PolicyAction"),
        "PolicyDecision": ("agent_security.policy.models", "PolicyDecision"),
        "PolicyDocument": ("agent_security.policy.models", "PolicyDocument"),
        "PolicyRule": ("agent_security.policy.models", "PolicyRule"),
        "PolicyCondition": ("agent_security.policy.models", "PolicyCondition"),
        "PolicyOperator": ("agent_security.policy.models", "PolicyOperator"),
        "PolicyEvaluator": ("agent_security.policy.engine", "PolicyEvaluator"),
        "govern": ("agent_security.governance.gate", "govern"),
        "GovernanceDenied": ("agent_security.governance.exceptions", "GovernanceDenied"),
        "GovernanceStepUpRequired": (
            "agent_security.governance.exceptions",
            "GovernanceStepUpRequired",
        ),
        "GovernanceDeferred": (
            "agent_security.governance.exceptions",
            "GovernanceDeferred",
        ),
    }
    if name in _map:
        module_name, attr = _map[name]
        import importlib

        module = importlib.import_module(module_name)
        return getattr(module, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
