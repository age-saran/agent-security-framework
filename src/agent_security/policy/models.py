"""Core policy data models — shared schema ``governance.toolkit/v1``.

These models are the contract between the Python SDK and the C#/.NET SDK.
Field names and the YAML representation MUST stay in sync across both so a
single policy document drives identical decisions in either runtime.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

API_VERSION = "governance.toolkit/v1"


class PolicyAction(str, Enum):
    """The five governance decisions."""

    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    STEP_UP = "step_up"
    DEFER = "defer"


class PolicyOperator(str, Enum):
    """Comparison operators usable in a condition."""

    IN = "in"
    NOT_IN = "not_in"
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    MATCHES = "matches"  # regex (re.search)
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"


class PolicyCondition(BaseModel):
    """A single field test. All conditions in a rule are AND-ed together."""

    model_config = ConfigDict(extra="forbid")

    field: str  # dotted path into the context, e.g. "agent.ring"
    operator: PolicyOperator
    value: Any = None


class PolicyRule(BaseModel):
    """A named rule: when every condition matches, ``action`` is returned."""

    model_config = ConfigDict(extra="forbid")

    name: str
    conditions: list[PolicyCondition] = Field(default_factory=list)
    action: PolicyAction
    priority: int = 0
    description: str = ""
    approvers: list[str] = Field(default_factory=list)  # for STEP_UP
    modify_params: dict[str, Any] = Field(default_factory=dict)  # for MODIFY
    tags: list[str] = Field(default_factory=list)  # compliance tags


class PolicyDefaults(BaseModel):
    """Fallback when no rule matches. Defaults to fail-closed (DENY)."""

    model_config = ConfigDict(extra="forbid")

    action: PolicyAction = PolicyAction.DENY


class PolicyDocument(BaseModel):
    """A complete policy: defaults + ordered rules."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    api_version: str = Field(default=API_VERSION, alias="apiVersion")
    name: str
    version: str = "1.0"
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    rules: list[PolicyRule] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    """The result of evaluating a context against a policy."""

    model_config = ConfigDict(extra="forbid")

    action: PolicyAction
    matched_rule: str | None = None
    description: str = ""
    approvers: list[str] = Field(default_factory=list)
    modify_params: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evaluation_time_ms: float = 0.0
    policy_version: str = ""

    @property
    def allowed(self) -> bool:
        """True only for a plain ALLOW (MODIFY still needs param rewrite)."""
        return self.action is PolicyAction.ALLOW
