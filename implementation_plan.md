# Agent Security Framework — Implementation Plan v2

Enterprise Agent Security Framework ตาม Microsoft Agent Governance Toolkit (AGT)
สำหรับองค์กรที่ใช้ multi-cloud, multi-framework AI agent ecosystem

---

## Requirements Summary

| Requirement | Specification |
|-------------|---------------|
| **Languages** | Python 3.10+ **AND** C#/.NET 8+ |
| **AI Frameworks** | Azure OpenAI, Azure AI Foundry, AWS Bedrock, AWS AgentCore, Gemini, Gemini Enterprise, Google Antigravity, Claude Code, Claude Cowork, Microsoft 365 Copilot, ChatGPT Business Plan, Openclaw |
| **Policy Backend** | YAML-first, designed for OPA/Rego extensibility |
| **Agent Topology** | Multi-agent mesh + runtime subagent spawning |
| **Compliance** | SOC 2, ISO 42001, HIPAA, **PDPA (Thailand)** |
| **External Tools** | MCP servers, APIs, databases |
| **Human-in-the-Loop** | **MS Teams** + **Outlook** for STEP_UP approvals |
| **Audit Storage** | **Azure Cosmos DB** (Merkle-chain) |
| **Sandbox** | **Azure Container Apps** |

---

## Architecture Overview

### Dual-Language Architecture

Python SDK และ C#/.NET SDK **share** policy schema เดียวกัน (YAML `governance.toolkit/v1`) และสื่อสารกันผ่าน wire protocol เดียวกัน ทำให้ agents จากทั้งสอง ecosystem ทำงานร่วมกันได้

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     AGENT SECURITY FRAMEWORK                                 ║
║                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │                      SHARED POLICY LAYER                               │  ║
║  │   YAML Policy Schema (governance.toolkit/v1) ──► OPA/Rego (pluggable) │  ║
║  │   5 Decisions: ALLOW │ DENY │ MODIFY │ STEP_UP │ DEFER                │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌──────────────────────────┐     ┌──────────────────────────────────────┐   ║
║  │    PYTHON SDK            │     │    C# / .NET SDK                     │   ║
║  │                          │     │                                      │   ║
║  │  ● PolicyEvaluator       │     │  ● GovernanceKernel                  │   ║
║  │  ● govern() wrapper      │     │  ● IGovernanceMiddleware             │   ║
║  │  ● AuditLogger           │◄───►│  ● AuditService                     │   ║
║  │  ● AgentIdentity         │wire │  ● AgentIdentity                     │   ║
║  │  ● TrustScorer           │proto│  ● TrustScorer                       │   ║
║  │  ● MeshRegistry          │     │  ● MeshRegistry                      │   ║
║  └──────────────────────────┘     └──────────────────────────────────────┘   ║
║                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │                   INFRASTRUCTURE LAYER                                  │  ║
║  │                                                                         │  ║
║  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │  ║
║  │  │ Azure Cosmos │  │ Azure Cont.  │  │  MS Teams /  │  │ MCP Gate-  │  │  ║
║  │  │ DB (Audit)   │  │ Apps (Sand.) │  │  Outlook     │  │ way        │  │  ║
║  │  └─────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │                   AI FRAMEWORK ADAPTERS                                  │  ║
║  │                                                                         │  ║
║  │  Azure OpenAI │ AI Foundry │ AWS Bedrock │ AgentCore │ Gemini │ ADK    │  ║
║  │  Antigravity  │ Claude Code │ Cowork │ M365 Copilot │ ChatGPT │ Claw  │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

### Multi-Agent Mesh with Subagent Spawning

```
                    ┌─────────────────┐
                    │  AgentRegistry   │ ← Service discovery
                    │  (Mesh Control)  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
        │ Agent A    │ │ Agent B    │ │ Agent C    │
        │ Ring 1     │ │ Ring 2     │ │ Ring 0     │
        │ Trust: 850 │ │ Trust: 700 │ │ Trust: 960 │
        └─────┬─────┘ └───────────┘ └───────────┘
              │ spawn at runtime
        ┌─────┴─────┐
        │ SubAgent  │ ← Inherits parent scope (never exceeds)
        │ A.1       │    Gets Ring 3 (sandbox) by default
        │ Ring 3    │    Parent delegation chain signed
        │ Trust: 400│
        └───────────┘
```

### Governance Flow

```
Agent Request
    │
    ▼
┌──────────────┐     ┌──────────────┐     ┌───────────────┐
│ Identity     │────►│ Trust Gate   │────►│ Policy Engine │
│ Verification │     │ (Ring Check) │     │ (YAML/OPA)    │
└──────────────┘     └──────────────┘     └───────┬───────┘
                                                   │
                          ┌────────────────────────┼──────────────┐
                          │            │           │              │
                       ALLOW        DENY       STEP_UP        MODIFY
                          │            │           │              │
                          ▼            ▼           ▼              ▼
                     ┌────────┐  ┌─────────┐ ┌─────────┐  ┌──────────┐
                     │Execute │  │Raise     │ │Teams /  │  │Rewrite   │
                     │Tool    │  │Governance│ │Outlook  │  │Params →  │
                     │        │  │Denied    │ │Approval │  │Execute   │
                     └───┬────┘  └────┬─────┘ └────┬────┘  └────┬─────┘
                         │            │            │             │
                         └────────────┴────────────┴─────────────┘
                                          │
                                          ▼
                                  ┌──────────────┐
                                  │ Audit Logger │
                                  │ (Cosmos DB)  │
                                  │ Merkle Chain │
                                  └──────────────┘
```

---

## Proposed Changes

### Phase 1: Core Policy Engine & Governance Gate (Python)

สร้าง foundation ของ framework ด้วย Python ก่อน เพราะเป็น primary SDK

---

#### [NEW] [pyproject.toml](file:///Users/saran/antigravity/agent-security-framework/pyproject.toml)

```toml
[project]
name = "agent-security-framework"
version = "0.1.0"
description = "Enterprise agent governance: policy enforcement, identity, audit, and SRE"
requires-python = ">=3.10"
dependencies = [
    "pydantic>=2.0",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
full = [
    "cryptography>=41.0",
    "httpx>=0.25",
    "click>=8.0",
    "azure-cosmos>=4.7",
    "azure-identity>=1.16",
    "msgraph-sdk>=1.5",
]
azure = ["azure-cosmos>=4.7", "azure-identity>=1.16", "azure-mgmt-containerinstance>=10.0"]
teams = ["msgraph-sdk>=1.5", "msal>=1.28"]
langchain = ["langchain-core>=0.2"]
bedrock = ["boto3>=1.34"]

[project.scripts]
agsec = "agent_security.cli.main:cli"
```

---

#### [NEW] [src/agent_security/\_\_init\_\_.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/__init__.py)

```python
"""Agent Security Framework — Enterprise agent governance."""
__version__ = "0.1.0"

from agent_security.policy.engine import PolicyEvaluator
from agent_security.policy.models import (
    PolicyAction, PolicyDecision, PolicyDocument,
    PolicyRule, PolicyCondition, PolicyOperator,
)
from agent_security.governance.gate import govern
from agent_security.governance.exceptions import (
    GovernanceDenied, GovernanceStepUpRequired, GovernanceDeferred,
)
```

---

#### [NEW] [src/agent_security/policy/models.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/policy/models.py)

Core data models — shared schema `governance.toolkit/v1` compatible with C#/.NET SDK:

```python
class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    STEP_UP = "step_up"
    DEFER = "defer"

class PolicyOperator(str, Enum):
    IN = "in"
    NOT_IN = "not_in"
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    MATCHES = "matches"          # Regex
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    GT = "gt"; LT = "lt"; GTE = "gte"; LTE = "lte"

class PolicyCondition(BaseModel):
    field: str                   # "tool_name", "action.type", "agent.ring", etc.
    operator: PolicyOperator
    value: Any

class PolicyRule(BaseModel):
    name: str
    conditions: list[PolicyCondition]  # ALL must match (AND logic)
    action: PolicyAction
    priority: int = 0
    description: str = ""
    approvers: list[str] = []          # For STEP_UP
    modify_params: dict = {}           # For MODIFY
    tags: list[str] = []               # compliance tags: "soc2", "hipaa", "pdpa"

class PolicyDefaults(BaseModel):
    action: PolicyAction = PolicyAction.DENY   # Fail-closed

class PolicyDocument(BaseModel):
    api_version: str = "governance.toolkit/v1"
    name: str
    version: str = "1.0"
    defaults: PolicyDefaults
    rules: list[PolicyRule]
    metadata: dict = {}                # compliance: ["soc2", "pdpa"]

class PolicyDecision(BaseModel):
    action: PolicyAction
    matched_rule: str | None = None
    description: str = ""
    approvers: list[str] = []
    modify_params: dict = {}
    metadata: dict = {}
    evaluation_time_ms: float = 0.0
    policy_version: str = ""
```

---

#### [NEW] [src/agent_security/policy/engine.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/policy/engine.py)

**PolicyEvaluator** — Deterministic, fail-closed, < 0.1ms p99:

```python
class PolicyEvaluator:
    """Stateless policy evaluator with pluggable backend support.
    
    Default: YAML rules evaluated in-memory.
    Extensible: implement IPolicyBackend for OPA/Rego.
    """
    
    def __init__(
        self,
        policies: list[PolicyDocument] | None = None,
        backends: list[IPolicyBackend] | None = None,  # OPA/Rego future
    ): ...
    
    def evaluate(self, context: dict) -> PolicyDecision:
        """Evaluate context against all rules. Highest priority match wins.
        Fail-closed: returns DENY on any error."""
        ...
    
    def evaluate_tool_call(
        self,
        tool_name: str,
        args: dict,
        agent_id: str = "",
        agent_ring: int = 3,
    ) -> PolicyDecision:
        """Convenience: build context from tool call and evaluate."""
        ...
```

**IPolicyBackend** — Pluggable interface for future OPA/Rego:

```python
class IPolicyBackend(Protocol):
    """Interface for pluggable policy backends (OPA, Rego, Cedar)."""
    
    def evaluate(self, context: dict) -> PolicyDecision | None:
        """Return decision or None to defer to next backend."""
        ...
    
    @property
    def name(self) -> str: ...
```

---

#### [NEW] [src/agent_security/policy/loader.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/policy/loader.py)

- `load_policy(path: str) -> PolicyDocument` — YAML with schema validation
- `load_policies(directory: str) -> list[PolicyDocument]` — merge by priority
- `PolicyWatcher` — hot-reload on file changes (for development)
- Schema validation against `governance.toolkit/v1`

---

#### [NEW] [src/agent_security/governance/gate.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/governance/gate.py)

**`govern()`** — The primary integration point:

```python
def govern(
    func: Callable,
    policy: str | PolicyDocument | list[PolicyDocument],
    agent_id: str = "default",
    audit_sink: GovernanceEventSink | None = None,
    step_up_handler: IStepUpHandler | None = None,  # Teams/Outlook
) -> Callable:
    """Wrap any tool function with governance.
    
    Every call: evaluate policy → log decision → execute or raise.
    Supports both sync and async functions.
    """
```

- `pre_execute()` hook: policy check + trust gate
- `post_execute()` hook: output scan + audit log
- Thread-safe
- Async-aware (detects `async def` and wraps accordingly)
- Auto context extraction from function signature

---

#### [NEW] [src/agent_security/governance/exceptions.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/governance/exceptions.py)

```python
class GovernanceDenied(Exception):
    """Policy denied the action. Structurally impossible to proceed."""
    decision: PolicyDecision

class GovernanceStepUpRequired(Exception):
    """Human approval required. Will route to MS Teams / Outlook."""
    decision: PolicyDecision
    approvers: list[str]
    approval_url: str | None  # Teams Adaptive Card URL

class GovernanceDeferred(Exception):
    """Action queued for batch review."""
    decision: PolicyDecision
    queue_id: str
```

---

### Phase 2: Audit & Compliance (Azure Cosmos DB)

---

#### [NEW] [src/agent_security/audit/models.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/audit/models.py)

```python
class AuditEntry(BaseModel):
    id: str                          # UUID (Cosmos partition-friendly)
    timestamp: datetime
    agent_id: str                    # DID of the agent
    parent_agent_id: str | None      # For subagent tracking
    event_type: str                  # "tool_call", "delegation", "spawn"
    tool_name: str
    tool_args: dict
    decision: PolicyAction
    matched_rule: str | None
    policy_version: str              # Decision BOM
    trust_score: int                 # Agent trust at decision time
    privilege_ring: int              # Agent ring at decision time
    compliance_tags: list[str]       # ["soc2", "hipaa", "pdpa"]
    previous_hash: str               # Merkle chain
    entry_hash: str                  # SHA-256
    # Cosmos DB partition key
    partition_key: str               # agent_id or tenant_id
```

---

#### [NEW] [src/agent_security/audit/logger.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/audit/logger.py)

**AuditLogger** — Merkle-chain with Cosmos DB backend:

```python
class AuditLogger:
    def __init__(self, sink: GovernanceEventSink):
        self._sink = sink
        self._chain = MerkleChain()
    
    def log_decision(
        self, agent_id: str, tool_name: str, tool_args: dict,
        decision: PolicyDecision, trust_score: int, ring: int,
        parent_agent_id: str | None = None,
    ) -> AuditEntry: ...
    
    def log_spawn(
        self, parent_id: str, child_id: str, 
        delegated_scope: list[str],
    ) -> AuditEntry: ...
    
    def verify_integrity(self, entries: list[AuditEntry] | None = None) -> bool: ...
    
    async def query_by_agent(self, agent_id: str, limit: int = 100) -> list[AuditEntry]: ...
    async def query_by_compliance(self, tag: str) -> list[AuditEntry]: ...
```

---

#### [NEW] [src/agent_security/audit/sink.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/audit/sink.py)

**GovernanceEventSink** — Pluggable audit destinations:

```python
class GovernanceEventSink(Protocol):
    async def write(self, entry: AuditEntry) -> None: ...
    async def read(self, entry_id: str) -> AuditEntry | None: ...
    async def query(self, filters: dict, limit: int) -> list[AuditEntry]: ...
    async def verify_chain(self) -> bool: ...

class CosmosEventSink(GovernanceEventSink):
    """Azure Cosmos DB audit sink — primary production backend."""
    def __init__(self, connection_string: str, database: str, container: str): ...

class FileEventSink(GovernanceEventSink):
    """JSONL file — development & offline verification."""

class CompositeEventSink(GovernanceEventSink):
    """Fan-out to multiple sinks (e.g., Cosmos + File backup)."""
```

---

#### [NEW] [src/agent_security/compliance/](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/compliance/)

Compliance verification and evidence generation:

| File | Purpose |
|------|---------|
| `checker.py` | `ComplianceChecker` — verify framework coverage against standards |
| `soc2.py` | SOC 2 control mapping (CC6.1–CC9.1) |
| `iso42001.py` | ISO/IEC 42001 AI management system mapping |
| `hipaa.py` | HIPAA technical safeguard verification |
| `pdpa.py` | **PDPA Thailand** — consent tracking, data localization, cross-border transfer rules, DPO notifications |
| `evidence.py` | Generate compliance evidence JSON for auditors |

```python
class PDPAComplianceRule:
    """PDPA (Thailand) specific governance rules.
    
    Enforces:
    - Consent verification before PII processing
    - Data localization (Thailand data stays in Thailand unless consent)
    - Cross-border transfer controls
    - DPO notification on PII access
    - Right to erasure support
    - 72-hour breach notification tracking
    """
```

---

### Phase 3: Identity, Trust & Multi-Agent Mesh

---

#### [NEW] [src/agent_security/identity/agent\_id.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/identity/agent_id.py)

```python
class AgentIdentity:
    """Cryptographic agent identity with Ed25519 keypair."""
    
    @classmethod
    def create(
        cls, name: str, sponsor: str,
        capabilities: list[str],
        org: str = "default",
    ) -> "AgentIdentity":
        """Create new identity: did:agent:<org>:<name>"""
    
    @property
    def did(self) -> str: ...        # "did:agent:myorg:data-analyst"
    
    def sign(self, data: bytes) -> bytes: ...
    def verify(self, data: bytes, signature: bytes) -> bool: ...
    def to_spiffe(self) -> str: ...  # SPIFFE URI for service mesh
```

---

#### [NEW] [src/agent_security/identity/trust.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/identity/trust.py)

```python
class PrivilegeRing(IntEnum):
    RING_0_PRIVILEGED = 0   # ≥ 950: Human-verified orchestrators
    RING_1_TRUSTED = 1      # ≥ 800: Full tool suite
    RING_2_STANDARD = 2     # ≥ 600: Standard operations
    RING_3_SANDBOX = 3      # < 600: Restricted (new/spawned agents)

class TrustScorer:
    """Dynamic trust scoring (0-1000) with privilege ring mapping."""
    
    def __init__(self, store: ITrustStore | None = None): ...
    
    def get_score(self, agent_id: str) -> int: ...
    def get_ring(self, agent_id: str) -> PrivilegeRing: ...
    
    def record_violation(self, agent_id: str, severity: str) -> int: ...
    def record_success(self, agent_id: str) -> int: ...
    
    def apply_decay(self, agent_id: str, elapsed_hours: float) -> int:
        """Trust decays over time without positive signals."""
    
    def initialize_spawned(self, parent_id: str, child_id: str) -> int:
        """Spawned subagent gets min(parent_trust * 0.5, 400) — always Ring 3."""
```

---

#### [NEW] [src/agent_security/identity/delegation.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/identity/delegation.py)

**DelegationChain** — Verifiable delegation with scope constraints:

```python
class DelegationToken(BaseModel):
    delegator_did: str           # Parent agent
    delegatee_did: str           # Child agent / subagent
    scope: list[str]             # Allowed capabilities ["read:data", "query:db"]
    max_depth: int = 3           # Maximum re-delegation depth
    expires_at: datetime         # TTL
    signature: str               # Ed25519 signature by delegator

class DelegationChain:
    """Track and verify A → B → C delegation chains."""
    
    def delegate(
        self, parent: AgentIdentity, child_did: str,
        scope: list[str], ttl_minutes: int = 60,
    ) -> DelegationToken: ...
    
    def verify_chain(self, chain: list[DelegationToken]) -> bool: ...
    
    def effective_scope(self, chain: list[DelegationToken]) -> list[str]:
        """Scope narrows at each hop — child can never exceed parent."""
```

---

#### [NEW] [src/agent_security/mesh/registry.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/mesh/registry.py)

```python
class AgentRegistration(BaseModel):
    did: str
    name: str
    capabilities: list[str]
    framework: str               # "azure_openai", "bedrock", "gemini", etc.
    ring: PrivilegeRing
    trust_score: int
    parent_did: str | None       # For spawned subagents
    status: AgentStatus          # RUNNING, STOPPED, KILLED
    registered_at: datetime

class AgentRegistry:
    """Service-mesh-style agent discovery and lifecycle management."""
    
    def register(self, identity: AgentIdentity, **kwargs) -> AgentRegistration: ...
    def deregister(self, did: str) -> None: ...
    def discover(self, capability: str) -> list[AgentRegistration]: ...
    
    def spawn_subagent(
        self, parent: AgentIdentity, child_name: str,
        capabilities: list[str], ttl_minutes: int = 60,
    ) -> tuple[AgentIdentity, DelegationToken]:
        """Runtime subagent spawning with automatic:
        - Identity generation (child DID under parent namespace)
        - Delegation token with scoped capabilities
        - Ring 3 (sandbox) assignment
        - TTL expiration
        - Parent chain tracking
        """
    
    def list_subagents(self, parent_did: str) -> list[AgentRegistration]: ...
    def kill_tree(self, did: str) -> int:
        """Kill agent and ALL its subagents recursively."""
```

---

### Phase 4: Human-in-the-Loop (MS Teams + Outlook)

---

#### [NEW] [src/agent_security/stepup/handler.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/stepup/handler.py)

```python
class IStepUpHandler(Protocol):
    """Interface for human approval workflows."""
    async def request_approval(
        self, decision: PolicyDecision, context: dict,
    ) -> ApprovalResult: ...

class ApprovalResult(BaseModel):
    approved: bool
    approver: str              # email/UPN of approver
    approved_at: datetime | None
    comment: str = ""
    expires_at: datetime       # Approval TTL
```

---

#### [NEW] [src/agent_security/stepup/teams.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/stepup/teams.py)

**MS Teams Adaptive Card** approval workflow:

```python
class TeamsStepUpHandler(IStepUpHandler):
    """Send Adaptive Card to MS Teams for human approval.
    
    Flow:
    1. Policy returns STEP_UP → handler triggered
    2. Adaptive Card sent to Teams channel/chat with approvers
    3. Card shows: agent ID, tool name, arguments, policy rule
    4. Approver clicks Approve / Deny
    5. Webhook callback updates approval status
    6. Agent proceeds or raises GovernanceDenied
    
    Uses: Microsoft Graph API → Teams → Adaptive Cards
    """
    
    def __init__(
        self, tenant_id: str, client_id: str, client_secret: str,
        channel_id: str | None = None,
        timeout_minutes: int = 30,
    ): ...
    
    async def request_approval(
        self, decision: PolicyDecision, context: dict,
    ) -> ApprovalResult: ...
```

---

#### [NEW] [src/agent_security/stepup/outlook.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/stepup/outlook.py)

**Outlook Actionable Message** approval:

```python
class OutlookStepUpHandler(IStepUpHandler):
    """Send Actionable Message to Outlook for approval.
    
    Fallback when Teams is not available.
    Uses: Microsoft Graph API → Mail → Actionable Messages
    """
```

---

#### [NEW] [src/agent_security/stepup/composite.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/stepup/composite.py)

```python
class CompositeStepUpHandler(IStepUpHandler):
    """Try Teams first, fallback to Outlook."""
    def __init__(self, handlers: list[IStepUpHandler]): ...
```

---

### Phase 5: Runtime Sandbox (Azure Container Apps) & SRE

---

#### [NEW] [src/agent_security/runtime/sandbox.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/runtime/sandbox.py)

```python
class SandboxConfig(BaseModel):
    """Resource limits per privilege ring."""
    cpu_limit: float = 0.5       # vCPUs
    memory_limit_mb: int = 512
    timeout_seconds: int = 300
    network_enabled: bool = False  # Ring 3: no network
    allowed_paths: list[str] = []  # VFS whitelist

# Ring-based default configs
RING_CONFIGS = {
    PrivilegeRing.RING_0_PRIVILEGED: SandboxConfig(cpu=4.0, memory=8192, network=True),
    PrivilegeRing.RING_1_TRUSTED:    SandboxConfig(cpu=2.0, memory=4096, network=True),
    PrivilegeRing.RING_2_STANDARD:   SandboxConfig(cpu=1.0, memory=2048, network=True),
    PrivilegeRing.RING_3_SANDBOX:    SandboxConfig(cpu=0.5, memory=512, network=False),
}

class AzureContainerSandbox:
    """Execute agent tools in Azure Container Apps instances.
    
    - Spawns ephemeral container per execution (Ring 3)
    - Container image with minimal dependencies
    - VNet isolation for network control
    - Auto-cleanup after execution
    """
    
    def __init__(
        self, subscription_id: str, resource_group: str,
        container_app_env: str,
    ): ...
    
    async def execute(
        self, func: Callable, args: dict,
        config: SandboxConfig,
    ) -> Any: ...
```

---

#### [NEW] [src/agent_security/runtime/signals.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/runtime/signals.py)

POSIX-inspired agent lifecycle signals

---

#### [NEW] [src/agent_security/sre/kill\_switch.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/sre/kill_switch.py)

```python
class KillSwitch:
    """Emergency agent termination.
    
    - global_kill()  → stop ALL agents in the mesh
    - kill(did)      → stop specific agent + all subagents
    - auto_kill()    → triggered by RogueDetector
    - Sends SIGKILL signal via mesh registry
    - Logs kill event to audit (Cosmos DB)
    - Cooldown period before restart allowed
    """
```

---

#### SRE additional files:

| File | Component |
|------|-----------|
| [rate_limiter.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/sre/rate_limiter.py) | Token bucket per agent + per tool + budget tracking |
| [circuit_breaker.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/sre/circuit_breaker.py) | CLOSED → OPEN → HALF_OPEN for external services |
| [rogue_detector.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/sre/rogue_detector.py) | Frequency spikes, entropy monitoring, auto-kill |

---

### Phase 6: AI Framework Adapters & C#/.NET SDK

---

#### Python Framework Adapters

| File | Framework | Integration Method |
|------|-----------|-------------------|
| [azure\_openai.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/azure_openai.py) | Azure OpenAI | Function calling wrapper with governance |
| [azure\_foundry.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/azure_foundry.py) | Azure AI Foundry | Agent service middleware |
| [aws\_bedrock.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/aws_bedrock.py) | AWS Bedrock | Converse API tool use governance |
| [aws\_agentcore.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/aws_agentcore.py) | AWS AgentCore | Agent runtime governance hook |
| [gemini.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/gemini.py) | Gemini / Gemini Enterprise | Function calling governance |
| [antigravity.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/antigravity.py) | Google Antigravity | ADK agent governance middleware |
| [claude.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/claude.py) | Claude Code / Claude Cowork | Tool use governance |
| [m365\_copilot.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/m365_copilot.py) | Microsoft 365 Copilot | Plugin governance + Graph API |
| [chatgpt.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/chatgpt.py) | ChatGPT Business Plan | Actions / GPT function governance |
| [openclaw.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/openclaw.py) | Openclaw | Sidecar governance |
| [mcp.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/integrations/mcp.py) | MCP Servers | Security gateway — tool scanning, content hashing |

**Adapter Pattern** — ทุก adapter implement `IFrameworkAdapter`:

```python
class IFrameworkAdapter(Protocol):
    """Common interface for all AI framework integrations."""
    
    @property
    def framework_name(self) -> str: ...
    
    def wrap_tool(self, tool: Any, policy: PolicyDocument) -> Any:
        """Wrap framework-specific tool with governance."""
    
    def wrap_agent(self, agent: Any, policy: PolicyDocument) -> Any:
        """Wrap entire agent with governance middleware."""
    
    def get_tool_context(self, tool_call: Any) -> dict:
        """Extract governance context from framework-specific tool call."""
```

---

#### C#/.NET SDK

> [!IMPORTANT]
> .NET SDK จะ **share policy schema เดียวกัน** (`governance.toolkit/v1` YAML) กับ Python SDK และใช้ wire protocol เดียวกันสำหรับ cross-language mesh communication

#### [NEW] [dotnet/AgentSecurity/](file:///Users/saran/antigravity/agent-security-framework/dotnet/AgentSecurity/)

```
dotnet/AgentSecurity/
├── AgentSecurity.sln
├── src/
│   └── AgentSecurity/
│       ├── AgentSecurity.csproj
│       ├── Policy/
│       │   ├── PolicyEvaluator.cs         # Core engine (mirrors Python)
│       │   ├── PolicyModels.cs            # Shared schema models
│       │   ├── PolicyLoader.cs            # YAML loader (YamlDotNet)
│       │   └── IPolicyBackend.cs          # Pluggable interface
│       ├── Governance/
│       │   ├── GovernanceKernel.cs         # Main kernel class
│       │   ├── GovernanceMiddleware.cs     # ASP.NET middleware
│       │   ├── GovernAttribute.cs          # [Govern] attribute for tools
│       │   └── Exceptions.cs              # GovernanceDeniedException
│       ├── Audit/
│       │   ├── AuditLogger.cs             # Merkle-chain logger
│       │   ├── AuditEntry.cs              # Entry model
│       │   ├── CosmosEventSink.cs         # Azure Cosmos DB sink
│       │   └── IEventSink.cs              # Interface
│       ├── Identity/
│       │   ├── AgentIdentity.cs           # Ed25519/DID identity
│       │   ├── TrustScorer.cs             # Trust scoring
│       │   └── DelegationChain.cs         # Delegation tokens
│       ├── StepUp/
│       │   ├── IStepUpHandler.cs
│       │   ├── TeamsStepUpHandler.cs      # MS Teams Adaptive Cards
│       │   └── OutlookStepUpHandler.cs    # Outlook Actionable Messages
│       ├── Integrations/
│       │   ├── AzureOpenAI/               # Azure.AI.OpenAI governance
│       │   ├── SemanticKernel/            # SK function filter
│       │   ├── M365Copilot/               # Copilot plugin governance
│       │   └── Mcp/                       # MCP .NET extension
│       └── Extensions/
│           └── ServiceCollectionExtensions.cs  # DI registration
├── tests/
│   └── AgentSecurity.Tests/
│       ├── PolicyEvaluatorTests.cs
│       ├── GovernanceKernelTests.cs
│       └── AuditLoggerTests.cs
└── examples/
    ├── BasicGovernance/
    ├── SemanticKernelIntegration/
    └── TeamsApproval/
```

**C# Usage Examples:**

```csharp
// 1. Basic governance
var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = ["policies/production.yaml"],
    CosmosConnection = "AccountEndpoint=...",
    TeamsChannelId = "19:xxx@thread.tacv2",
});

var result = kernel.EvaluateToolCall(
    agentDid: "did:agent:myorg:analyst",
    toolName: "query_database",
    args: new() { ["query"] = "SELECT * FROM users" }
);

// 2. ASP.NET middleware (for API-hosted agents)
builder.Services.AddAgentGovernance(options =>
{
    options.PolicyPaths.Add("policies/production.yaml");
    options.AuditSink = new CosmosEventSink(connectionString);
    options.StepUpHandler = new TeamsStepUpHandler(teamsConfig);
});

// 3. Semantic Kernel integration
var sk = Kernel.CreateBuilder()
    .AddAzureOpenAIChatCompletion(...)
    .Build();

sk.FunctionInvocationFilters.Add(
    new GovernanceFunctionFilter(kernel)
);

// 4. [Govern] attribute
[Govern(Policy = "production.yaml")]
public async Task<string> SendEmail(string to, string body) { ... }
```

---

### CLI Tool

#### [NEW] [src/agent_security/cli/main.py](file:///Users/saran/antigravity/agent-security-framework/src/agent_security/cli/main.py)

```bash
# Installation & health
agsec doctor                          # Check installation
agsec version                         # Show versions

# Policy management
agsec lint-policy ./policies/         # Validate YAML policies
agsec policy test ./policy.yaml       # Dry-run policy with test contexts

# Compliance verification
agsec verify                          # Full compliance check
agsec verify --standard soc2          # SOC 2 specific
agsec verify --standard pdpa          # PDPA Thailand specific
agsec verify --json                   # Machine-readable output
agsec verify --evidence ./output.json # Generate auditor evidence

# Agent management
agsec agent list                      # List all agents in mesh
agsec agent trust <did>               # Show trust score & ring
agsec agent kill <did>                # Kill agent + subagents
agsec agent kill --all                # Global kill switch

# Audit trail
agsec audit show                      # View recent audit entries
agsec audit verify                    # Verify Merkle chain integrity
agsec audit export --format csv       # Export for compliance review
agsec audit query --agent <did>       # Query by agent
agsec audit query --tag pdpa          # Query by compliance tag
```

---

### Example Policy Templates

#### [NEW] [examples/policies/production.yaml](file:///Users/saran/antigravity/agent-security-framework/examples/policies/production.yaml)

```yaml
apiVersion: governance.toolkit/v1
name: production-enterprise
version: "1.0"
metadata:
  compliance: ["soc2", "iso42001", "hipaa", "pdpa"]
  environment: production

defaults:
  action: deny   # Fail-closed

rules:
  # === DESTRUCTIVE OPERATIONS ===
  - name: block-destructive-ops
    conditions:
      - field: tool_name
        operator: in
        value: ["delete_file", "drop_table", "truncate", "shell_exec", "rm"]
    action: deny
    priority: 1000
    description: "Destructive operations are structurally impossible"
    tags: ["soc2-cc6.1"]

  # === PII / PDPA PROTECTION ===
  - name: pdpa-pii-detection
    conditions:
      - field: input_text
        operator: matches
        value: "\\b\\d{1}-\\d{4}-\\d{5}-\\d{2}-\\d{1}\\b"   # Thai ID
    action: deny
    priority: 900
    description: "Thai National ID detected — PDPA violation"
    tags: ["pdpa", "hipaa"]

  - name: pdpa-cross-border
    conditions:
      - field: tool_name
        operator: equals
        value: "transfer_data"
      - field: destination.country
        operator: not_equals
        value: "TH"
    action: step_up
    priority: 850
    approvers: ["dpo@company.com", "security-team"]
    description: "Cross-border data transfer requires DPO approval (PDPA)"
    tags: ["pdpa"]

  # === HUMAN APPROVAL ===
  - name: require-approval-financial
    conditions:
      - field: tool_name
        operator: in
        value: ["send_payment", "approve_invoice", "wire_transfer"]
    action: step_up
    priority: 800
    approvers: ["finance-team", "cfo@company.com"]
    description: "Financial operations require human approval"
    tags: ["soc2-cc6.3"]

  - name: require-approval-email
    conditions:
      - field: tool_name
        operator: equals
        value: "send_email"
    action: step_up
    priority: 700
    approvers: ["manager"]
    tags: ["soc2-cc6.1"]

  # === RING-BASED ACCESS ===
  - name: ring3-read-only
    conditions:
      - field: agent.ring
        operator: equals
        value: 3
      - field: action.type
        operator: not_in
        value: ["read", "query", "search"]
    action: deny
    priority: 600
    description: "Ring 3 (sandbox) agents are read-only"

  # === SAFE OPERATIONS ===
  - name: allow-read-operations
    conditions:
      - field: action.type
        operator: in
        value: ["read", "query", "search", "list", "get"]
    action: allow
    priority: 100
    description: "Read operations are allowed"
```

---

## Complete Directory Structure

```
agent-security-framework/
├── pyproject.toml                          # Python package config
├── README.md
│
├── src/                                    # ── PYTHON SDK ──
│   └── agent_security/
│       ├── __init__.py
│       │
│       ├── policy/                         # Phase 1
│       │   ├── __init__.py
│       │   ├── engine.py                   # PolicyEvaluator
│       │   ├── models.py                   # Shared schema models
│       │   ├── loader.py                   # YAML loading + validation
│       │   └── backends.py                 # IPolicyBackend (OPA/Rego ready)
│       │
│       ├── governance/                     # Phase 1
│       │   ├── __init__.py
│       │   ├── gate.py                     # govern() wrapper
│       │   └── exceptions.py              # GovernanceDenied, StepUp, Defer
│       │
│       ├── audit/                          # Phase 2
│       │   ├── __init__.py
│       │   ├── logger.py                   # AuditLogger (Merkle-chain)
│       │   ├── models.py                   # AuditEntry
│       │   ├── sink.py                     # EventSink interface
│       │   └── cosmos_sink.py              # Azure Cosmos DB sink
│       │
│       ├── compliance/                     # Phase 2
│       │   ├── __init__.py
│       │   ├── checker.py                  # ComplianceChecker
│       │   ├── soc2.py                     # SOC 2 mapping
│       │   ├── iso42001.py                 # ISO 42001 mapping
│       │   ├── hipaa.py                    # HIPAA mapping
│       │   ├── pdpa.py                     # PDPA Thailand 🇹🇭
│       │   └── evidence.py                 # Evidence generation
│       │
│       ├── identity/                       # Phase 3
│       │   ├── __init__.py
│       │   ├── agent_id.py                 # AgentIdentity (Ed25519/DID)
│       │   ├── trust.py                    # TrustScorer (0-1000)
│       │   └── delegation.py              # DelegationChain
│       │
│       ├── mesh/                           # Phase 3
│       │   ├── __init__.py
│       │   └── registry.py                 # AgentRegistry + subagent spawning
│       │
│       ├── stepup/                         # Phase 4
│       │   ├── __init__.py
│       │   ├── handler.py                  # IStepUpHandler interface
│       │   ├── teams.py                    # MS Teams Adaptive Cards
│       │   ├── outlook.py                  # Outlook Actionable Messages
│       │   └── composite.py               # Teams → Outlook fallback
│       │
│       ├── runtime/                        # Phase 5
│       │   ├── __init__.py
│       │   ├── sandbox.py                  # Azure Container Apps sandbox
│       │   └── signals.py                  # POSIX-like agent signals
│       │
│       ├── sre/                            # Phase 5
│       │   ├── __init__.py
│       │   ├── kill_switch.py              # KillSwitch
│       │   ├── rate_limiter.py             # TokenBucket + budgets
│       │   ├── circuit_breaker.py          # CircuitBreaker
│       │   └── rogue_detector.py           # Anomaly detection
│       │
│       ├── integrations/                   # Phase 6
│       │   ├── __init__.py
│       │   ├── base.py                     # IFrameworkAdapter
│       │   ├── azure_openai.py             # Azure OpenAI
│       │   ├── azure_foundry.py            # Azure AI Foundry
│       │   ├── aws_bedrock.py              # AWS Bedrock
│       │   ├── aws_agentcore.py            # AWS AgentCore
│       │   ├── gemini.py                   # Gemini / Enterprise
│       │   ├── antigravity.py              # Google Antigravity
│       │   ├── claude.py                   # Claude Code / Cowork
│       │   ├── m365_copilot.py             # Microsoft 365 Copilot
│       │   ├── chatgpt.py                  # ChatGPT Business
│       │   ├── openclaw.py                 # Openclaw
│       │   └── mcp.py                      # MCP Security Gateway
│       │
│       └── cli/                            # Phase 6
│           ├── __init__.py
│           └── main.py                     # CLI commands
│
├── dotnet/                                 # ── C# / .NET SDK ──
│   └── AgentSecurity/
│       ├── AgentSecurity.sln
│       ├── src/AgentSecurity/
│       │   ├── AgentSecurity.csproj
│       │   ├── Policy/                     # PolicyEvaluator.cs etc.
│       │   ├── Governance/                 # GovernanceKernel.cs etc.
│       │   ├── Audit/                      # CosmosEventSink.cs etc.
│       │   ├── Identity/                   # AgentIdentity.cs etc.
│       │   ├── StepUp/                     # TeamsStepUpHandler.cs etc.
│       │   ├── Integrations/               # Azure OpenAI, SK, Copilot
│       │   └── Extensions/                 # DI extensions
│       ├── tests/AgentSecurity.Tests/
│       └── examples/
│
├── examples/                               # ── Examples ──
│   ├── python/
│   │   ├── 01_basic_governance.py
│   │   ├── 02_policy_evaluator.py
│   │   ├── 03_audit_cosmos.py
│   │   ├── 04_teams_approval.py
│   │   ├── 05_multi_agent_mesh.py
│   │   ├── 06_subagent_spawning.py
│   │   ├── 07_azure_openai_integration.py
│   │   └── 08_bedrock_integration.py
│   └── policies/
│       ├── default.yaml
│       ├── production.yaml
│       ├── development.yaml
│       ├── financial-soc2.yaml
│       ├── healthcare-hipaa.yaml
│       └── thailand-pdpa.yaml
│
├── tests/                                  # ── Tests ──
│   ├── test_policy_engine.py
│   ├── test_governance_gate.py
│   ├── test_audit_logger.py
│   ├── test_cosmos_sink.py
│   ├── test_identity.py
│   ├── test_trust_scorer.py
│   ├── test_delegation.py
│   ├── test_mesh_registry.py
│   ├── test_subagent_spawning.py
│   ├── test_kill_switch.py
│   ├── test_rate_limiter.py
│   ├── test_circuit_breaker.py
│   ├── test_pdpa_compliance.py
│   ├── test_conformance/                   # OWASP conformance
│   └── test_integrations/                  # Framework adapters
│
└── docs/
    ├── architecture.md
    ├── policy-guide.md
    ├── identity-guide.md
    ├── compliance-guide.md                 # SOC2/ISO42001/HIPAA/PDPA
    ├── teams-approval-guide.md
    └── deployment-guide.md                 # Azure Container Apps
```

---

## Verification Plan

### Automated Tests

```bash
# Python — Full test suite
pytest tests/ -v --cov=agent_security --cov-report=html

# Python — Performance benchmark (target: 10,000 evals/sec)
pytest tests/test_policy_engine.py -v -k "benchmark"

# .NET — Full test suite
dotnet test dotnet/AgentSecurity/tests/

# Compliance-specific tests
pytest tests/test_pdpa_compliance.py -v
pytest tests/test_conformance/ -v
```

### Key Test Matrix

| Test | Input | Expected |
|------|-------|----------|
| Policy DENY | `tool_name: "delete_file"` | `PolicyAction.DENY` |
| Policy ALLOW | `tool_name: "web_search"` | `PolicyAction.ALLOW` |
| PDPA Thai ID block | `input_text: "1-1234-12345-12-1"` | `PolicyAction.DENY` |
| PDPA cross-border | `transfer_data` to `US` | `PolicyAction.STEP_UP` |
| Ring 3 write block | `ring: 3, action: "write"` | `PolicyAction.DENY` |
| Governance wrap | `govern(delete)("path")` | Raises `GovernanceDenied` |
| Cosmos audit chain | Write 1000 entries | `verify_integrity() == True` |
| Cosmos audit tamper | Modify 1 entry | `verify_integrity() == False` |
| Trust violation | 5 violations → check ring | Demoted to Ring 3 |
| Subagent spawn | Parent spawns child | Child trust = parent×0.5, Ring 3 |
| Kill switch tree | Kill parent → check children | All children terminated |
| Rate limiter | 100 req at 10/sec | First 10 pass, rest throttled |
| .NET parity | Same policy, same context | Same decision as Python |

### Manual Verification
- Run all 8 Python examples end-to-end
- Run all 3 .NET examples end-to-end
- Teams Adaptive Card approval flow (send → approve → resume)
- Cosmos DB audit query via Azure Portal
- Red-team: prompt injection bypass attempt → governance layer blocks

---

## Implementation Timeline

| Phase | Scope | Language | Priority |
|-------|-------|----------|----------|
| **Phase 1** | Policy Engine + Governance Gate | Python | 🔴 Must-have |
| **Phase 2** | Audit (Cosmos DB) + Compliance (SOC2/PDPA) | Python | 🔴 Must-have |
| **Phase 3** | Identity + Trust + Mesh + Subagent Spawning | Python | 🔴 Must-have |
| **Phase 4** | Human-in-the-Loop (Teams + Outlook) | Python | 🟡 Important |
| **Phase 5** | Runtime Sandbox (Azure Container) + SRE | Python | 🟡 Important |
| **Phase 6** | Framework Adapters (12) + C#/.NET SDK + CLI | Both | 🟢 Incremental |

> [!TIP]
> **แนะนำให้ approve ทั้ง 6 phases** แต่จะ implement เป็น incremental — Phase 1-3 จะได้ functional framework ที่:
> - ✅ Policy enforcement ครบ 5 decisions
> - ✅ Cosmos DB audit trail (Merkle-chain, tamper-evident)
> - ✅ PDPA + SOC 2 + HIPAA + ISO 42001 compliance tags
> - ✅ Multi-agent mesh + runtime subagent spawning
> - ✅ Zero-trust identity + trust scoring + delegation chains
>
> Phase 4-6 เพิ่ม Teams approval, Azure sandbox, และ adapter สำหรับ 12 frameworks

> [!WARNING]
> **C#/.NET SDK** จะพัฒนาหลัง Python SDK เสร็จ Phase 1-3 โดยจะ **mirror API** เดียวกัน ใช้ **shared YAML policy schema** เดียวกัน เพื่อให้ Python agents และ .NET agents ทำงานร่วมกันใน mesh เดียวกันได้
