# Agent Security Framework — Action Plan Checklist

> Companion ของ `implementation_plan.md` v2 — ใช้ track ความคืบหน้าทีละ step
> วิธีใช้: เปลี่ยน `[ ]` เป็น `[x]` เมื่อทำเสร็จ แล้วอัปเดต **Progress Dashboard** + **Version Tracking** ด้านล่าง

---

## Progress Dashboard

| Phase | Scope | Priority | Status | Progress |
|-------|-------|----------|--------|----------|
| Phase 0 | Project scaffolding | 🔴 Must | ✅ Done | 100% |
| Phase 1 | Policy Engine + Governance Gate | 🔴 Must | ✅ Done | 100% |
| Phase 2 | Audit (Cosmos DB) + Compliance | 🔴 Must | ✅ Done | 100% |
| Phase 3 | Identity + Trust + Mesh + Subagent | 🔴 Must | ⬜ Not started | 0% |
| Phase 4 | Human-in-the-Loop (Teams + Outlook) | 🟡 Important | ⬜ Not started | 0% |
| Phase 5 | Runtime Sandbox + SRE | 🟡 Important | ⬜ Not started | 0% |
| Phase 6 | Framework Adapters + .NET SDK + CLI | 🟢 Incremental | ⬜ Not started | 0% |

**Status legend:** ⬜ Not started · 🟦 In progress · ✅ Done · ⛔ Blocked

---

## Phase 0 — Project Scaffolding

- [x] สร้าง repo structure + `pyproject.toml`
- [x] ตั้งค่า virtualenv (Python 3.10+) และติดตั้ง dev deps (pytest, ruff, mypy)
- [x] สร้าง `README.md` โครงร่าง
- [x] ตั้งค่า pre-commit (lint + format)
- [x] วาง `src/agent_security/__init__.py` (lazy export ผ่าน PEP 562)
- [x] **Verify:** `pip install -e .` ผ่าน, `agsec version/doctor` resolve ได้

---

## Phase 1 — Policy Engine & Governance Gate (Python)

### 1.1 Policy models
- [x] `policy/models.py` — `PolicyAction`, `PolicyOperator`, `PolicyCondition`, `PolicyRule`, `PolicyDefaults`, `PolicyDocument`, `PolicyDecision`
- [x] ยืนยัน schema = `governance.toolkit/v1` (ตรงกับ .NET ในอนาคต)

### 1.2 Policy engine
- [x] `policy/engine.py` — `PolicyEvaluator` (deterministic, fail-closed)
- [x] `evaluate()` — highest priority match wins, DENY on error
- [x] `evaluate_tool_call()` convenience (+ action-type inference)
- [x] `policy/backends.py` — `IPolicyBackend` Protocol (เผื่อ OPA/Rego)

### 1.3 Policy loader
- [x] `policy/loader.py` — `load_policy()`, `load_policies()`
- [x] schema validation (apiVersion + pydantic)
- [x] `PolicyWatcher` hot-reload (dev)

### 1.4 Governance gate
- [x] `governance/exceptions.py` — `GovernanceDenied`, `GovernanceStepUpRequired`, `GovernanceDeferred`
- [x] `governance/gate.py` — `govern()` wrapper (sync + async aware)
- [x] decide → audit hook → execute/raise; MODIFY param rewrite; STEP_UP handler

### 1.5 Example policy
- [x] `examples/policies/production.yaml` (5 decisions ครบ + PDPA rules)

### 1.6 Tests
- [x] `tests/test_policy_engine.py` (รวม benchmark > 10,000 evals/sec)
- [x] `tests/test_governance_gate.py`
- [x] **Verify:** 22 tests ผ่าน + ruff clean; DENY/ALLOW/STEP_UP/MODIFY/DEFER ครบ, `delete_file()` raises `GovernanceDenied`

---

## Phase 2 — Audit & Compliance (Azure Cosmos DB)

### 2.1 Audit core
- [x] `audit/models.py` — `AuditEntry` (Merkle fields + partition_key)
- [x] `audit/logger.py` — `AuditLogger` (`log_decision`, `log_spawn`, `verify_integrity`, query)
- [x] `audit/sink.py` — `GovernanceEventSink` Protocol + `FileEventSink` + `CompositeEventSink`
- [x] `audit/cosmos_sink.py` — `CosmosEventSink` (production backend)

### 2.2 Compliance
- [x] `compliance/checker.py` — `ComplianceChecker`
- [x] `compliance/soc2.py` (CC6.1–CC9.1)
- [x] `compliance/iso42001.py`
- [x] `compliance/hipaa.py`
- [x] `compliance/pdpa.py` 🇹🇭 (consent, data localization, cross-border, DPO notify, erasure, 72h breach)
- [x] `compliance/evidence.py` — auditor evidence JSON

### 2.3 Tests
- [x] `tests/test_audit_logger.py`, `test_cosmos_sink.py`, `test_pdpa_compliance.py`
- [x] **Verify:** write 1000 entries → `verify_integrity()==True`; tamper 1 → `False`

---

## Phase 3 — Identity, Trust & Multi-Agent Mesh

### 3.1 Identity
- [ ] `identity/agent_id.py` — `AgentIdentity` (Ed25519, DID, SPIFFE)
- [ ] `identity/trust.py` — `PrivilegeRing`, `TrustScorer` (0–1000, decay, spawned init)
- [ ] `identity/delegation.py` — `DelegationToken`, `DelegationChain` (scope narrows per hop)

### 3.2 Mesh
- [ ] `mesh/registry.py` — `AgentRegistration`, `AgentRegistry`
- [ ] `spawn_subagent()` (child DID, Ring 3, TTL, delegation), `list_subagents()`, `kill_tree()`

### 3.3 Tests
- [ ] `test_identity.py`, `test_trust_scorer.py`, `test_delegation.py`, `test_mesh_registry.py`, `test_subagent_spawning.py`
- [ ] **Verify:** 5 violations → demote Ring 3; subagent trust = parent×0.5 & Ring 3; kill parent → children terminated

---

## Phase 4 — Human-in-the-Loop (MS Teams + Outlook)

- [ ] `stepup/handler.py` — `IStepUpHandler`, `ApprovalResult`
- [ ] `stepup/teams.py` — `TeamsStepUpHandler` (Graph API + Adaptive Card)
- [ ] `stepup/outlook.py` — `OutlookStepUpHandler` (Actionable Message fallback)
- [ ] `stepup/composite.py` — `CompositeStepUpHandler` (Teams → Outlook)
- [ ] `examples/python/04_teams_approval.py`
- [ ] **Verify:** send → approve → resume flow ทำงาน end-to-end

---

## Phase 5 — Runtime Sandbox (Azure Container Apps) & SRE

- [ ] `runtime/sandbox.py` — `SandboxConfig`, `RING_CONFIGS`, `AzureContainerSandbox`
- [ ] `runtime/signals.py` — POSIX-like agent signals
- [ ] `sre/kill_switch.py` — `KillSwitch` (global/targeted/auto + cooldown)
- [ ] `sre/rate_limiter.py` — token bucket per agent/tool + budget
- [ ] `sre/circuit_breaker.py` — CLOSED→OPEN→HALF_OPEN
- [ ] `sre/rogue_detector.py` — frequency/entropy + auto-kill
- [ ] `tests/test_kill_switch.py`, `test_rate_limiter.py`, `test_circuit_breaker.py`
- [ ] **Verify:** 100 req @10/sec → first 10 pass; rogue spike → auto-kill triggers

---

## Phase 6 — Framework Adapters & C#/.NET SDK & CLI

### 6.1 Adapter base + Python adapters (12)
- [ ] `integrations/base.py` — `IFrameworkAdapter`
- [ ] azure_openai · azure_foundry · aws_bedrock · aws_agentcore
- [ ] gemini · antigravity · claude · m365_copilot
- [ ] chatgpt · openclaw · mcp (security gateway)

### 6.2 CLI
- [ ] `cli/main.py` — doctor/version, lint-policy, policy test
- [ ] verify (+ --standard soc2/pdpa, --json, --evidence)
- [ ] agent list/trust/kill (+ --all), audit show/verify/export/query

### 6.3 C#/.NET SDK (mirror Python, shared YAML schema)
- [ ] `dotnet/AgentSecurity/` solution + csproj
- [ ] Policy/ · Governance/ · Audit/ · Identity/ · StepUp/ · Integrations/ · Extensions/
- [ ] tests: PolicyEvaluator / GovernanceKernel / AuditLogger
- [ ] examples: BasicGovernance / SemanticKernelIntegration / TeamsApproval

### 6.4 Tests + docs
- [ ] `test_integrations/`, `test_conformance/` (OWASP)
- [ ] docs: architecture / policy-guide / identity-guide / compliance-guide / teams-approval-guide / deployment-guide
- [ ] **Verify (.NET parity):** same policy + context → same decision as Python

---

## Final Acceptance (Verification Plan)

- [ ] `pytest tests/ -v --cov=agent_security` ผ่านทั้งหมด
- [ ] performance benchmark ผ่าน target (10,000 evals/sec)
- [ ] `dotnet test` ผ่าน
- [ ] Manual: 8 Python examples + 3 .NET examples end-to-end
- [ ] Manual: Teams approval flow, Cosmos audit query via Portal
- [ ] Red-team: prompt injection bypass → ถูก block

---

## Version Tracking / Changelog

| Version | Date | Phase | Change summary | Status | By |
|---------|------|-------|----------------|--------|-----|
| v0.1.0 | 2026-06-30 | — | สร้าง checklist จาก implementation_plan v2 | Baseline | มิ้นท์ |
| v0.1.1 | 2026-06-30 | Phase 0 | scaffold: pyproject, src package, README, pre-commit, agsec stub; verify pip install -e . + agsec ผ่าน | ✅ Done | มิ้นท์ |
| v0.2.0 | 2026-06-30 | Phase 1 | policy models/engine/loader/backends + governance gate + production.yaml; 22 tests ผ่าน, ruff clean, benchmark > 10k evals/s | ✅ Done | มิ้นท์ |
| v0.3.0 | 2026-07-01 | Phase 2 | audit Merkle-chain (File/InMemory/Cosmos sinks) + compliance checker (SOC2/ISO42001/HIPAA/PDPA) + evidence; wired into govern(); 35 tests ผ่าน, ruff clean | ✅ Done | มิ้นท์ |
| | | | | | |

**กติกาการอัปเดต version:**
- Phase ใหม่เริ่ม → bump **minor** (v0.1 → v0.2)
- เสร็จ task ย่อยภายใน phase → bump **patch** (v0.1.0 → v0.1.1) + เพิ่มแถวใน changelog
- Release จริง (ครบ Phase 1–3 functional) → **v1.0.0**

### Decision Log (บันทึกการตัดสินใจสำคัญ)

| Date | Decision | Rationale | Trade-off |
|------|----------|-----------|-----------|
| 2026-06-30 | YAML-first policy, OPA/Rego pluggable ทีหลัง | เริ่มเร็ว, ลด dependency | ต้องออกแบบ `IPolicyBackend` ให้ดีตั้งแต่แรก |
| | | | |
