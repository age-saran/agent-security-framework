# Agent Security Framework

Enterprise **agent governance** framework ตาม Microsoft Agent Governance Toolkit (AGT)
สำหรับองค์กรที่ใช้ multi-cloud, multi-framework AI agent ecosystem

[![status](https://img.shields.io/badge/status-phase%200%20scaffold-blue)]()
[![python](https://img.shields.io/badge/python-3.10%2B-blue)]()

---

## ทำอะไรได้บ้าง

Policy enforcement, cryptographic identity, tamper-evident audit, และ SRE controls
สำหรับ AI agents — ใช้ร่วม **policy schema เดียวกัน** (`governance.toolkit/v1`) ได้ทั้ง
Python และ C#/.NET SDK

5 policy decisions: `ALLOW` · `DENY` · `MODIFY` · `STEP_UP` · `DEFER`

| Capability | Backend |
|------------|---------|
| Policy engine | YAML-first (OPA/Rego pluggable) |
| Audit trail | Azure Cosmos DB (Merkle-chain) |
| Human-in-the-loop | MS Teams + Outlook |
| Runtime sandbox | Azure Container Apps |
| Compliance | SOC 2 · ISO 42001 · HIPAA · PDPA (Thailand) |

---

## Quick start

```bash
# ติดตั้งแบบ editable พร้อม dev tools
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# ตรวจสอบการติดตั้ง
agsec doctor
agsec version
```

---

## Project layout

```
src/agent_security/   # Python SDK
dotnet/AgentSecurity/ # C#/.NET SDK (Phase 6)
examples/             # ตัวอย่าง + policy templates
tests/                # test suite
docs/                 # สถาปัตยกรรม + คู่มือ
```

## Roadmap

ดูแผนเต็มที่ [`implementation_plan.md`](./implementation_plan.md)
และความคืบหน้าทีละ step ที่ [`CHECKLIST.md`](./CHECKLIST.md)

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Project scaffolding | ✅ |
| 1 | Policy Engine + Governance Gate | ⬜ |
| 2 | Audit (Cosmos DB) + Compliance | ⬜ |
| 3 | Identity + Trust + Mesh | ⬜ |
| 4 | Human-in-the-Loop (Teams/Outlook) | ⬜ |
| 5 | Runtime Sandbox + SRE | ⬜ |
| 6 | Framework Adapters + .NET SDK + CLI | ⬜ |

## License

Apache-2.0
