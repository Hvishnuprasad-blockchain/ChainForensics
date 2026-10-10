# ARCHITECTURE.md — ChainForensics Full Component & Data-Flow Documentation

## Overview

ChainForensics is a real-time AI/blockchain forensic recovery system built around **four structural novelty pillars**. Each pillar is traced below to the specific code that implements it — not just described in prose.

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                     EXTERNAL TRAFFIC / DATA                      │
│          (CICIDS-2017 CSV files, or live forensic events)        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  SPRINT 1 — Detection Engine                                     │
│  chainforensics/ingestion.py    — CSV ingestion + label norm     │
│  chainforensics/features.py     — Feature contract (78 cols)     │
│  chainforensics/model.py        — RandomForest train/predict     │
│  chainforensics/exceptions.py   — Schema/inference errors        │
│  chainforensics/cli.py          — CLI retrain entry point        │
└──────────────────────────┬──────────────────────────────────────┘
                           │  Prediction{label, probabilities}
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  SPRINT 2 — Forensic Event + Blockchain Ledger  [PILLAR 1]      │
│  chainforensics/event_builder.py — build/canonicalize/hash      │
│  chainforensics/blockchain/abi.py — load compiled ABI           │
│  chainforensics/blockchain/client.py — BlockchainClient          │
│  contracts/ForensicLedger.sol — immutable on-chain ledger        │
└──────────────────────────┬──────────────────────────────────────┘
                           │  tx_hash, block_number, event_hash
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  SPRINT 3 — Explainability + Recovery Recommendations [PILLAR 2]│
│  chainforensics/explainability/knowledge_base.py — attack KB    │
│  chainforensics/explainability/generator.py — generate_explanation│
└──────────────────────────┬──────────────────────────────────────┘
                           │  explanation{status, severity, text, actions}
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  SPRINT 4 — Recovery Simulator + Verifier  [PILLAR 3]           │
│  chainforensics/recovery/simulator.py — simulate_recovery        │
│  chainforensics/recovery/verifier.py — verify_recovery           │
│     └─ on success: client.mark_recovery_verified(index)          │
└──────────────────────────┬──────────────────────────────────────┘
                           │  verification{status, blockchain_write}
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  SPRINT 5 — API + Database + BASE Metrics  [PILLAR 4]           │
│  chainforensics/database/models.py — Incident ORM               │
│  chainforensics/database/repository.py — CRUD operations        │
│  chainforensics/api/main.py — FastAPI application               │
│  chainforensics/api/incidents.py — /incidents routes            │
│  chainforensics/api/schemas.py — Pydantic schemas               │
│  chainforensics/api/dependencies.py — auth + DB session         │
│  chainforensics/api/errors.py — safe error responses            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Four Novelty Pillars — Code Traceability

### Pillar 1: Synchronous On-Chain Evidence Logging

**Claim:** Every forensic detection event is hashed and written to an immutable blockchain ledger synchronously before the pipeline proceeds.

**Code that structurally guarantees this:**

| Step | File | Function | What it does |
|---|---|---|---|
| Canonicalize | `chainforensics/event_builder.py` | `canonicalize_event()` L45–58 | Produces deterministic JSON bytes (sorted keys, no spaces) |
| Hash | `chainforensics/event_builder.py` | `hash_forensic_event()` L61–71 | SHA-256 of canonical bytes → 64-char hex |
| Validate hash | `chainforensics/blockchain/client.py` | `log_event()` L432–464 | Rejects non-hex, wrong-length, or empty hashes |
| Send on-chain | `chainforensics/blockchain/client.py` | `_send_contract_transaction()` L200–346 | Builds, signs, sends TX, **waits for receipt** before returning |
| Contract enforce | `contracts/ForensicLedger.sol` | `logEvent()` L134–173 | Rejects empty hash; rejects duplicate hash; emits `EventLogged` |
| Retry on failure | `chainforensics/blockchain/client.py` | `_with_retry()` L126–194 | Exponential backoff, propagates final failure |

**The synchronous receipt wait** (`web3.eth.wait_for_transaction_receipt`) on line 296–300 of `client.py` is the structural guarantee — the call does not return until the transaction is mined. The pipeline cannot proceed past blockchain logging without a confirmed on-chain write.

---

### Pillar 2: Explainable Forensic Timeline

**Claim:** Every detected event generates a human-readable explanation and ordered recovery recommendations, traceable to a documented knowledge base.

**Code that structurally guarantees this:**

| Step | File | Function | What it does |
|---|---|---|---|
| Knowledge base | `chainforensics/explainability/knowledge_base.py` | `ATTACK_KNOWLEDGE_BASE` | Dict of `AttackKnowledge(explanation_template, severity, recovery_actions)` for each attack type |
| Lookup | `chainforensics/explainability/knowledge_base.py` | `get_attack_knowledge()` L151–159 | Returns `None` for unknown types — no silent fallback |
| Generate | `chainforensics/explainability/generator.py` | `generate_explanation()` L45–118 | Fills templates with real event values; returns `manual_review_required` for unknown types |
| Open/closed | `knowledge_base.py` L130–147 | `SQLInjection` entry | Adding a new attack type requires ONLY a new KB entry — `generator.py` has no `if/elif` per attack |

**The structural guarantee:** `generate_explanation()` never raises an exception regardless of input. Unknown attack types return `{"status": "manual_review_required"}` — the system degrades gracefully rather than crashing.

---

### Pillar 3: Verified Closed-Loop Recovery Confirmation On-Chain

**Claim:** Recovery outcomes are verified by comparing simulation results against deterministic thresholds, and only confirmed recoveries produce a second on-chain write.

**Code that structurally guarantees this:**

| Step | File | Function | What it does |
|---|---|---|---|
| Simulate | `chainforensics/recovery/simulator.py` | `simulate_recovery()` L55–295 | Deterministic threshold rules per attack type (no randomness) |
| Scan chain | `chainforensics/recovery/verifier.py` | `find_event_index()` L43–73 | Scans actual blockchain entries by hash — never assumes index == incident ID |
| Conditional write | `chainforensics/recovery/verifier.py` | `verify_recovery()` L76–193 | **Only** calls `mark_recovery_verified()` when `simulation_result.status == "verified"` |
| On-chain mark | `chainforensics/blockchain/client.py` | `mark_recovery_verified()` L488–559 | Calls `ForensicLedger.markRecoveryVerified(index)` |
| Contract enforce | `contracts/ForensicLedger.sol` | `markRecoveryVerified()` L187–202 | `onlyOwner` modifier — arbitrary accounts cannot falsely verify |

**The structural guarantee:** `verify_recovery()` line 125 (`if status != "verified": return escalated`) means escalated recoveries produce **zero blockchain writes**. The code path to `mark_recovery_verified()` is only reachable after simulation success AND hash confirmation on-chain.

---

### Pillar 4: Empirical BASE Framework Evaluation

**Claim:** All system performance metrics — latency, completeness, recovery rate — are computed from real persisted incident data, not synthetic benchmarks.

**Code that structurally guarantees this:**

| Step | File | What it tracks |
|---|---|---|
| Blockchain latency | `chainforensics/database/models.py` L107–110 | `ledger_write_latency_seconds` — real measured from `time.perf_counter()` in `client.py` L213, L302–305 |
| Forensic completeness | `chainforensics/database/repository.py` `list_incidents()` | Events with `event_transaction_hash IS NOT NULL` = written to chain |
| Recovery verification rate | `chainforensics/database/models.py` L137–140 | `recovery_verified` boolean — only True after on-chain confirmation |
| API exposure | `chainforensics/api/schemas.py` L122–139 | `BaseMetricsResponse` schema exposes all BASE metrics |

**Metrics definition:**
- **Forensic Completeness** = `count(event_transaction_hash IS NOT NULL) / count(*)` — fraction of detections actually written on-chain
- **Recovery Verification Rate** = `count(recovery_verified=True) / count(*)` — fraction of incidents with confirmed closed-loop recovery
- **Ledger Write Latency** = measured from `time.perf_counter()` start to receipt confirmation, stored per-incident

---

## Data Flow — Single Incident Lifecycle

```
1. Traffic data (CSV row or API payload)
         │
         ▼
2. build_forensic_event() ──────────────────► event dict (flow_id, timestamp,
         │                                    src/dst, attack_type, confidence,
         │                                    raw_features)
         ▼
3. hash_forensic_event() ──────────────────► SHA-256 hex string (64 chars)
         │
         ▼
4. BlockchainClient.log_event() ───────────► On-chain: ForensicLedger.logEvent()
         │                                    ← tx_hash, block_number, gas_used
         ▼
5. generate_explanation() ─────────────────► explanation{severity, text, actions}
         │
         ▼
6. simulate_recovery() ────────────────────► sim_result{status, reason}
         │
         ▼
7. verify_recovery() ──────────────────────► If verified:
         │                                      find_event_index() scan chain
         │                                      mark_recovery_verified() on-chain
         │                                    If escalated:
         │                                      no blockchain write
         ▼
8. database/repository.py ─────────────────► Incident row: all fields persisted
         │                                    (event, blockchain result, recovery)
         ▼
9. GET /incidents/{hash} ──────────────────► Complete incident replay via API
```

---

## Key Design Decisions

| Decision | Location | Rationale |
|---|---|---|
| Synchronous blockchain write | `client.py _send_contract_transaction()` | Evidence integrity — no fire-and-forget |
| Duplicate hash rejection on-chain | `ForensicLedger.sol hashExists mapping` | Prevents replay attacks |
| Rule-based explainability | `knowledge_base.py` + `generator.py` | Deterministic, auditable, no LLM dependency |
| `onlyOwner` on recovery verification | `ForensicLedger.sol markRecoveryVerified()` | Prevents false verification by arbitrary callers |
| Hash scan not index assumption | `verifier.py find_event_index()` | Defensive: local DB ID ≠ blockchain index |
| `secrets.compare_digest()` for API key | `dependencies.py require_api_key()` | Constant-time comparison prevents timing attacks |
| Generic error responses | `errors.py generic_exception_handler()` | No stack traces to external callers |

---

## Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Detection | scikit-learn RandomForest | 1.9.1 |
| Feature engineering | pandas, numpy | 3.0.6, 2.5.3 |
| Blockchain client | web3.py | 8.0.0 |
| Smart contract | Solidity 0.8.19, Hardhat 3 | — |
| API | FastAPI + uvicorn | 0.141.1 / 0.54.0 |
| Database | SQLAlchemy + SQLite | 2.1.1 |
| Validation | Pydantic v2 | 2.13.5 |
| Python | CPython | 3.14.2 |
