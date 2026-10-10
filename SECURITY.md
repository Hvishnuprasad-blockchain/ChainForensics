# SECURITY.md — ChainForensics Threat Model

## 1. What This System Is

ChainForensics is a real-time AI/blockchain forensic-evidence logging and recovery system. When a network-traffic anomaly is detected, the system: (1) classifies it, (2) hashes the complete forensic event, (3) writes the hash synchronously to a smart contract ledger, (4) generates a human-readable explanation and recovery recommendation, (5) simulates and verifies recovery, and (6) marks verified recoveries permanently on-chain.

---

## 2. What This System Protects Against

### 2.1 Post-Incident Tampering with Forensic Evidence

**Threat:** An adversary with write access to the off-chain database or file store retroactively modifies a stored forensic event (e.g., changes the attack classification, source IP, or confidence score) after an incident to cover their tracks or undermine a legal case.

**Countermeasure (Pillar 1 — On-Chain Evidence Logging):**

- At the moment of detection, `hash_forensic_event()` (`chainforensics/event_builder.py`) computes a deterministic SHA-256 hash of the canonical JSON representation of the event.
- `BlockchainClient.log_event()` (`chainforensics/blockchain/client.py`) immediately writes this hash to the `ForensicLedger` smart contract on-chain, synchronously waiting for the transaction receipt before returning.
- The `ForensicLedger.sol` contract enforces `hashExists[eventHash]` — the hash cannot be re-written or overwritten.
- Any subsequent modification to the off-chain record produces a different SHA-256 hash, which will not match the immutable on-chain record. Tampering is therefore **detectable** by comparing the current event hash against the chain.

**Scope of protection:**  Post-write tampering with event content, not the initial write.

---

### 2.2 Duplicate/Replay Event Injection

**Threat:** An adversary replays the same forensic event to the ledger to inflate incident counts or create artificial audit noise.

**Countermeasure:** `ForensicLedger.sol` uses `mapping(bytes32 => bool) public hashExists` and reverts with `DuplicateHash` on any attempt to log the same hash twice. The Python client propagates this revert as an exception (tested in `tests/test_blockchain_duplicate.py`).

---

### 2.3 False Recovery Confirmation

**Threat:** An adversary falsely marks an unresolved incident as "recovery verified" to prematurely close an active investigation.

**Countermeasure (Pillar 3 — Verified Closed-Loop Recovery):**

- `markRecoveryVerified()` in `ForensicLedger.sol` is `onlyOwner` — only the deploying account can call it.
- The Python `verify_recovery()` function (`chainforensics/recovery/verifier.py`) only calls `mark_recovery_verified()` after the simulation result status is `"verified"` and the event hash is found on-chain. Escalated events produce **no blockchain write**.

---

### 2.4 API Authentication Bypass

**Threat:** Unauthorized access to the incident API to read forensic data.

**Countermeasure:** All `/incidents` endpoints require the `x-api-key` header validated via `secrets.compare_digest()` (constant-time comparison, preventing timing attacks) against the `CHAINFORENSIS_API_KEY` environment variable (`chainforensics/api/dependencies.py`). If the env var is not set, the API returns HTTP 500 rather than silently accepting any key.

---

### 2.5 Information Leakage via Error Responses

**Threat:** Stack traces or internal exception details exposed to API callers could reveal system internals.

**Countermeasure:** `chainforensics/api/errors.py` implements a generic exception handler that logs the full exception server-side but returns only `{"error": "Request could not be completed.", "correlation_id": "<uuid>"}` to the caller. The correlation ID allows log matching without exposing details.

---

### 2.6 Malicious CSV Injection

**Threat:** A crafted CSV dataset causes arbitrary code execution or data corruption during model training/ingestion.

**Countermeasure:** `chainforensics/ingestion.py` uses `pd.read_csv()` with no formula evaluation. Labels are validated against a whitelist (`CICIDS_LABEL_MAP`); unknown labels are rejected. No `eval()` or `exec()` is used anywhere in the ingestion path.

---

## 3. What This System Does NOT Protect Against

The following are **explicit out-of-scope threats**. This is not an oversight — they are stated here so that any operator deploying this system understands its limits.

### 3.1 Compromise of the Detection Model Itself

The RandomForest classifier is trained on CICIDS-2017 data and makes predictions based on 78 statistical network-flow features. It **does not protect against**:

- **Adversarial inputs:** A sophisticated attacker who knows the model's feature thresholds can craft network traffic that evades detection (adversarial ML). No adversarial training or input certification is implemented.
- **Model poisoning:** If the training dataset is compromised, the resulting model will silently mis-classify attacks. No dataset provenance verification is implemented.
- **Distribution shift:** The model was trained on 2017 dataset traffic patterns. Novel attack variants not represented in training may be misclassified.

### 3.2 Compromise of the Off-Chain Database

The SQLite database (`chainforensics.db`) stores the complete forensic events, explanations, and recovery data. **The database itself is not encrypted or tamper-evident.** An adversary with filesystem access can:

- Read all stored incident data
- Delete the database file
- Corrupt entries

The blockchain provides **detection** of tampering (the on-chain hash won't match a modified off-chain record) but does not prevent the off-chain data from being altered or destroyed. A real production deployment would require encrypted storage, access control, and backup policies for the off-chain database.

### 3.3 Sepolia Testnet — Real Public Chain, But Not Mainnet

**IMPORTANT — READ CAREFULLY:**

This deployment runs against the **Ethereum Sepolia public testnet** via a QuickNode RPC endpoint (`CHAINFORENSIS_RPC_URL` in `.env`). The contract is deployed at `0xB12BB431DbfB42A2FDfF608aec09e8e7413dEc3C`.

**What this provides:**
- Real decentralised consensus across Sepolia validators — no single operator can rewrite history.
- Public verifiability — any party can independently verify a logged event hash against the Sepolia blockchain.
- Genuine block immutability — the chain cannot be reset without global consensus.

**What this does NOT provide:**
- Legally admissible evidence without Ethereum mainnet deployment (Sepolia is a test network with no economic security guarantees).
- Privacy — all event hashes on Sepolia are public. The SHA-256 hash does not reveal event contents, but the existence and timing of writes is public.
- HSM key management — the private key (`CHAINFORENSIS_PRIVATE_KEY`) is stored in a plaintext `.env` file. Compromise of this key allows an adversary to call `markRecoveryVerified()` for any incident. **This key must be rotated before any production deployment and managed via a secrets manager (Vault, AWS Secrets Manager) or HSM.**

For a legally defensible production deployment, migration to Ethereum mainnet with multisig or HSM-backed key management would be required.

### 3.4 Network-Level Attacks on the RPC Endpoint

The QuickNode RPC URL is HTTPS-authenticated by URL token. However, the token is stored in plaintext in `.env`. Compromise of the `.env` file exposes the RPC endpoint to arbitrary transaction submission from the compromised wallet. The RPC provider's rate limiting provides some protection.

### 3.5 Denial-of-Service Against the API or Detection Pipeline

No rate limiting is implemented on the FastAPI application. A high-volume caller could exhaust resources. In production, rate limiting (e.g., via a reverse proxy) would be required.

---

## 4. Secret Management

| Secret | How Handled |
|---|---|
| `CHAINFORENSIS_PRIVATE_KEY` | Environment variable only; never in source code |
| `CHAINFORENSIS_API_KEY` | Environment variable only; validated with `secrets.compare_digest()` |
| `CHAINFORENSIS_RPC_URL` | Environment variable only (contains QuickNode auth token) |
| `SEPOLIA_RPC_URL` | Environment variable only |
| `.env` file | Listed in `.gitignore`; never committed |

**The `.env` file contains real Sepolia testnet keys.** The private key controls a Sepolia wallet with test ETH only — there are no mainnet funds at risk. However, **this key must be rotated and moved to a secrets manager before any production deployment.** The QuickNode RPC URL token must also be treated as a secret.

---

## 5. Security Baseline — What Was Deliberately Built In

- No secrets in source code (all via env vars)
- No raw stack traces to API callers
- Input validation on every external boundary (Pydantic schemas, feature contract, CSV ingestion whitelist)
- Constant-time API key comparison
- Synchronous blockchain writes (no fire-and-forget — write failure propagates)
- Explicit duplicate-hash rejection on-chain
- Owner-only recovery verification on-chain
