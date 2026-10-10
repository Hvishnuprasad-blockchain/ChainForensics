# ChainForensics — Known Limitations

> This document is written with the honesty you would want from a vendor selling you this system. Every item below is genuinely true of the current implementation.

---

## 1. Recovery Actions Are Simulated, Not Real

**What the system does:** The recovery simulator (`chainforensics/recovery/simulator.py`) applies deterministic threshold rules to forensic event features. If `packet_count ≤ 500` for a DoS event, the recovery is declared "verified."

**What this means in practice:** No actual network action is taken. No firewall rule is created. No IP is blocked. No account is locked. The "verification" is a software assertion that the simulated condition is met — it is a stand-in for what a real infrastructure enforcement layer would do.

**What would change for real production use:** The simulator would need to be replaced with (or augmented by) actual enforcement integrations — e.g., calls to a firewall API, a SIEM rule engine, or a network access control system — with real confirmation feedback.

---

## 2. Sepolia Testnet — Not Ethereum Mainnet

**What the system does:** Forensic event hashes are written to a `ForensicLedger` smart contract deployed on the Ethereum Sepolia public testnet (`0xB12BB431DbfB42A2FDfF608aec09e8e7413dEc3C`).

**What this means in practice:**

- Sepolia is a public, decentralised testnet — block history cannot be rewritten by a single party. On-chain writes are genuinely immutable.
- Sepolia has **no economic security guarantees**: validators are not bonded with real ETH, so the game-theoretic security assumptions of mainnet do not apply.
- Evidence recorded on Sepolia is publicly verifiable by anyone, but would not be considered legally admissible without mainnet deployment.
- The private key is stored in a plaintext `.env` file. Key compromise allows `markRecoveryVerified()` calls from a third party.
- Block confirmation time on Sepolia is ~12 seconds (observed range in this project: 8–35 s per write), which dominates the latency of the `/detect` endpoint when live blockchain writes are enabled.

**What would change for real production use:** Deployment to Ethereum mainnet with HSM or multisig key management. Gas costs at ~90,000–120,000 gas per `logEvent()` call would need to be budgeted (at current gas prices: ~$1–3 USD per write on mainnet).

---

## 3. Dataset Scale and Class Coverage

**What the system does:** The trained model artifact (`detector_v20260928_184345`) was trained on 692,692 rows from CICIDS-2017, but only two classes were present in those specific files: BENIGN and DoS.

**What this means in practice:** The deployed model artifact has seen zero BruteForce and zero PortScan training examples. Its performance on those classes is undefined — it may misclassify them. The model architecture supports all four classes; the issue is the training data selection for this run.

**What would change for real production use:** Training on the full CICIDS-2017 dataset (all 8 daily files, ~883 MB, ~3.8M rows) to ensure all four classes are represented. More critically, the CICIDS-2017 dataset is from 2017 — modern attack traffic patterns may not be well-represented.

---

## 4. No Adversarial Robustness

**What the system does:** The RandomForest classifier predicts attack types from 78 network-flow features.

**What this means in practice:** A sophisticated attacker who knows the feature thresholds used by the classifier can craft network traffic that evades detection. The classifier has no adversarial training, input certification, or anomaly detection layer for detecting evasion attempts.

**What would change for real production use:** Adversarial training, feature-level anomaly detection, ensemble diversity, or integration with rule-based detection as a complement to the ML layer.

---

## 5. Off-Chain Database Is Not Tamper-Evident or Encrypted

**What the system does:** The complete forensic event, explanation, and recovery data is stored in a SQLite file (`chainforensics.db`).

**What this means in practice:** Anyone with filesystem access to the server can read, modify, or delete the database. The blockchain hash proves tampering occurred but does not prevent it or restore the data. There is no encryption at rest, no access control log, and no backup mechanism built into the system.

**What would change for real production use:** Encrypted database (e.g., PostgreSQL with TDE), filesystem access controls, audit logging, and automated backups. The blockchain provides tamper *detection*; the off-chain store needs tamper *prevention*.

---

## 6. API Has No Rate Limiting

**What the system does:** The FastAPI application accepts unlimited requests per second with no throttling.

**What this means in practice:** A malicious or misconfigured client can exhaust server resources with high-volume requests, causing a denial of service for legitimate users.

**What would change for real production use:** A reverse proxy (nginx, Caddy) or API gateway with rate limiting in front of the application.

---

## 7. Single Point of Failure — No High Availability

**What the system does:** A single Python process runs the API; a single Hardhat node runs the blockchain.

**What this means in practice:** If either process crashes, the entire system is unavailable. There is no failover, no redundancy, and no health-monitoring restart policy.

**What would change for real production use:** Containerized deployment with a process supervisor (systemd, Docker restart policy), load balancing for the API, and use of a public blockchain network (which has its own availability guarantees) instead of a local node.

---

## 8. No Real-Time Traffic Ingestion

**What the system does:** The detection pipeline is designed around batch CSV ingestion (CICIDS-2017 files) via `load_csv()` and a CLI `retrain` command.

**What this means in practice:** There is no live packet capture, no streaming interface, and no real-time feature extraction from network traffic. The "real-time" claim applies to the pipeline's architecture once events arrive — not to the acquisition of those events.

**What would change for real production use:** Integration with a real-time flow exporter (e.g., NetFlow, IPFIX, or a PCAP processing daemon like CICFlowMeter) to produce the 78-column feature vectors in real time and feed them to the `predict()` function continuously.

---

## 9. Dashboard Is Read-Only (No Real-Time Alerting)

**What the system does:** The live dashboard (`/`) fetches incident data, KPI cards, and BASE metrics from the backend API. Clicking any incident row opens a forensic replay modal. A "Trigger" button can submit a synthetic event through the full pipeline.

**What this means in practice:** The dashboard is a read-only forensic audit tool. It does not send alerts, trigger paging, or integrate with SIEM/SOAR platforms. Auto-refresh is a periodic poll (every 30 s), not a push-based WebSocket stream.

**What would change for real production use:** Real-time push notifications via WebSocket or Server-Sent Events; integration with PagerDuty, Splunk, or similar for alerting on high-confidence detections.

---

## Summary Table

| Limitation | Severity | What Changes for Production |
|---|---|---|
| Simulated recovery (no real actions) | High | Real enforcement integrations |
| Sepolia testnet (not mainnet) | Medium | Ethereum mainnet + HSM key management |
| Incomplete class coverage in trained model | High | Full CICIDS-2017 training + modern dataset |
| No adversarial robustness | High | Adversarial training + rule-based complement |
| Off-chain DB not encrypted/tamper-evident | Medium | Encrypted DB + access controls + backups |
| No API rate limiting | Medium | Reverse proxy with throttling |
| Single point of failure | Medium | Container orchestration + HA deployment |
| No real-time traffic ingestion | Medium | NetFlow/PCAP integration |
| Dashboard is read-only (no alerting) | Low | WebSocket push + SIEM/SOAR integration |
