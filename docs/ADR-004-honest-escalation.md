# ADR-004: Honest Escalation Over False On-Chain Confirmation

## Status
Accepted

## Date
2026-09-30

## Context
ChainForensics establishes a closed-loop incident response pipeline (Novelty Pillar 3). When an attack is detected, its forensic hash is committed to an immutable smart contract ledger (`ForensicLedger.sol`). Following detection, the system simulates or executes automated recovery actions and evaluates whether the underlying network condition has genuinely resolved.

The core architectural dilemma is: **What should the system do when automated recovery cannot be conclusively verified as successful?**

Two possible approaches exist:
1. **Optimistic Attestation**: Always record an on-chain verification update indicating that an automated remediation action was executed, perhaps with an error code or partial status flag.
2. **Strict Honest Escalation (Fail-Closed)**: Only write `markRecoveryVerified` to the immutable ledger when genuine, measurable recovery success is empirically proven. If recovery fails, or if telemetry is incomplete, mark the incident as `escalated` and emit **ZERO blockchain writes**.

## Decision
ChainForensics adopts **Strict Honest Escalation Over False On-Chain Confirmation**.

Under no circumstances will the system write a recovery verification transaction to the blockchain unless post-remediation evidence satisfies all documented threshold rules. On failure, uncertainty, missing telemetry, or uncataloged attack vectors, the incident is flagged as `escalated` in local persistent state, triggering human SOC investigation, and the blockchain is left untouched.

## Core Engineering & Security Rationale

### 1. The Immutability Paradox: Permanent Falsification
Blockchains are cryptographically immutable. A transaction confirming recovery (`recoveryVerified = true`) cannot be amended, deleted, or rolled back.
- If a false or premature "verified" status is committed to the blockchain, the immutable ledger becomes an **indelible record of falsehood**.
- An auditor, regulator, or executive inspecting the blockchain would observe a cryptographically signed attestation of containment for an asset that is still actively compromised.

### 2. Operational Hazard: Premature SOC Complacency
In cybersecurity operations centers (SOCs), automated status signals dictate triage priority:
- A "verified" signal marks an incident ticket as resolved, dismissing alarms and freeing analysts to focus elsewhere.
- If an automated script fails to mitigate a DoS or brute-force attack but emits an on-chain confirmation, security personnel are blinded. The attacker continues exfiltrating data or denying service behind the facade of a "verified" automated recovery.
- Conversely, an honest `escalated` status triggers high-priority human review, ensuring an engineer actively investigates the ongoing threat.

### 3. Regulatory & Evidentiary Liability
In modern regulatory environments (e.g., SEC Cybersecurity Disclosure Rules, EU NIS2 Directive, GDPR breach notification, PCI-DSS):
- Immutable blockchain records are frequently subpoenaed or presented to regulatory authorities as cryptographic proof of due diligence and incident containment.
- Presenting a smart contract ledger certifying that an incident was contained when system logs prove the breach continued exposes an enterprise to severe legal penalties, shareholder lawsuits, and accusations of fraudulent reporting.

### 4. Asymmetry of Cost and Integrity
- **Executing a Blockchain Write**: Consumes transaction fees (gas), consumes block space, requires RPC round-trips, and irreversibly modifies global ledger state.
- **Refraining from a Blockchain Write**: Zero gas expenditure, zero network overhead, zero pollution of global state. The event remains recorded as an unverified incident, accurately reflecting reality until human operators or subsequent automated cycles prove resolution.

### 5. Fail-Closed Security Engineering
High-assurance security systems must always fail closed:
- When evidence is missing, ambiguous, or incomplete (e.g., a required feature is absent from the snapshot), the system treats this as an escalation event.
- It is profoundly safer to escalate a resolved incident for human verification (a harmless false escalation) than to certify an unresolved breach as contained (a catastrophic false confirmation).

## Implementation Rules
1. **Hash-Based Chain Scanning**: The verifier locates the matching event by scanning on-chain event hashes (`find_event_index()`), never assuming index correspondence.
2. **Single Authorized Caller**: The `markRecoveryVerified(uint256 index)` smart-contract function enforces `onlyOwner`, preventing unauthorized accounts from attesting recovery.
3. **Verified-Only Invocation**: In `chainforensics/recovery/verifier.py`, `client.mark_recovery_verified(index)` is reached if and only if `status == "verified"`.
4. **Independent Auditability**: The contract emits `RecoveryVerified(index, eventHash, verifier, timestamp)`. Escalated incidents produce zero such events, verifiable by inspecting contract logs.

## Consequences

### Positive
- Absolute cryptographic integrity: the on-chain `recoveryVerified` flag is an uncompromised gold standard of verified remediation.
- SOC teams maintain trust in the automated ledger; a verified flag never produces a false sense of security.
- Eliminates unnecessary gas consumption on failed remediation attempts.

### Negative / Operational Considerations
- Incidents requiring manual remediation do not receive on-chain completion stamps until human-in-the-loop tooling is invoked.
- Requires robust local database persistence (Sprint 5) to track escalated incidents and ensure they are not lost.
