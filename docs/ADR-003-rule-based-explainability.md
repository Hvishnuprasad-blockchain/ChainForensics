# ADR-003: Rule-Based Explainability and Recovery Recommendations

## Status
Accepted

## Date
2026-09-30

## Context
ChainForensics converts raw, detected forensic events (network endpoints, flow identifiers, timestamp, attack category, detection confidence, and quantitative flow feature snapshots) into plain-language narratives and actionable incident-response recommendations for stakeholders (SOC analysts, incident commanders, regulatory auditors, and executives).

During incident response and compliance demonstrations, explanations must be generated rapidly, predictably, and without external network vulnerabilities.

Two architectural approaches were evaluated:
1. **External Commercial LLM API (e.g., OpenAI GPT-4, Anthropic Claude)**: Sending event JSON to a third-party hosted model with prompt engineering to synthesize dynamic prose.
2. **Deterministic Rule-Based Knowledge Engine**: Utilizing an Open/Closed knowledge base mapping verified attack categories to structured explanation templates, consistent impact-based severity ratings, and actionable remediation checklists parameterized with real flow measurements.

## Decision
ChainForensics adopts an in-process, deterministic rule-based explainability and recovery recommendation engine.

Key architectural characteristics:
- **Centralized Knowledge Base (`knowledge_base.py`)**: Stores `AttackKnowledge` records containing explanation templates, severity ratings, and recovery action templates.
- **Open/Closed Design**: New attack classes (e.g., `SQLInjection`) are integrated solely by declaring an entry in `ATTACK_KNOWLEDGE_BASE`. Zero changes are made to generator or pipeline logic.
- **Explicit Manual-Review Fallback**: Unrecognized attack categories never raise unhandled exceptions; they safely emit a structured `"manual_review_required"` response instructing human analysts to investigate.
- **Quantitative Forensic Grounding**: Templates dynamically incorporate verified flow metrics (source/dest endpoints, duration, packet counts, packet rates) rather than vague prose.

## Engineering Trade-off Analysis

### 1. Cost & Financial Reliability
- **Commercial LLM API**: Incurs ongoing per-token financial costs ($0.01–$0.06 per event). Under burst attacks (e.g., 5,000 DDoS flows/sec), API fees quickly become prohibitive or deplete quotas.
- **Rule-Based Engine**: Completely zero-cost. Operates locally with no operational overhead or budget vulnerability.

### 2. High-Stakes Reliability & Latency
- **Commercial LLM API**: Subject to WAN latency (500ms–3,000ms), third-party service outages, network rate limits (HTTP 429), and token exhaustion during active incidents.
- **Rule-Based Engine**: Sub-millisecond execution (<1ms). Guarantees 100% availability during high-stress SOC operations and network partitions.

### 3. Forensic Determinism & Hallucination Elimination
- **Commercial LLM API**: Probabilistic models can hallucinate non-existent IP addresses, misquote packet counts, soften critical warnings, or vary advice between incident audits.
- **Rule-Based Engine**: Mathematically deterministic. The identical event always produces identical byte-for-byte explanations, preserving evidentiary admissibility and compliance reproducibility.

### 4. Phrasing Naturalness Trade-off
- **Accepted Trade-off**: Templated text offers less conversational variety than a multi-billion-parameter LLM. However, in security incident response, semantic accuracy, evidentiary consistency, and zero failure rates vastly outweigh creative conversational flair.

## Severity Policy

Severity is explicitly classified based on operational impact and attack vector risk:

| Severity Level | Operational Impact Definition | Mapped Attack Categories |
| :--- | :--- | :--- |
| **LOW** | Informational or benign baseline network traffic. No compromise risk. | `BENIGN` |
| **MEDIUM** | Low-impact anomalies or policy violations not immediately threatening availability. | Minor configuration alerts |
| **HIGH** | Active reconnaissance or service disruption impacting service availability or access boundaries. | `DoS`, `PortScan`, `BruteForce` |
| **CRITICAL** | Direct attempts to manipulate databases, execute code, or achieve unauthorized privilege escalation. | `SQLInjection`, Remote Code Execution |

## Consequences

### Positive
- Zero external API dependencies, credentials, or network transmission of sensitive telemetry.
- Sub-millisecond generation latency.
- Full test reproducibility in CI/CD without mocks or API credits.
- Audit-compliant, transparent explanation rules.

### Negative / Future Outlook
- Templates require manual composition when introducing completely new threat taxonomies.
- Future enhancements may optionally layer a local open-weight model (e.g., quantized Llama 3) for supplementary prose summaries, but the deterministic rule engine remains the foundational, authoritative source of truth.
