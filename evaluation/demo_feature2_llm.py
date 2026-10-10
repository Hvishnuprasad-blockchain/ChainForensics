from __future__ import annotations

import json
import logging
import os
from unittest.mock import MagicMock, patch

from chainforensics.recovery.llm_provider import LlmRecoveryProvider
from chainforensics.recovery.provider import RuleBasedRecoveryProvider

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")


SAMPLE_INCIDENTS = [
    {
        "flow_id": "flow-demo-001",
        "timestamp": "2026-10-03T14:00:00Z",
        "source": {"ip": "198.51.100.42", "port": 44812},
        "destination": {"ip": "10.0.0.5", "port": 80},
        "attack_type": "DoS",
        "confidence": 0.9994,
        "raw_features": {
            "Total Fwd Packets": 12500,
            "Flow Duration": 5000000,
            "Flow Packets/s": 2500.0,
            "SYN Flag Count": 12500,
        },
    },
    {
        "flow_id": "flow-demo-002",
        "timestamp": "2026-10-03T14:05:00Z",
        "source": {"ip": "203.0.113.19", "port": 51234},
        "destination": {"ip": "10.0.0.12", "port": 22},
        "attack_type": "BruteForce",
        "confidence": 0.9875,
        "raw_features": {
            "failed_attempts": 350,
            "Flow Duration": 450000,
            "Flow Packets/s": 42.0,
        },
    },
    {
        "flow_id": "flow-demo-003",
        "timestamp": "2026-10-03T14:10:00Z",
        "source": {"ip": "198.51.100.88", "port": 60120},
        "destination": {"ip": "10.0.0.5", "port": 443},
        "attack_type": "PortScan",
        "confidence": 0.9750,
        "raw_features": {
            "Total Fwd Packets": 1024,
            "Flow Duration": 1200000,
            "Fwd Packet Length Max": 64,
        },
    },
    {
        "flow_id": "flow-demo-004",
        "timestamp": "2026-10-03T14:15:00Z",
        "source": {"ip": "192.0.2.140", "port": 39810},
        "destination": {"ip": "10.0.0.25", "port": 8080},
        "attack_type": "SQLInjection",
        "confidence": 0.9910,
        "raw_features": {
            "suspicious_queries": 45,
            "Total Fwd Packets": 120,
            "Flow Duration": 350000,
        },
    },
    {
        "flow_id": "flow-demo-005",
        "timestamp": "2026-10-03T14:20:00Z",
        "source": {"ip": "192.168.1.55", "port": 52140},
        "destination": {"ip": "10.0.0.5", "port": 80},
        "attack_type": "BENIGN",
        "confidence": 0.9991,
        "raw_features": {
            "Total Fwd Packets": 12,
            "Flow Duration": 150000,
            "Flow Packets/s": 80.0,
        },
    },
]


def run_llm_feature2_evaluation():
    print("=" * 80)
    print("CHAINFORENSICS V2 — FEATURE 2: LLM RECOVERY RECOMMENDATION DEMONSTRATION")
    print("=" * 80)

    from dotenv import load_dotenv
    load_dotenv()

    rule_provider = RuleBasedRecoveryProvider()
    llm_provider = LlmRecoveryProvider(mode="llm_with_fallback")
    has_live_key = bool(os.getenv("GROQ_API_KEY"))

    print(f"\n--- 1. PROCESSING 5 REAL INCIDENTS THROUGH LLM ADAPTER PATH (Live Groq: {has_live_key}) ---")
    for i, event in enumerate(SAMPLE_INCIDENTS):
        res = llm_provider.get_recommendation(event)
        print(f"\n[Incident {i+1}: {event['flow_id']} | Vector: {event['attack_type']}]")
        print(f"  Provider:       {res['recovery_provider']}")
        print(f"  Severity:       {res['severity']}")
        if res.get('llm_latency_seconds'):
            print(f"  Latency:        {res['llm_latency_seconds']}s")
        print(f"  Explanation:    {res['explanation']}")
        print(f"  Actions:        {len(res['recovery_recommendations'])} structured remediation steps")
        for step_idx, act in enumerate(res['recovery_recommendations']):
            print(f"    {step_idx+1}. {act}")

    print("\n" + "=" * 80)
    print("--- 2. DELIBERATELY FORCED FAILURE: PROVING TRANSPARENT FALLBACK ---")
    print("Simulating API network timeout and missing key...")

    with patch("requests.post", side_effect=Exception("Connection to Groq API timed out after 2.50s")):
        fallback_res = llm_provider.get_recommendation(SAMPLE_INCIDENTS[0])
        print(f"\nFallback Activated:      {fallback_res['fallback_triggered']}")
        print(f"Active Provider:         {fallback_res['recovery_provider']}")
        print(f"Fallback Reason Logged:  {fallback_res.get('fallback_reason')}")
        print(f"Recovered Explanation:   {fallback_res['explanation'][:100]}...")
        print(f"Recovered Actions Count: {len(fallback_res['recovery_recommendations'])}")

    print("\n" + "=" * 80)
    print("--- 3. SIDE-BY-SIDE COMPARISON: RULE-BASED VS. LLM EXPLANATION ---")
    rule_res = rule_provider.get_recommendation(SAMPLE_INCIDENTS[0])
    llm_res = llm_provider.get_recommendation(SAMPLE_INCIDENTS[0])

    print("\n[V1 RULE-BASED OUTPUT]:")
    print(f"  Explanation: {rule_res['explanation']}")
    print(f"  Actions:     {list(rule_res['recovery_recommendations'])}")

    print(f"\n[V2 LLM-POWERED OUTPUT (Provider: {llm_res.get('recovery_provider')})]:")
    print(f"  Explanation: {llm_res['explanation']}")
    print(f"  Actions:     {llm_res['recovery_recommendations']}")
    print("=" * 80)


if __name__ == "__main__":
    run_llm_feature2_evaluation()
