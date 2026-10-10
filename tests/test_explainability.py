from chainforensics.event_builder import build_forensic_event
from chainforensics.explainability.generator import generate_explanation
from chainforensics.explainability.knowledge_base import (
    ATTACK_KNOWLEDGE_BASE,
)


def make_event(attack_type: str):
    """Create a deterministic event using the real Sprint 1 event builder."""

    return build_forensic_event(
        flow_id=f"TEST-{attack_type}",
        timestamp="2026-09-29T10:00:00Z",
        src_ip="192.168.1.100",
        src_port=49152,
        dst_ip="10.0.0.25",
        dst_port=443,
        attack_type=attack_type,
        confidence=0.97,
        raw_features={
            "packet_count": 150,
            "flow_duration": 2.41,
            "destination_port": 443,
        },
    )


# ============================================================
# Supported attack types
# ============================================================


def test_all_supported_attack_types_generate_output():
    """
    Every attack type in the knowledge base must generate a
    normal explanation.
    """

    for attack_type in ATTACK_KNOWLEDGE_BASE:

        event = make_event(attack_type)

        result = generate_explanation(event)

        assert result["status"] == "generated"
        assert result["attack_type"] == attack_type
        assert result["severity"] != "UNKNOWN"

        assert result["explanation"]
        assert len(result["recovery_recommendations"]) > 0


# ============================================================
# Real values must appear
# ============================================================


def test_generated_explanation_contains_real_event_values():

    event = make_event("PortScan")

    result = generate_explanation(event)

    explanation = result["explanation"]

    assert "192.168.1.100" in explanation
    assert "49152" in explanation
    assert "10.0.0.25" in explanation
    assert "443" in explanation

    assert "97.0%" in explanation
    assert "4" in explanation


# ============================================================
# Recovery recommendations must contain real values
# ============================================================


def test_recovery_recommendations_contain_real_values():

    event = make_event("DoS")

    result = generate_explanation(event)

    recommendations = "\n".join(
        result["recovery_recommendations"]
    )

    assert "192.168.1.100" in recommendations
    assert "10.0.0.25" in recommendations
    assert "443" in recommendations
    assert "TEST-DoS" in recommendations


def test_quantitative_metrics_included_in_explanation():
    """Proves explanations contain specific flow metrics (rates, durations, counts)."""
    event = build_forensic_event(
        flow_id="FLOW-METRICS-001",
        timestamp="2026-09-30T10:00:00Z",
        src_ip="10.0.0.99",
        src_port=50000,
        dst_ip="10.0.0.1",
        dst_port=80,
        attack_type="DoS",
        confidence=0.995,
        raw_features={
            "Flow Duration": 2_000_000,  # 2.0s
            "Total Fwd Packets": 824,
            "Total Backward Packets": 0,
            "Flow Packets/s": 412.0,
        },
    )
    result = generate_explanation(event)
    assert "packet rate: 412.0 pkts/sec" in result["explanation"]
    assert "packet count: 824" in result["explanation"]
    assert "duration: 2.00s" in result["explanation"]


# ============================================================
# Fallback
# ============================================================


def test_unknown_attack_type_uses_manual_review_fallback():

    event = make_event("UnknownFutureAttack")

    result = generate_explanation(event)

    assert result["status"] == "manual_review_required"

    assert result["attack_type"] == "UnknownFutureAttack"

    assert result["severity"] == "UNKNOWN"

    assert "Manual review required" in result["explanation"]

    assert len(result["recovery_recommendations"]) > 0


# ============================================================
# Demonstration new attack type
# ============================================================


def test_sql_injection_demonstration_attack_type():

    event = make_event("SQLInjection")

    result = generate_explanation(event)

    assert result["status"] == "generated"

    assert result["attack_type"] == "SQLInjection"

    assert result["severity"] == "CRITICAL"

    assert "SQL Injection" in result["explanation"]

    assert "192.168.1.100" in result["explanation"]

    assert "97.0%" in result["explanation"]

    assert len(result["recovery_recommendations"]) >= 3


# ============================================================
# Open/Closed design
# ============================================================


def test_existing_attack_types_remain_supported_after_extension():

    expected_attack_types = {
        "BENIGN",
        "DoS",
        "PortScan",
        "BruteForce",
        "SQLInjection",
    }

    assert expected_attack_types.issubset(
        set(ATTACK_KNOWLEDGE_BASE.keys())
    )

    for attack_type in (
        "BENIGN",
        "DoS",
        "PortScan",
        "BruteForce",
    ):

        event = make_event(attack_type)

        result = generate_explanation(event)

        assert result["status"] == "generated"

        assert result["attack_type"] == attack_type