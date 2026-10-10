from chainforensics.event_builder import build_forensic_event
from chainforensics.explainability.generator import generate_explanation


def test_real_sprint_pipeline_event_to_explanation():
    """
    Integration test using the same event builder used by
    the actual ChainForensics Sprint 1/2 pipeline.
    """

    # This is created through the real production event builder,
    # not through the Sprint 3 test helper.
    event = build_forensic_event(
        flow_id="CF-INTEGRATION-001",
        timestamp="2026-09-29T10:30:00Z",
        src_ip="192.168.1.100",
        src_port=49152,
        dst_ip="10.0.0.25",
        dst_port=443,
        attack_type="PortScan",
        confidence=0.97,
        raw_features={
            "packet_count": 150,
            "flow_duration": 2.41,
            "destination_port": 443,
        },
    )

    result = generate_explanation(event)

    assert result["status"] == "generated"
    assert result["attack_type"] == "PortScan"
    assert result["severity"] == "HIGH"

    assert "CF-INTEGRATION-001" in result["explanation"]
    assert "192.168.1.100" in result["explanation"]
    assert "10.0.0.25" in result["explanation"]
    assert "97.0%" in result["explanation"]

    recommendations = "\n".join(
        result["recovery_recommendations"]
    )

    assert "192.168.1.100" in recommendations
    assert "CF-INTEGRATION-001" in recommendations