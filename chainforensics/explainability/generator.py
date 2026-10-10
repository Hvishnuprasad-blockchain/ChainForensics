from __future__ import annotations

from typing import Any

from .knowledge_base import get_attack_knowledge


def _feature_count(event: dict[str, Any]) -> int:
    """Return the number of raw features recorded in the event."""

    raw_features = event.get("raw_features", {})

    if not isinstance(raw_features, dict):
        return 0

    return len(raw_features)


def _template_values(event: dict[str, Any]) -> dict[str, Any]:
    """
    Extract real values from the forensic event.

    These values are passed directly into the knowledge-base
    explanation and recovery templates. Specific flow characteristics
    (packet count, duration, packet rate) are dynamically extracted from
    raw_features to ensure explanations contain quantitative forensic evidence.
    """

    source = event.get("source", {})
    destination = event.get("destination", {})

    confidence = float(event.get("confidence", 0.0))
    raw_features = event.get("raw_features", {}) if isinstance(event.get("raw_features"), dict) else {}

    # Extract flow duration in seconds (CICIDS2017 uses microseconds)
    duration: float | None = None
    if "Flow Duration" in raw_features:
        try:
            duration = float(raw_features["Flow Duration"]) / 1_000_000.0
        except (ValueError, TypeError):
            duration = None
    elif "flow_duration" in raw_features:
        try:
            duration = float(raw_features["flow_duration"])
        except (ValueError, TypeError):
            duration = None

    # Extract packet count
    packets: float | None = None
    if "Total Fwd Packets" in raw_features:
        try:
            fwd = float(raw_features["Total Fwd Packets"])
            bwd = float(raw_features.get("Total Backward Packets", 0) or 0)
            packets = fwd + bwd
        except (ValueError, TypeError):
            packets = None
    elif "packet_count" in raw_features:
        try:
            packets = float(raw_features["packet_count"])
        except (ValueError, TypeError):
            packets = None

    # Extract or compute packet rate (packets / sec)
    packet_rate: float | None = None
    if "Flow Packets/s" in raw_features:
        try:
            packet_rate = float(raw_features["Flow Packets/s"])
        except (ValueError, TypeError):
            packet_rate = None
    elif packets is not None and duration is not None and duration > 0:
        packet_rate = packets / duration

    # Format quantitative metrics summary
    metrics_parts = []
    if packets is not None:
        metrics_parts.append(f"packet count: {int(packets):,}")
    if duration is not None and duration > 0:
        metrics_parts.append(f"duration: {duration:.2f}s")
    if packet_rate is not None and packet_rate > 0:
        metrics_parts.append(f"packet rate: {packet_rate:.1f} pkts/sec")

    metrics_summary = f" (observed {', '.join(metrics_parts)})" if metrics_parts else ""

    return {
        "flow_id": str(event.get("flow_id", "UNKNOWN")),
        "timestamp": str(event.get("timestamp", "UNKNOWN")),
        "src_ip": str(source.get("ip", "UNKNOWN")),
        "src_port": int(source.get("port", 0)),
        "dst_ip": str(destination.get("ip", "UNKNOWN")),
        "dst_port": int(destination.get("port", 0)),
        "confidence": confidence,
        "confidence_percent": confidence * 100.0,
        "feature_count": _feature_count(event),
        "metrics_summary": metrics_summary,
        "packet_count": int(packets) if packets is not None else 0,
        "packet_rate": packet_rate if packet_rate is not None else 0.0,
        "duration": duration if duration is not None else 0.0,
    }


def generate_explanation(event: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a forensic event into a stakeholder-readable
    explanation and recovery recommendation.

    Unknown attack types intentionally do not raise an exception.
    They return an explicit manual-review response.
    """

    if not isinstance(event, dict):
        return {
            "status": "manual_review_required",
            "attack_type": "UNKNOWN",
            "severity": "UNKNOWN",
            "explanation": (
                "Manual review required: the forensic event is not "
                "a valid event dictionary."
            ),
            "recovery_recommendations": (
                "Validate the forensic event structure before further analysis.",
            ),
        }

    attack_type = str(event.get("attack_type", "UNKNOWN"))

    knowledge = get_attack_knowledge(attack_type)

    # ========================================================
    # Explicit fallback
    # ========================================================

    if knowledge is None:
        values = _template_values(event)

        return {
            "status": "manual_review_required",
            "attack_type": attack_type,
            "severity": "UNKNOWN",
            "explanation": (
                f"Manual review required: attack type '{attack_type}' "
                f"is not currently present in the ChainForensics "
                f"knowledge base. "
                f"The event originated from {values['src_ip']}:{values['src_port']} "
                f"and targeted {values['dst_ip']}:{values['dst_port']} "
                f"with {values['confidence_percent']:.1f}% detection confidence."
            ),
            "recovery_recommendations": (
                "Review the event manually before taking automated recovery action.",
                "Add the attack type to the knowledge base after validating its response procedure.",
                f"Preserve forensic evidence associated with flow {values['flow_id']}.",
            ),
        }

    # ========================================================
    # Normal supported attack path
    # ========================================================

    values = _template_values(event)

    explanation = knowledge.explanation_template.format(**values)

    recommendations = tuple(
        action.format(**values)
        for action in knowledge.recovery_actions
    )

    return {
        "status": "generated",
        "attack_type": attack_type,
        "severity": knowledge.severity,
        "explanation": explanation,
        "recovery_recommendations": recommendations,
        "event": event,
    }