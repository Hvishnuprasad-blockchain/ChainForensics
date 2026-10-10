from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AttackKnowledge:
    """
    Knowledge-base entry for one attack type.

    Adding a new attack should require only a new entry in
    ATTACK_KNOWLEDGE_BASE.
    """

    explanation_template: str
    severity: str
    recovery_actions: tuple[str, ...]


# ============================================================
# Severity policy
# ============================================================
#
# Severity is based on potential operational impact:
#
# LOW:
#   Informational or non-attack traffic.
#
# MEDIUM:
#   Suspicious activity requiring investigation but with
#   comparatively limited immediate impact.
#
# HIGH:
#   Activity that can materially affect availability,
#   authentication, or reconnaissance exposure.
#
# CRITICAL:
#   Activity indicating a direct attempt to compromise,
#   execute unauthorized operations, or cause severe impact.
#
# The severity is therefore determined by attack category,
# not by arbitrary per-event judgement.
# ============================================================


ATTACK_KNOWLEDGE_BASE: dict[str, AttackKnowledge] = {

    "BENIGN": AttackKnowledge(
        explanation_template=(
            "The network event {flow_id} was classified as BENIGN "
            "with {confidence_percent:.1f}% confidence. "
            "The observed connection originated from {src_ip}:{src_port} "
            "and targeted {dst_ip}:{dst_port}. "
            "The recorded feature snapshot contains {feature_count} "
            "relevant network features{metrics_summary}."
        ),
        severity="LOW",
        recovery_actions=(
            "No immediate containment action is required.",
            "Retain the event as part of the normal forensic audit trail.",
            "Continue monitoring for changes in the observed traffic pattern.",
        ),
    ),

    "DoS": AttackKnowledge(
        explanation_template=(
            "The network event {flow_id} was classified as a Denial-of-Service "
            "attack with {confidence_percent:.1f}% confidence. "
            "Traffic originated from {src_ip}:{src_port} and targeted "
            "{dst_ip}:{dst_port}. "
            "The event contains {feature_count} recorded network features{metrics_summary}. "
            "The observed traffic characteristics indicate activity that "
            "may reduce the availability of the targeted service."
        ),
        severity="HIGH",
        recovery_actions=(
            "Identify and rate-limit the source traffic associated with {src_ip}.",
            "Protect the targeted service at {dst_ip}:{dst_port} using existing network controls.",
            "Review traffic volume and connection patterns around flow {flow_id}.",
            "Preserve relevant traffic logs for incident investigation.",
        ),
    ),

    "PortScan": AttackKnowledge(
        explanation_template=(
            "The network event {flow_id} was classified as a Port Scan "
            "with {confidence_percent:.1f}% confidence. "
            "The scan originated from {src_ip}:{src_port} and targeted "
            "{dst_ip}:{dst_port}. "
            "The event contains {feature_count} recorded network features{metrics_summary}. "
            "Port scanning is reconnaissance activity that can be used "
            "to identify exposed network services before a later attack."
        ),
        severity="HIGH",
        recovery_actions=(
            "Investigate the source host {src_ip} for additional reconnaissance activity.",
            "Review exposed services on the destination host {dst_ip}.",
            "Check firewall and access-control rules for unnecessary exposed ports.",
            "Preserve network evidence associated with flow {flow_id}.",
        ),
    ),

    "BruteForce": AttackKnowledge(
        explanation_template=(
            "The network event {flow_id} was classified as a Brute Force "
            "attack with {confidence_percent:.1f}% confidence. "
            "The activity originated from {src_ip}:{src_port} and targeted "
            "{dst_ip}:{dst_port}. "
            "The event contains {feature_count} recorded network features{metrics_summary}. "
            "This classification indicates repeated authentication-oriented "
            "activity that may represent an attempt to discover valid credentials."
        ),
        severity="HIGH",
        recovery_actions=(
            "Investigate authentication failures originating from {src_ip}.",
            "Temporarily restrict or rate-limit repeated authentication attempts.",
            "Review the affected account and authentication logs on {dst_ip}.",
            "Preserve authentication and network evidence for investigation.",
        ),
    ),

    # ========================================================
    # Demonstration extension
    #
    # This entry proves that a new attack type can be added
    # without changing generator.py or existing attack entries.
    # ========================================================

    "SQLInjection": AttackKnowledge(
        explanation_template=(
            "The network event {flow_id} was classified as a SQL Injection "
            "attempt with {confidence_percent:.1f}% confidence. "
            "The activity originated from {src_ip}:{src_port} and targeted "
            "{dst_ip}:{dst_port}. "
            "The event contains {feature_count} recorded network features. "
            "This classification indicates traffic that may contain attempts "
            "to manipulate database queries through an application interface."
        ),
        severity="CRITICAL",
        recovery_actions=(
            "Investigate requests originating from {src_ip}.",
            "Review application and database logs associated with {dst_ip}:{dst_port}.",
            "Inspect the affected application for unsafe database-query handling.",
            "Preserve application, network, and database evidence for forensic review.",
        ),
    ),
}


def get_attack_knowledge(attack_type: str) -> AttackKnowledge | None:
    """
    Return the knowledge-base entry for an attack type.

    Returns None for an unsupported attack type so that the
    generator can activate its explicit manual-review fallback.
    """

    return ATTACK_KNOWLEDGE_BASE.get(str(attack_type))