from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from typing import Any

from chainforensics.explainability.generator import generate_explanation

logger = logging.getLogger("chainforensics.recovery.provider")


class RecoveryRecommendationProvider(ABC):
    """
    Abstract interface for incident recovery and explainability recommendation providers.
    Supports both deterministic rule-based engines and adaptive LLM engines.
    """

    @abstractmethod
    def get_recommendation(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Produce structured explanation and recovery recommendations for a forensic event.
        Must return a dictionary conforming to the standard recovery schema:
        {
            "status": str,
            "attack_type": str,
            "severity": str,
            "explanation": str,
            "recovery_recommendations": list[str] | tuple[str, ...],
            "recovery_provider": str,
            ...
        }
        """
        raise NotImplementedError


class RuleBasedRecoveryProvider(RecoveryRecommendationProvider):
    """
    The baseline v1 deterministic rule-based explainability and recovery provider.
    Always available, executes in <1ms, zero external dependencies.
    """

    def get_recommendation(self, event: dict[str, Any]) -> dict[str, Any]:
        res = generate_explanation(event)
        res_copy = dict(res)
        res_copy["recovery_provider"] = "rule_based"
        res_copy["fallback_triggered"] = False
        return res_copy


def get_recovery_provider() -> RecoveryRecommendationProvider:
    """
    Factory function returning the configured RecoveryRecommendationProvider based on
    the RECOVERY_ENGINE environment variable (default: 'llm_with_fallback').
    """
    engine_mode = os.getenv("RECOVERY_ENGINE", "llm_with_fallback").strip().lower()

    if engine_mode == "rule_based":
        logger.info("Using RuleBasedRecoveryProvider (RECOVERY_ENGINE=rule_based)")
        return RuleBasedRecoveryProvider()

    # Deferred import to prevent circular dependencies
    from chainforensics.recovery.llm_provider import LlmRecoveryProvider

    logger.info("Using LlmRecoveryProvider (RECOVERY_ENGINE=%s)", engine_mode)
    return LlmRecoveryProvider(mode=engine_mode)
