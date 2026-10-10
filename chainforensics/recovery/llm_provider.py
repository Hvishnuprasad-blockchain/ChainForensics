from __future__ import annotations

import json
import logging
import os
import random
import time
from typing import Any

import requests
from pydantic import BaseModel, Field, ValidationError

from chainforensics.recovery.provider import (
    RecoveryRecommendationProvider,
    RuleBasedRecoveryProvider,
)

logger = logging.getLogger("chainforensics.recovery.llm_provider")


class LlmStructuredOutput(BaseModel):
    status: str = Field(default="generated")
    attack_type: str
    severity: str
    explanation: str
    recovery_recommendations: list[str]


class LlmRecoveryProvider(RecoveryRecommendationProvider):
    """
    LLM-powered recovery recommendation adapter supporting Groq Cloud (hosted free tier)
    and Ollama (local open-weight). Features:
      - Exponential backoff with jitter for transient Groq API failures
      - 12s per-request timeout (generous for Groq LPU inference)
      - 3 retry attempts before falling back to rule-based engine
      - JSON extraction fallback for responses with markdown fences
      - Automatic graceful fallback to deterministic rule-based engine
    """

    MAX_RETRIES = 3
    BASE_DELAY_SECONDS = 1.0
    MAX_DELAY_SECONDS = 8.0

    def __init__(self, mode: str = "llm_with_fallback") -> None:
        self.mode = mode
        self.rule_based_fallback = RuleBasedRecoveryProvider()

    def _get_config(self) -> dict[str, Any]:
        provider = os.getenv("LLM_PROVIDER", "groq").strip().lower()
        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "12.0"))

        if provider == "ollama":
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1").rstrip("/")
            api_key = "ollama"
            model = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
        else:
            # Default: Groq Cloud
            base_url = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
            api_key = os.getenv("GROQ_API_KEY", "").strip()
            model = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")

        return {
            "provider": provider,
            "base_url": base_url,
            "api_key": api_key,
            "model": model,
            "timeout": timeout,
        }

    def _build_prompt(self, event: dict[str, Any]) -> list[dict[str, str]]:
        attack_type = event.get("attack_type", "UNKNOWN")
        confidence = float(event.get("confidence", 0.0))
        source = event.get("source", {})
        dest = event.get("destination", {})
        flow_id = event.get("flow_id", "UNKNOWN")
        raw_feats = event.get("raw_features", {}) if isinstance(event.get("raw_features"), dict) else {}

        system_prompt = (
            "You are an expert Security Operations Center (SOC) incident response architect. "
            "Analyze the following network forensic event and return a JSON object with this exact structure:\n"
            "{\n"
            '  "status": "generated",\n'
            '  "attack_type": "<Attack Type>",\n'
            '  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",\n'
            '  "explanation": "<Clear, quantitative explanation referencing the observed attack vector and telemetry>",\n'
            '  "recovery_recommendations": [\n'
            '    "<Action 1: immediate isolation/firewall/ACL rule>",\n'
            '    "<Action 2: system/service reconfiguration or mitigation>",\n'
            '    "<Action 3: forensic verification and evidence preservation>"\n'
            "  ]\n"
            "}\n"
            "Respond ONLY with valid JSON. Do not include markdown code fences or conversational text."
        )

        user_content = (
            f"Forensic Incident Telemetry:\n"
            f"- Flow ID: {flow_id}\n"
            f"- Attack Vector: {attack_type} (Confidence: {confidence * 100:.1f}%)\n"
            f"- Source: {source.get('ip', 'UNKNOWN')}:{source.get('port', 0)}\n"
            f"- Destination: {dest.get('ip', 'UNKNOWN')}:{dest.get('port', 0)}\n"
            f"- Flow Features Sample: {json.dumps(dict(list(raw_feats.items())[:6]))}\n"
        )

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

    def _extract_json_from_content(self, raw_content: str) -> dict[str, Any]:
        """
        Robustly parse JSON from LLM response.
        Handles cases where the model wraps output in markdown code fences despite instructions.
        """
        content = raw_content.strip()

        # First: try direct parse
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Second: strip markdown fences ```json ... ``` or ``` ... ```
        for fence_start in ["```json", "```"]:
            if fence_start in content:
                try:
                    inner = content.split(fence_start, 1)[1]
                    inner = inner.rsplit("```", 1)[0]
                    return json.loads(inner.strip())
                except (json.JSONDecodeError, IndexError):
                    pass

        # Third: find first { ... } block
        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(content[start : end + 1])
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Cannot extract valid JSON from LLM content: {content[:200]!r}")

    def _call_llm_api_with_retry(
        self, config: dict[str, Any], messages: list[dict[str, str]]
    ) -> tuple[dict[str, Any], float]:
        """
        Calls the LLM API with exponential backoff + jitter.
        Retries up to MAX_RETRIES times on transient failures (network errors, 429, 503).
        """
        if config["provider"] == "groq" and not config["api_key"]:
            raise ValueError("GROQ_API_KEY environment variable is not configured.")

        url = f"{config['base_url']}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['api_key']}",
        }
        payload = {
            "model": config["model"],
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 768,
            "response_format": {"type": "json_object"},
        }

        last_exception: Exception = RuntimeError("No attempts made")

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                start_time = time.perf_counter()
                resp = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=config["timeout"],
                )
                latency = time.perf_counter() - start_time

                if resp.status_code == 200:
                    res_json = resp.json()
                    raw_content = res_json["choices"][0]["message"]["content"]
                    parsed_data = self._extract_json_from_content(raw_content)
                    logger.info(
                        "LLM API success | attempt=%d/%d | latency=%.3fs | model=%s",
                        attempt,
                        self.MAX_RETRIES,
                        latency,
                        config["model"],
                    )
                    return parsed_data, latency

                # Retryable HTTP errors
                if resp.status_code in (429, 500, 502, 503, 504):
                    error_msg = f"LLM HTTP {resp.status_code}"
                    try:
                        error_body = resp.json()
                        error_msg += f": {error_body.get('error', {}).get('message', resp.text[:120])}"
                    except Exception:
                        error_msg += f": {resp.text[:120]}"
                    last_exception = RuntimeError(error_msg)
                    logger.warning(
                        "LLM transient error (attempt %d/%d): %s",
                        attempt,
                        self.MAX_RETRIES,
                        error_msg,
                    )
                else:
                    # Non-retryable: 400, 401, 403
                    raise RuntimeError(f"LLM API returned HTTP {resp.status_code}: {resp.text[:200]}")

            except requests.exceptions.Timeout:
                last_exception = TimeoutError(
                    f"LLM request timed out after {config['timeout']}s (attempt {attempt})"
                )
                logger.warning("LLM timeout on attempt %d/%d", attempt, self.MAX_RETRIES)

            except requests.exceptions.ConnectionError as conn_err:
                last_exception = RuntimeError(f"LLM connection error: {conn_err}")
                logger.warning("LLM connection error on attempt %d/%d: %s", attempt, self.MAX_RETRIES, conn_err)

            except (json.JSONDecodeError, KeyError, ValueError) as parse_err:
                last_exception = RuntimeError(f"LLM response parse error: {parse_err}")
                logger.warning("LLM parse error on attempt %d/%d: %s", attempt, self.MAX_RETRIES, parse_err)

            if attempt < self.MAX_RETRIES:
                # Exponential backoff with full jitter
                delay = min(
                    self.BASE_DELAY_SECONDS * (2 ** (attempt - 1)),
                    self.MAX_DELAY_SECONDS,
                ) * (0.5 + random.random() * 0.5)
                logger.info("Retrying LLM call in %.2fs (attempt %d/%d)", delay, attempt + 1, self.MAX_RETRIES)
                time.sleep(delay)

        raise last_exception

    def get_recommendation(self, event: dict[str, Any]) -> dict[str, Any]:
        config = self._get_config()
        messages = self._build_prompt(event)

        logger.info(
            "Invoking LLM recovery provider | provider=%s | model=%s | attack_type=%s",
            config["provider"],
            config["model"],
            event.get("attack_type"),
        )

        try:
            raw_output, latency = self._call_llm_api_with_retry(config, messages)
            validated = LlmStructuredOutput(**raw_output)

            logger.info(
                "LLM recommendation generated successfully | latency=%.3fs | provider=%s | model=%s",
                latency,
                config["provider"],
                config["model"],
            )

            return {
                "status": validated.status,
                "attack_type": validated.attack_type,
                "severity": validated.severity.upper(),
                "explanation": validated.explanation,
                "recovery_recommendations": validated.recovery_recommendations,
                "recovery_provider": f"llm_{config['provider']}",
                "llm_model": config["model"],
                "llm_latency_seconds": round(latency, 4),
                "fallback_triggered": False,
                "event": event,
            }

        except Exception as exc:
            if self.mode == "llm":
                # Strict LLM mode: do not catch
                logger.error("LLM provider execution failed in strict mode: %s", exc)
                raise

            logger.warning(
                "LLM provider failed after %d attempts (%s: %s). Activating rule-based fallback.",
                self.MAX_RETRIES,
                type(exc).__name__,
                exc,
            )

            fallback_res = self.rule_based_fallback.get_recommendation(event)
            fallback_res["fallback_triggered"] = True
            fallback_res["fallback_reason"] = f"{type(exc).__name__}: {str(exc)}"
            fallback_res["recovery_provider"] = "rule_based_fallback"
            return fallback_res
