from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from chainforensics.recovery.llm_provider import LlmRecoveryProvider
from chainforensics.recovery.provider import (
    RuleBasedRecoveryProvider,
    get_recovery_provider,
)


@pytest.fixture
def sample_event():
    return {
        "flow_id": "flow-test-999",
        "timestamp": "2026-10-03T12:00:00Z",
        "source": {"ip": "198.51.100.42", "port": 44812},
        "destination": {"ip": "10.0.0.5", "port": 80},
        "attack_type": "DoS",
        "confidence": 0.998,
        "raw_features": {
            "Total Fwd Packets": 500,
            "Flow Duration": 2000000,
            "Flow Packets/s": 250.0,
        },
    }


def test_rule_based_recovery_provider(sample_event):
    provider = RuleBasedRecoveryProvider()
    res = provider.get_recommendation(sample_event)

    assert res["status"] == "generated"
    assert res["attack_type"] == "DoS"
    assert "explanation" in res
    assert len(res["recovery_recommendations"]) > 0
    assert res["recovery_provider"] == "rule_based"
    assert res["fallback_triggered"] is False


def test_llm_provider_success_mock(sample_event, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-mock-valid-key")
    monkeypatch.setenv("LLM_PROVIDER", "groq")

    mock_llm_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "status": "generated",
                        "attack_type": "DoS",
                        "severity": "CRITICAL",
                        "explanation": "High-volume SYN flood targeting port 80. Immediate automated filtering warranted.",
                        "recovery_recommendations": [
                            "Block source IP 198.51.100.42 at edge firewall",
                            "Enable TCP SYN cookies on web host 10.0.0.5",
                            "Preserve packet capture flow-test-999 for forensic ledger audit",
                        ],
                    })
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_llm_response

    with patch("requests.post", return_value=mock_resp):
        provider = LlmRecoveryProvider(mode="llm_with_fallback")
        res = provider.get_recommendation(sample_event)

        assert res["status"] == "generated"
        assert res["attack_type"] == "DoS"
        assert res["severity"] == "CRITICAL"
        assert "SYN flood" in res["explanation"]
        assert len(res["recovery_recommendations"]) == 3
        assert res["recovery_provider"] == "llm_groq"
        assert res["fallback_triggered"] is False


def test_llm_provider_missing_key_triggers_fallback(sample_event, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "groq")

    provider = LlmRecoveryProvider(mode="llm_with_fallback")
    res = provider.get_recommendation(sample_event)

    assert res["status"] == "generated"
    assert res["attack_type"] == "DoS"
    assert res["recovery_provider"] == "rule_based_fallback"
    assert res["fallback_triggered"] is True
    assert "GROQ_API_KEY" in res["fallback_reason"]


def test_llm_provider_timeout_triggers_fallback(sample_event, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-mock-valid-key")
    monkeypatch.setenv("LLM_PROVIDER", "groq")

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Connection timed out")):
        provider = LlmRecoveryProvider(mode="llm_with_fallback")
        res = provider.get_recommendation(sample_event)

        assert res["status"] == "generated"
        assert res["fallback_triggered"] is True
        assert res["recovery_provider"] == "rule_based_fallback"
        assert "Timeout" in res["fallback_reason"]


def test_llm_provider_malformed_json_triggers_fallback(sample_event, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-mock-valid-key")
    monkeypatch.setenv("LLM_PROVIDER", "groq")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "This is raw unformatted text without JSON"}}]
    }

    with patch("requests.post", return_value=mock_resp):
        provider = LlmRecoveryProvider(mode="llm_with_fallback")
        res = provider.get_recommendation(sample_event)

        assert res["status"] == "generated"
        assert res["fallback_triggered"] is True
        assert res["recovery_provider"] == "rule_based_fallback"


def test_llm_provider_strict_mode_raises(sample_event, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "groq")

    provider = LlmRecoveryProvider(mode="llm")
    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        provider.get_recommendation(sample_event)


def test_factory_function(monkeypatch):
    monkeypatch.setenv("RECOVERY_ENGINE", "rule_based")
    p1 = get_recovery_provider()
    assert isinstance(p1, RuleBasedRecoveryProvider)

    monkeypatch.setenv("RECOVERY_ENGINE", "llm_with_fallback")
    p2 = get_recovery_provider()
    assert isinstance(p2, LlmRecoveryProvider)
