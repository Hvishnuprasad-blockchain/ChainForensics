from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)


class DestinationEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)


class TrafficDetectionRequest(BaseModel):
    """
    Input payload for POST /detect.

    The API accepts the same core forensic-event structure
    used by the existing ChainForensics pipeline.
    """

    model_config = ConfigDict(extra="forbid")

    flow_id: str = Field(min_length=1, max_length=255)
    timestamp: str = Field(min_length=1, max_length=100)

    source: SourceEndpoint
    destination: DestinationEndpoint

    attack_type: str = Field(min_length=1, max_length=100)

    confidence: float = Field(ge=0.0, le=1.0)

    raw_features: dict[str, Any] = Field(
        default_factory=dict
    )

    @field_validator("flow_id")
    @classmethod
    def validate_flow_id(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("flow_id must not be empty")

        return value

    @field_validator("attack_type")
    @classmethod
    def validate_attack_type(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("attack_type must not be empty")

        return value


class IncidentResponse(BaseModel):
    """
    Public API representation of a persisted incident.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int

    flow_id: str
    timestamp: str

    source_ip: str
    source_port: int

    destination_ip: str
    destination_port: int

    attack_type: str
    confidence: float

    raw_features: dict[str, Any]

    event_hash: str

    detection_status: str

    event_transaction_hash: str | None = None
    event_block_number: int | None = None
    ledger_write_latency_seconds: float | None = None

    recovery_status: str | None = None
    recovery_reason: str | None = None
    recovery_entry_index: int | None = None
    recovery_transaction_hash: str | None = None
    recovery_verified: bool = False

    # v2 Additive telemetry
    threat_level: str | None = None
    threat_score: int | None = None
    recovery_provider: str | None = None
    enhanced_status: str | None = None


class ThreatDistributionResponse(BaseModel):
    """
    Response returned by GET /api/v2/threats/distribution.
    """
    distribution: dict[str, int]
    total_evaluated: int
    mean_threat_score: float


class IncidentListResponse(BaseModel):
    """
    Response returned by GET /incidents.
    """

    items: list[IncidentResponse]
    total: int



class IncidentReplayResponse(BaseModel):
    """
    Full replay response for one incident.
    """

    incident: IncidentResponse


class BaseMetricsResponse(BaseModel):
    """
    BASE framework metrics response.

    Values are calculated from persisted incident history.
    """

    total_detected: int

    ledger_write_latency_avg_seconds: float | None = None
    ledger_write_latency_min_seconds: float | None = None
    ledger_write_latency_max_seconds: float | None = None

    forensic_completeness_percent: float

    recovery_verification_rate_percent: float

    end_to_end_closed_loop_rate_percent: float


class ErrorResponse(BaseModel):
    """
    Generic API error response.

    correlation_id allows the server-side logs to be
    matched with the caller's failed request.
    """

    error: str
    correlation_id: str


class PreventedAttackResponse(BaseModel):
    """
    v2 Feature 5: Record of a proactively prevented attack.
    """
    id: int
    source_ip: str
    destination_ip: str
    destination_port: int
    attack_type: str
    prevented_at: str
    origin_incident_hash: str | None = None
    prevention_reason: str


class PreventedAttackListResponse(BaseModel):
    """
    Response returned by GET /api/v2/prevention/attacks.
    """
    items: list[PreventedAttackResponse]
    total: int


class ProactiveTrafficResponse(BaseModel):
    """
    Unified response for traffic processing: either proactively prevented or detected.
    """
    status: str  # "prevented" | "detected"
    prevented_attack: PreventedAttackResponse | None = None
    incident: IncidentResponse | None = None