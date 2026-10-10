from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from chainforensics.database.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ============================================================
    # Core forensic event
    # ============================================================

    flow_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    event_timestamp: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    source_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    source_port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    destination_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    destination_port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    attack_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    raw_features_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # ============================================================
    # Detection
    # ============================================================

    detection_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="detected",
    )

    explanation_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # ============================================================
    # Integrity / blockchain
    # ============================================================

    event_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    event_transaction_hash: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    event_block_number: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    ledger_write_latency_seconds: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    # ============================================================
    # Recovery
    # ============================================================

    recovery_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending",
    )

    recovery_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    recovery_entry_index: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    recovery_transaction_hash: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    recovery_verified: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
    )

    # ============================================================
    # v2 Additive telemetry
    # ============================================================

    threat_level: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    threat_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    recovery_provider: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    enhanced_status: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    # ============================================================
    # Persistence timestamps
    # ============================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


IncidentModel = Incident  # Alias for backward compatibility


class PreventedAttack(Base):
    """
    v2 Feature 5: Proactive Chain-Coordinated Attack Prevention Record.
    Stores traffic that was pre-emptively blocked based on on-chain confirmed threat registry.
    """
    __tablename__ = "prevented_attacks"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    source_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    destination_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    destination_port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    attack_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    prevented_at: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    origin_incident_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    prevention_reason: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )