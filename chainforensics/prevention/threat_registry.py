from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy.orm import Session

from chainforensics.database.models import Incident, PreventedAttack
from chainforensics.database.repository import create_prevented_attack

logger = logging.getLogger("chainforensics.prevention.threat_registry")


@dataclass(frozen=True)
class ThreatRecord:
    source_ip: str
    attack_type: str
    event_hash: str
    confirmed_on_chain: bool
    recovery_verified: bool
    incident_id: int


class ThreatRegistryService:
    """
    v2 Feature 5: Proactive Chain-Coordinated Attack Prevention.

    Architectural Design:
      - READ-ONLY against the smart contract / ledger.
      - Pulls confirmed malicious event hashes from the blockchain ledger
        (or verifies existing hashes via read-only smart contract checks).
      - Cross-references on-chain hashes with persisted forensic incidents to build
        an immutable, tamper-proof Known-Malicious-Source registry.
      - Any future traffic from a confirmed malicious source is pre-emptively
        blocked before completing another attack cycle.
    """

    def __init__(self, client: Any = None):
        self.client = client
        self._cache: dict[str, ThreatRecord] = {}

    def sync_from_ledger(self, db: Session) -> int:
        """
        Synchronize the threat registry by querying verified events.
        Performs read-only evaluation of confirmed ledger events.
        """
        verified_incidents = (
            db.query(Incident)
            .filter(
                Incident.attack_type != "BENIGN",
                (Incident.recovery_verified == True) | (Incident.event_transaction_hash.is_not(None)),  # noqa: E712
            )
            .all()
        )

        synced_count = 0
        for inc in verified_incidents:
            # If client is available, verify the hash exists on-chain via read-only call
            on_chain = bool(inc.event_transaction_hash)
            if self.client is not None and hasattr(self.client, "entry_hash_exists"):
                try:
                    on_chain = self.client.entry_hash_exists(inc.event_hash)
                except Exception as exc:
                    logger.debug("Read-only ledger check note: %s", exc)

            record = ThreatRecord(
                source_ip=inc.source_ip,
                attack_type=inc.attack_type,
                event_hash=inc.event_hash,
                confirmed_on_chain=on_chain,
                recovery_verified=bool(inc.recovery_verified),
                incident_id=inc.id,
            )
            self._cache[inc.source_ip] = record
            synced_count += 1

        logger.info("ThreatRegistry synced %d active threats from ledger records", synced_count)
        return synced_count

    def check_source_ip(self, source_ip: str, db: Optional[Session] = None) -> Optional[ThreatRecord]:
        """
        Check if a source IP is in the on-chain confirmed threat registry.
        """
        if not source_ip:
            return None

        # Check local in-memory registry
        if source_ip in self._cache:
            return self._cache[source_ip]

        # If not cached and db is provided, check directly
        if db is not None:
            match = (
                db.query(Incident)
                .filter(
                    Incident.source_ip == source_ip,
                    Incident.attack_type != "BENIGN",
                    (Incident.recovery_verified == True) | (Incident.event_transaction_hash.is_not(None)),  # noqa: E712
                )
                .first()
            )
            if match:
                record = ThreatRecord(
                    source_ip=match.source_ip,
                    attack_type=match.attack_type,
                    event_hash=match.event_hash,
                    confirmed_on_chain=bool(match.event_transaction_hash),
                    recovery_verified=bool(match.recovery_verified),
                    incident_id=match.id,
                )
                self._cache[source_ip] = record
                return record

        return None

    def prevent_if_threat(
        self,
        *,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        attack_type: str,
        timestamp: str,
        db: Session,
    ) -> Optional[PreventedAttack]:
        """
        Pre-processing step: If the source IP has a confirmed malicious event on-chain,
        pre-emptively block it and record in prevented_attacks.
        """
        threat = self.check_source_ip(source_ip, db=db)
        if threat is None:
            return None

        reason = (
            f"Pre-emptively blocked: Source {source_ip} is flagged in on-chain threat registry "
            f"(Origin incident: {threat.event_hash[:16]}..., attack: {threat.attack_type})"
        )

        prevented = create_prevented_attack(
            db,
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            attack_type=attack_type or threat.attack_type,
            prevented_at=timestamp,
            origin_incident_hash=threat.event_hash,
            prevention_reason=reason,
        )

        logger.warning("PROACTIVE PREVENTION TRIGGERED: %s blocked", source_ip)
        return prevented

    def get_all_registered_threats(self, db: Optional[Session] = None) -> list[dict[str, Any]]:
        """
        Return all currently registered threats for SOC dashboard inspection.
        """
        if db is not None and not self._cache:
            self.sync_from_ledger(db)

        return [
            {
                "source_ip": r.source_ip,
                "attack_type": r.attack_type,
                "origin_incident_hash": r.event_hash,
                "confirmed_on_chain": r.confirmed_on_chain,
                "recovery_verified": r.recovery_verified,
                "incident_id": r.incident_id,
            }
            for r in self._cache.values()
        ]


# Singleton default service
_default_threat_registry: Optional[ThreatRegistryService] = None


def get_threat_registry() -> ThreatRegistryService:
    global _default_threat_registry
    if _default_threat_registry is None:
        _default_threat_registry = ThreatRegistryService()
    return _default_threat_registry
