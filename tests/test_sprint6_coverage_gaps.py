"""
Sprint 6 — Coverage gap tests.

Targets modules that were below 80% after the full coverage run:

  chainforensics/api/incidents.py          46%  -> tests for the full
      detect pipeline (with blockchain mock) and duplicate-idempotency
  chainforensics/api/errors.py             64%  -> error handler paths
  chainforensics/api/dependencies.py       73%  -> auth edge cases
  chainforensics/api/dashboard.py          43%  -> /api/dashboard/stats

These are genuine business-logic gaps, not boilerplate padding.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from chainforensics.api.main import app
from chainforensics.api.dependencies import get_db, require_api_key
from chainforensics.api.errors import (
    create_correlation_id,
    generic_error_response,
    generic_exception_handler,
)
from chainforensics.database.database import Base


# ─────────────────────────────────────────────────────────────────────
# Shared fixtures
# ─────────────────────────────────────────────────────────────────────

@pytest.fixture()
def db_session(tmp_path):
    """Isolated in-memory SQLite DB for each test."""
    db_url = f"sqlite:///{tmp_path}/coverage_test.db"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def api_client(db_session):
    """FastAPI TestClient with DB override and API key set."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    api_key = os.environ.get("CHAINFORENSIS_API_KEY", "test-coverage-key")
    os.environ.setdefault("CHAINFORENSIS_API_KEY", api_key)

    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield client, api_key
    finally:
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────
# errors.py — generic_error_response and generic_exception_handler
# ─────────────────────────────────────────────────────────────────────

class TestErrorsModule:
    def test_create_correlation_id_is_uuid_string(self):
        """create_correlation_id must return a valid UUID string."""
        import uuid
        cid = create_correlation_id()
        assert isinstance(cid, str)
        uuid.UUID(cid)  # raises ValueError if invalid

    def test_generic_error_response_structure(self):
        """generic_error_response returns a JSONResponse with correct body."""
        resp = generic_error_response(status_code=422, correlation_id="test-cid")
        assert resp.status_code == 422
        import json
        body = json.loads(resp.body)
        assert body["error"] == "Request could not be completed."
        assert body["correlation_id"] == "test-cid"

    def test_generic_error_response_500(self):
        resp = generic_error_response(status_code=500, correlation_id="err-500")
        assert resp.status_code == 500

    def test_generic_exception_handler_returns_500(self):
        """generic_exception_handler swallows exception, returns 500 + correlation_id."""
        import asyncio
        import json
        from starlette.datastructures import URL

        mock_request = MagicMock()
        mock_request.method = "POST"
        mock_request.url = URL("http://testserver/incidents/detect")

        exc = RuntimeError("something went wrong")
        response = asyncio.run(generic_exception_handler(mock_request, exc))

        body = json.loads(response.body)
        assert response.status_code == 500
        assert body["error"] == "Request could not be completed."
        assert "correlation_id" in body

    def test_api_unhandled_exception_returns_500_not_traceback(self, api_client):
        """
        Trigger an unhandled server exception and confirm the API returns a safe
        JSON body rather than a raw Python traceback.
        """
        client, api_key = api_client
        headers = {"x-api-key": api_key}

        # Inject a broken DB dependency that raises
        def broken_db():
            raise RuntimeError("DB exploded for test")
            yield  # make it a generator

        app.dependency_overrides[get_db] = broken_db
        try:
            resp = client.get("/incidents", headers=headers)
            # Must NOT return 200 and must NOT expose stack trace
            assert resp.status_code in (500, 422, 503)
            body = resp.json()
            assert "traceback" not in str(body).lower()
            assert "RuntimeError" not in str(body)
        finally:
            # restore clean override
            app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────
# dependencies.py — auth edge cases
# ─────────────────────────────────────────────────────────────────────

class TestDependenciesAuth:
    def test_missing_api_key_header_returns_401(self, api_client):
        client, _ = api_client
        resp = client.get("/incidents")  # no x-api-key header
        assert resp.status_code == 401

    def test_wrong_api_key_returns_401(self, api_client):
        client, _ = api_client
        resp = client.get("/incidents", headers={"x-api-key": "WRONG-KEY-999"})
        assert resp.status_code == 401

    def test_correct_api_key_returns_200(self, api_client):
        client, api_key = api_client
        resp = client.get("/incidents", headers={"x-api-key": api_key})
        assert resp.status_code == 200

    def test_missing_server_api_key_env_returns_500(self, db_session):
        """If CHAINFORENSIS_API_KEY is not set server-side, return 500."""
        def override_get_db():
            try:
                yield db_session
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        try:
            # Temporarily remove the server-side key
            original = os.environ.pop("CHAINFORENSIS_API_KEY", None)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/incidents", headers={"x-api-key": "any-key"})
            assert resp.status_code == 500
        finally:
            if original is not None:
                os.environ["CHAINFORENSIS_API_KEY"] = original
            app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────
# api/incidents.py — process_traffic_detection with blockchain path
# ─────────────────────────────────────────────────────────────────────

class TestDetectEndpointCoverage:
    """
    Tests for POST /incidents/detect covering:
    - Successful new incident with mocked blockchain write
    - Idempotent duplicate (same flow_id -> cached response)
    - Validation error (bad payload)
    - Blockchain failure (graceful degradation)
    """

    VALID_PAYLOAD = {
        "flow_id": "coverage-test-001",
        "timestamp": "2026-09-30T12:00:00Z",
        "source": {"ip": "10.0.0.1", "port": 1111},
        "destination": {"ip": "10.0.0.2", "port": 80},
        "attack_type": "DoS",
        "confidence": 0.91,
        "raw_features": {"packet_count": 200},
    }

    def test_detect_new_incident_no_blockchain(self, api_client):
        """New incident without blockchain env set — persists off-chain, returns 201."""
        client, api_key = api_client
        headers = {"x-api-key": api_key}

        # Ensure blockchain env is absent
        with patch.dict(os.environ, {
            "CHAINFORENSIS_RPC_URL": "",
            "CHAINFORENSIS_PRIVATE_KEY": "",
            "CHAINFORENSIS_CONTRACT_ADDRESS": "",
        }):
            resp = client.post(
                "/incidents/detect",
                json=self.VALID_PAYLOAD,
                headers=headers,
            )

        assert resp.status_code == 201
        data = resp.json()
        assert "incident" in data
        assert data["incident"]["flow_id"] == "coverage-test-001"
        assert data["incident"]["attack_type"] == "DoS"
        assert data["incident"]["event_transaction_hash"] is None  # no blockchain

    def test_detect_duplicate_returns_cached(self, api_client):
        """Submitting same payload twice returns the first incident (idempotent)."""
        client, api_key = api_client
        headers = {"x-api-key": api_key}
        payload = {**self.VALID_PAYLOAD, "flow_id": "coverage-dup-001"}

        with patch.dict(os.environ, {
            "CHAINFORENSIS_RPC_URL": "",
            "CHAINFORENSIS_PRIVATE_KEY": "",
            "CHAINFORENSIS_CONTRACT_ADDRESS": "",
        }):
            resp1 = client.post("/incidents/detect", json=payload, headers=headers)
            resp2 = client.post("/incidents/detect", json=payload, headers=headers)

        assert resp1.status_code == 201
        # Duplicate returns from cache (200 or 201, same incident)
        assert resp2.status_code in (200, 201)
        assert resp1.json()["incident"]["event_hash"] == resp2.json()["incident"]["event_hash"]

    def test_detect_invalid_payload_returns_422(self, api_client):
        """Missing required fields return 422 Unprocessable Entity."""
        client, api_key = api_client
        headers = {"x-api-key": api_key}

        bad_payload = {"flow_id": "bad-001"}  # missing source, destination, etc.
        resp = client.post("/incidents/detect", json=bad_payload, headers=headers)
        assert resp.status_code == 422

    def test_detect_with_mocked_blockchain_write(self, api_client, db_session):
        """
        When blockchain env vars are present and BlockchainClient is mocked,
        the full blockchain+persistence path executes and incident stores tx_hash.
        """
        client, api_key = api_client
        headers = {"x-api-key": api_key}

        mock_write_result = MagicMock()
        mock_write_result.tx_hash = "0x" + "aa" * 32
        mock_write_result.block_number = 42
        mock_write_result.latency_seconds = 0.05

        mock_verify_result = MagicMock()
        mock_verify_result.tx_hash = "0x" + "bb" * 32
        mock_verify_result.block_number = 43
        mock_verify_result.latency_seconds = 0.03

        mock_client = MagicMock()
        mock_client.log_event.return_value = mock_write_result
        mock_client.get_entry_count.return_value = 1
        mock_client.get_entry.return_value = {
            "event_hash": bytes.fromhex(
                # We compute the hash in advance by using the same logic
                # No — just return a sentinel that won't match so the path
                # exercises the "index is None" branch and graceful fail
                "aa" * 32
            ),
            "timestamp": 1700000000,
            "recorder": "0x" + "00" * 20,
            "recovery_verified": False,
        }
        mock_client.mark_recovery_verified.return_value = mock_verify_result

        payload = {**self.VALID_PAYLOAD, "flow_id": "coverage-bc-001"}

        with patch.dict(os.environ, {
            "CHAINFORENSIS_RPC_URL": "http://fake-rpc:8545",
            "CHAINFORENSIS_PRIVATE_KEY": "0x" + "aa" * 32,
            "CHAINFORENSIS_CONTRACT_ADDRESS": "0x" + "bb" * 20,
        }):
            with patch(
                "chainforensics.api.incidents.BlockchainClient",
                return_value=mock_client,
            ):
                resp = client.post(
                    "/incidents/detect",
                    json=payload,
                    headers=headers,
                )

        assert resp.status_code == 201
        incident = resp.json()["incident"]
        assert incident["event_transaction_hash"] == "0x" + "aa" * 32
        assert incident["event_block_number"] == 42
        # verify mock was called
        mock_client.log_event.assert_called_once()

    def test_detect_blockchain_failure_degrades_gracefully(self, api_client):
        """
        If BlockchainClient.log_event raises, the incident is still persisted
        off-chain and the API returns 201 (not 500).
        """
        client, api_key = api_client
        headers = {"x-api-key": api_key}

        mock_client = MagicMock()
        mock_client.log_event.side_effect = ConnectionError("RPC unreachable")

        payload = {**self.VALID_PAYLOAD, "flow_id": "coverage-bc-fail-001"}

        with patch.dict(os.environ, {
            "CHAINFORENSIS_RPC_URL": "http://fake-rpc:8545",
            "CHAINFORENSIS_PRIVATE_KEY": "0x" + "aa" * 32,
            "CHAINFORENSIS_CONTRACT_ADDRESS": "0x" + "bb" * 20,
        }):
            with patch(
                "chainforensics.api.incidents.BlockchainClient",
                return_value=mock_client,
            ):
                resp = client.post(
                    "/incidents/detect",
                    json=payload,
                    headers=headers,
                )

        # The incident must be persisted even when blockchain fails
        assert resp.status_code == 201
        assert resp.json()["incident"]["event_transaction_hash"] is None


# ─────────────────────────────────────────────────────────────────────
# api/dashboard.py — /api/dashboard/stats data endpoint
# ─────────────────────────────────────────────────────────────────────

class TestDashboardStats:
    def test_dashboard_stats_no_auth_required(self, api_client):
        """
        /api/dashboard/stats is not behind API key auth — it returns 200
        with the correct structure even with zero incidents.
        """
        client, _ = api_client

        with patch("chainforensics.api.dashboard.Web3") as mock_w3_cls:
            mock_w3 = MagicMock()
            mock_w3.is_connected.return_value = False
            mock_w3_cls.return_value = mock_w3
            mock_w3_cls.HTTPProvider = MagicMock()

            resp = client.get("/api/dashboard/stats")

        assert resp.status_code == 200
        data = resp.json()
        assert "blockchain" in data
        assert "incidents" in data
        assert "base_metrics" in data
        assert data["incidents"]["total"] == 0
        assert data["blockchain"]["connected"] is False

    def test_dashboard_stats_with_incidents(self, api_client, db_session):
        """
        After inserting an incident, /api/dashboard/stats reflects
        updated totals.
        """
        from chainforensics.database.repository import create_incident
        from chainforensics.event_builder import build_forensic_event, hash_forensic_event

        client, api_key = api_client

        # Insert a test incident directly into db
        event = build_forensic_event(
            flow_id="dashboard-test-001",
            timestamp="2026-09-30T12:00:00Z",
            src_ip="1.2.3.4",
            src_port=1234,
            dst_ip="5.6.7.8",
            dst_port=80,
            attack_type="DoS",
            confidence=0.9,
            raw_features={"packet_count": 100},
        )
        event_hash = hash_forensic_event(event)
        create_incident(db_session, event=event, event_hash=event_hash)

        with patch("chainforensics.api.dashboard.Web3") as mock_w3_cls:
            mock_w3 = MagicMock()
            mock_w3.is_connected.return_value = False
            mock_w3_cls.return_value = mock_w3
            mock_w3_cls.HTTPProvider = MagicMock()

            resp = client.get("/api/dashboard/stats")

        assert resp.status_code == 200
        data = resp.json()
        assert data["incidents"]["total"] == 1

    def test_dashboard_html_root_returns_200(self, api_client):
        """The dashboard HTML page serves without error."""
        client, _ = api_client
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")


# ─────────────────────────────────────────────────────────────────────
# api/main.py — validation error handler path
# ─────────────────────────────────────────────────────────────────────

class TestValidationErrorHandler:
    def test_invalid_json_body_returns_safe_422(self, api_client):
        """
        A malformed request body should return 422 with the generic
        error format (not a raw pydantic exception).
        """
        client, api_key = api_client
        headers = {"x-api-key": api_key, "Content-Type": "application/json"}

        # confidence must be float in [0,1] — send a string to trigger validation
        bad_payload = {
            "flow_id": "val-test",
            "timestamp": "2026-09-30T12:00:00Z",
            "source": {"ip": "1.2.3.4", "port": 1234},
            "destination": {"ip": "5.6.7.8", "port": 80},
            "attack_type": "DoS",
            "confidence": "not-a-float",
            "raw_features": {},
        }
        resp = client.post(
            "/incidents/detect",
            json=bad_payload,
            headers=headers,
        )
        assert resp.status_code == 422
