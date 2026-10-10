from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from chainforensics.api.dependencies import get_db
from chainforensics.api.main import app
from chainforensics.database.models import Base
from chainforensics.simulator.cicids_scenarios import get_all_scenarios, get_scenario_by_id
from chainforensics.simulator.service import (
    execute_live_cicids_attack_and_ai_recovery,
    get_sepolia_network_status,
)


from sqlalchemy.pool import StaticPool

@pytest.fixture
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()


def test_cicids_scenarios_exist():
    scenarios = get_all_scenarios()
    assert len(scenarios) >= 6
    ids = [s["scenario_id"] for s in scenarios]
    assert "cicids-dos-hulk" in ids
    assert "cicids-portscan" in ids
    assert "cicids-ftp-patator" in ids
    assert "cicids-benign" in ids


def test_get_scenario_by_id():
    hulk = get_scenario_by_id("cicids-dos-hulk")
    assert hulk is not None
    assert hulk["attack_type"] == "DoS"
    assert "Flow Duration" in hulk["telemetry"]
    assert hulk["destination_port"] == 80

    missing = get_scenario_by_id("non-existent-id")
    assert missing is None


def test_sepolia_network_status_structure():
    status = get_sepolia_network_status()
    assert "connected" in status
    assert "network_name" in status
    assert "contract_address" in status
    assert "contract_etherscan_url" in status


def test_execute_simulation_benign_flow(test_db):
    res = execute_live_cicids_attack_and_ai_recovery(
        db=test_db,
        scenario_id="cicids-benign",
        commit_onchain=False,
    )
    assert res["success"] is True
    assert res["forensic_event"]["attack_type"] == "BENIGN"
    assert res["recovery_health_tracker"]["is_recovered"] is True
    assert res["recovery_health_tracker"]["enhanced_status"] == "fully_recovered"
    assert len(res["recovery_health_tracker"]["health_probes"]) == 3
    assert res["database"]["persisted"] is True


def test_execute_simulation_dos_hulk_with_ai_recovery(test_db):
    res = execute_live_cicids_attack_and_ai_recovery(
        db=test_db,
        scenario_id="cicids-dos-hulk",
        custom_intensity=400,
        commit_onchain=False,
    )
    assert res["success"] is True
    assert res["forensic_event"]["attack_type"] == "DoS"
    assert len(res["forensic_event"]["event_hash"]) == 64
    assert res["ai_recovery_intelligence"]["threat_level"] in ("HIGH", "CRITICAL")
    assert len(res["ai_recovery_intelligence"]["action_plan"]) > 0
    assert res["recovery_health_tracker"]["checks_total"] == 3


def test_api_list_scenarios(client):
    resp = client.get("/api/v2/simulator/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 6
    assert "dataset" in data
    assert any(s["scenario_id"] == "cicids-dos-hulk" for s in data["scenarios"])


def test_api_get_scenario_detail(client):
    resp = client.get("/api/v2/simulator/scenarios/cicids-portscan")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario"]["attack_type"] == "PortScan"
    assert data["scenario"]["severity"] == "MEDIUM"

    resp404 = client.get("/api/v2/simulator/scenarios/unknown-xyz")
    assert resp404.status_code == 404


def test_api_blockchain_status(client):
    resp = client.get("/api/v2/simulator/blockchain/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "network_name" in data
    assert "contract_address" in data


def test_api_execute_simulation_endpoint(client):
    payload = {
        "scenario_id": "cicids-dos-hulk",
        "custom_intensity": 350,
        "commit_onchain": False,
    }
    resp = client.post("/api/v2/simulator/execute", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "forensic_event" in data
    assert "ai_recovery_intelligence" in data
    assert "recovery_health_tracker" in data
    assert len(data["recovery_health_tracker"]["health_probes"]) == 3
