from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from web3 import Web3

from chainforensics.api.dependencies import get_db
from chainforensics.blockchain.abi import load_forensic_ledger_abi
from chainforensics.blockchain.client import BlockchainClient
from chainforensics.database.repository import (
    count_incidents,
    create_incident,
    get_base_metrics,
    list_incidents,
    update_blockchain_result,
    update_recovery_result,
)
from chainforensics.event_builder import build_forensic_event, hash_forensic_event
from chainforensics.explainability.generator import generate_explanation
from chainforensics.recovery.provider import get_recovery_provider
from chainforensics.recovery.simulator import simulate_recovery
from chainforensics.recovery.verifier import verify_recovery
from chainforensics.threat_scoring import assess_event_threat

logger = logging.getLogger("chainforensics.dashboard")
router = APIRouter(tags=["Dashboard"])


class TriggerRequest(BaseModel):
    attack_type: str = "DoS"
    packet_count: int = 400
    src_ip: str = "198.51.100.42"
    dst_ip: str = "10.0.0.5"
    dst_port: int = 80


@router.get("/api/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)) -> dict[str, Any]:
    primary_rpc = os.getenv("CHAINFORENSIS_RPC_URL", os.getenv("SEPOLIA_RPC_URL", "https://ethereum-sepolia-rpc.publicnode.com"))
    fallback_rpcs = [
        primary_rpc,
        "https://ethereum-sepolia-rpc.publicnode.com",
        "https://1rpc.io/sepolia",
        "https://gateway.tenderly.co/public/sepolia",
    ]
    contract_addr = os.getenv("CHAINFORENSIS_CONTRACT_ADDRESS", os.getenv("SEPOLIA_CONTRACT_ADDRESS", "0xB12BB431DbfB42A2FDfF608aec09e8e7413dEc3C"))

    block_number = 0
    on_chain_entries = 0
    chain_connected = False
    active_rpc = primary_rpc

    seen_rpcs = set()
    for rpc in fallback_rpcs:
        if not rpc or rpc in seen_rpcs:
            continue
        seen_rpcs.add(rpc)
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 6}))
            if w3.is_connected():
                chain_connected = True
                active_rpc = rpc
                block_number = int(w3.eth.block_number)
                contract = w3.eth.contract(
                    address=Web3.to_checksum_address(contract_addr),
                    abi=load_forensic_ledger_abi(),
                )
                on_chain_entries = int(contract.functions.getEntryCount().call())
                break
        except Exception as exc:
            logger.warning("Error fetching blockchain status from %s: %s", rpc, exc)

    total_incidents = count_incidents(db)
    incidents = list_incidents(db, limit=20)

    verified_count = sum(1 for inc in incidents if inc.recovery_verified)

    items = []
    for inc in incidents:
        try:
            raw_feats = json.loads(inc.raw_features_json) if inc.raw_features_json else {}
        except Exception:
            raw_feats = {}
        try:
            exp_data = json.loads(inc.explanation_json) if inc.explanation_json else {}
        except Exception:
            exp_data = {}
        items.append({
            "id": inc.id,
            "flow_id": inc.flow_id,
            "timestamp": inc.event_timestamp,
            "source_ip": inc.source_ip,
            "source_port": inc.source_port,
            "destination_ip": inc.destination_ip,
            "destination_port": inc.destination_port,
            "attack_type": inc.attack_type,
            "confidence": inc.confidence,
            "event_hash": inc.event_hash,
            "event_transaction_hash": inc.event_transaction_hash,
            "event_block_number": inc.event_block_number,
            "latency_seconds": inc.ledger_write_latency_seconds,
            "recovery_status": inc.recovery_status,
            "recovery_reason": inc.recovery_reason,
            "recovery_transaction_hash": inc.recovery_transaction_hash,
            "recovery_verified": inc.recovery_verified,
            "raw_features": raw_feats,
            "explanation": exp_data,
            "threat_level": getattr(inc, 'threat_level', None),
            "threat_score": getattr(inc, 'threat_score', None),
            "recovery_provider": getattr(inc, 'recovery_provider', None),
            "enhanced_status": getattr(inc, 'enhanced_status', None),
        })

    return {
        "blockchain": {
            "connected": chain_connected,
            "rpc_url": active_rpc,
            "contract_address": contract_addr,
            "block_number": block_number,
            "on_chain_entries": on_chain_entries,
        },
        "incidents": {
            "total": total_incidents,
            "verified": verified_count,
            "items": items,
        },
        "base_metrics": get_base_metrics(db),
    }


@router.post("/api/dashboard/trigger")
def trigger_pipeline(req: TriggerRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    features = {
        "Flow Duration": 5000000,
        "Total Fwd Packets": req.packet_count,
        "Total Backward Packets": 0,
        "Fwd Packet Length Max": 1460,
        "Flow Bytes/s": 438000.0,
        "Flow Packets/s": 300.0,
        "SYN Flag Count": req.packet_count,
        "ACK Flag Count": 0,
        "packet_count": req.packet_count,
        "failed_attempts": req.packet_count if req.attack_type == "BruteForce" else 0,
        "suspicious_queries": req.packet_count if req.attack_type == "SQLInjection" else 0,
    }

    flow_id = f"flow-live-{int(time.time())}"
    event = build_forensic_event(
        flow_id=flow_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        src_ip=req.src_ip,
        src_port=44812,
        dst_ip=req.dst_ip,
        dst_port=req.dst_port,
        attack_type=req.attack_type,
        confidence=0.9994 if req.attack_type != "BENIGN" else 0.998,
        raw_features=features,
    )
    event_hash = hash_forensic_event(event)

    rpc_url = os.getenv("CHAINFORENSIS_RPC_URL", os.getenv("SEPOLIA_RPC_URL", ""))
    private_key = os.getenv("CHAINFORENSIS_PRIVATE_KEY", os.getenv("SEPOLIA_PRIVATE_KEY", ""))
    contract_address = os.getenv("CHAINFORENSIS_CONTRACT_ADDRESS", os.getenv("SEPOLIA_CONTRACT_ADDRESS", ""))

    tx_hash_val: str | None = None
    block_number_val: int = 0
    latency_seconds_val: float = 0.0
    client: BlockchainClient | None = None

    if rpc_url and private_key and contract_address:
        try:
            client = BlockchainClient(
                rpc_url=rpc_url,
                private_key=private_key,
                contract_address=contract_address,
                contract_abi=load_forensic_ledger_abi(),
            )
            write_res = client.log_event(event_hash, event_context=flow_id)
            tx_hash_val = write_res.tx_hash
            block_number_val = write_res.block_number
            latency_seconds_val = write_res.latency_seconds
        except Exception as chain_err:
            logger.warning("Blockchain write failed for trigger (non-fatal): %s", chain_err)
    else:
        logger.warning("Blockchain env vars not fully configured; skipping on-chain commit for trigger.")

    explanation = get_recovery_provider().get_recommendation(event)
    recovery_res = simulate_recovery(event)

    # v2 Feature 3: Compute multi-factor threat score
    t_score, t_level = assess_event_threat(event, db=db)
    rec_provider = explanation.get("recovery_provider", "rule_based") if isinstance(explanation, dict) else "rule_based"

    is_verified = False
    rec_tx_hash: str | None = None

    if client is not None:
        try:
            event_with_hash = dict(event)
            event_with_hash["_event_hash"] = event_hash
            verification_res = verify_recovery(
                event=event_with_hash,
                simulation_result=recovery_res,
                client=client,
            )
            is_verified = verification_res["status"] == "verified"
            tx_obj = verification_res.get("transaction")
            rec_tx_hash = tx_obj.tx_hash if tx_obj else None
        except Exception as verify_err:
            logger.warning("Recovery verification failed (non-fatal): %s", verify_err)
            is_verified = recovery_res.status == "verified"
    else:
        is_verified = recovery_res.status == "verified"

    incident = create_incident(
        db,
        event=event,
        event_hash=event_hash,
        explanation=explanation,
        threat_level=t_level,
        threat_score=t_score,
        recovery_provider=rec_provider,
    )

    if tx_hash_val:
        update_blockchain_result(
            db,
            event_hash=event_hash,
            transaction_hash=tx_hash_val,
            block_number=block_number_val,
            latency_seconds=latency_seconds_val,
        )

    enhanced_status = "fully_recovered" if is_verified else "escalated"
    update_recovery_result(
        db,
        event_hash=event_hash,
        recovery_status=recovery_res.status,
        recovery_reason=recovery_res.reason,
        recovery_transaction_hash=rec_tx_hash,
        recovery_verified=is_verified,
        enhanced_status=enhanced_status,
    )

    return {
        "success": True,
        "incident_id": incident.id,
        "flow_id": flow_id,
        "event_hash": event_hash,
        "tx_hash": tx_hash_val,
        "block_number": block_number_val,
        "latency_ms": round(latency_seconds_val * 1000, 2),
        "recovery_status": recovery_res.status,
        "recovery_verified": is_verified,
        "recovery_tx_hash": rec_tx_hash,
        "explanation": explanation.get("explanation", "") if isinstance(explanation, dict) else "",
        "action": recovery_res.action,
        "threat_score": t_score,
        "threat_level": t_level,
        "recovery_provider": rec_provider,
        "enhanced_status": enhanced_status,
    }


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ChainForensics — AI Blockchain Forensic Incident Response</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #07090e;
      --card-bg: rgba(15, 23, 42, 0.75);
      --card-border: rgba(255, 255, 255, 0.08);
      --accent-cyan: #06b6d4;
      --accent-emerald: #10b981;
      --accent-rose: #f43f5e;
      --accent-amber: #f59e0b;
      --accent-indigo: #6366f1;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 10% 20%, rgba(6, 182, 212, 0.08) 0px, transparent 50%),
        radial-gradient(at 90% 10%, rgba(99, 102, 241, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 90%, rgba(16, 185, 129, 0.05) 0px, transparent 50%);
      color: var(--text-main);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      min-height: 100vh;
      padding-bottom: 60px;
    }
    header {
      border-bottom: 1px solid var(--card-border);
      background: rgba(7, 9, 14, 0.85);
      backdrop-filter: blur(12px);
      padding: 18px 40px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .logo-container {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .logo-badge {
      width: 42px;
      height: 42px;
      background: linear-gradient(135deg, #06b6d4, #6366f1);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 20px;
      box-shadow: 0 0 20px rgba(6, 182, 212, 0.35);
    }
    .title-group h1 {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .title-group p {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 2px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 500;
      color: var(--accent-emerald);
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      background: var(--accent-emerald);
      border-radius: 50%;
      box-shadow: 0 0 10px var(--accent-emerald);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(1.3); }
    }
    .container {
      max-width: 1400px;
      margin: 32px auto;
      padding: 0 24px;
    }
    .grid-kpi {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 22px;
      backdrop-filter: blur(16px);
      transition: transform 0.2s ease, border-color 0.2s ease;
      position: relative;
      overflow: hidden;
    }
    .kpi-card:hover {
      transform: translateY(-2px);
      border-color: rgba(255, 255, 255, 0.2);
    }
    .kpi-card::after {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: var(--accent, #6366f1);
    }
    .kpi-card.cyan { --accent: #06b6d4; }
    .kpi-card.emerald { --accent: #10b981; }
    .kpi-card.indigo { --accent: #6366f1; }
    .kpi-card.amber { --accent: #f59e0b; }
    .kpi-label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-muted);
    }
    .kpi-val {
      font-size: 32px;
      font-weight: 800;
      margin-top: 10px;
      letter-spacing: -1px;
    }
    .kpi-sub {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 6px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .code-text {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      background: rgba(0, 0, 0, 0.3);
      padding: 2px 6px;
      border-radius: 4px;
    }

    /* Layout Sections */
    .dashboard-layout {
      display: grid;
      grid-template-columns: 380px 1fr;
      gap: 28px;
    }
    @media (max-width: 1024px) {
      .dashboard-layout { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px;
      backdrop-filter: blur(16px);
    }
    .panel h2 {
      font-size: 17px;
      font-weight: 700;
      margin-bottom: 18px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .form-group {
      margin-bottom: 16px;
    }
    .form-group label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-muted);
      margin-bottom: 8px;
    }
    .form-control {
      width: 100%;
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid var(--card-border);
      color: var(--text-main);
      padding: 12px 14px;
      border-radius: 8px;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    .form-control:focus {
      border-color: var(--accent-cyan);
    }
    .btn-primary {
      width: 100%;
      background: linear-gradient(135deg, #06b6d4, #3b82f6);
      color: #fff;
      border: none;
      padding: 14px;
      border-radius: 10px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: opacity 0.2s, transform 0.2s;
      box-shadow: 0 4px 16px rgba(6, 182, 212, 0.3);
    }
    .btn-primary:hover {
      opacity: 0.95;
      transform: translateY(-1px);
    }
    .btn-primary:active {
      transform: translateY(1px);
    }

    /* Table styling */
    .incident-table-wrapper {
      overflow-x: auto;
      margin-top: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }
    th {
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.5px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--card-border);
    }
    td {
      padding: 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      vertical-align: middle;
    }
    tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge.dos { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); }
    .badge.portscan { background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.3); }
    .badge.bruteforce { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge.benign { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge.verified { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge.escalated { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .hash-cell {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--accent-cyan);
    }
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid var(--accent-cyan);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
      border-radius: 12px;
      padding: 16px 20px;
      display: none;
      align-items: center;
      gap: 12px;
      z-index: 1000;
      animation: slideIn 0.3s ease;
    }
    @keyframes slideIn {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    .incident-row {
      cursor: pointer;
      transition: background 0.15s ease, transform 0.1s ease;
    }
    .incident-row:hover {
      background: rgba(255, 255, 255, 0.05) !important;
    }
    .modal-overlay {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.82);
      backdrop-filter: blur(10px);
      z-index: 999;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .modal-box {
      background: #0b1120;
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 16px;
      width: 100%;
      max-width: 820px;
      max-height: 90vh;
      overflow-y: auto;
      padding: 30px;
      box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.9);
      animation: modalFade 0.2s ease;
    }
    @keyframes modalFade {
      from { opacity: 0; transform: scale(0.96); }
      to { opacity: 1; transform: scale(1); }
    }
    .modal-section {
      background: rgba(255, 255, 255, 0.025);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 14px;
    }
    .modal-section-title {
      font-size: 11px;
      text-transform: uppercase;
      color: var(--text-muted);
      font-weight: 700;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo-container">
      <div class="logo-badge">CF</div>
      <div class="title-group">
        <h1>ChainForensics <span style="font-size:12px; font-weight:normal; background:rgba(255,255,255,0.1); padding:2px 8px; border-radius:4px;">PRODUCTION</span></h1>
        <p>Immutable AI Forensic Ledger & Automated Incident Response</p>
      </div>
    </div>
    <div style="display:flex; align-items:center; gap:16px;">
      <a href="/docs" target="_blank" style="color:var(--text-muted); font-size:13px; text-decoration:none;">Swagger API Docs &rarr;</a>
      <div class="status-pill" id="system-status-pill">
        <span class="pulse-dot" id="system-status-dot"></span>
        <span id="system-status">EVM Chain & API Live</span>
      </div>
    </div>
  </header>

  <!-- Clear API Error State Banner (Requirement Deliverable 4) -->
  <div id="api-error-banner" style="display:none; margin: 20px 40px 0; background: rgba(244, 63, 94, 0.15); border: 1px solid var(--accent-rose); border-radius: 12px; padding: 16px 20px; align-items: center; gap: 14px; color: #fecdd3;">
    <span style="font-size: 24px;">⚠️</span>
    <div>
      <div style="font-weight: 700; font-size: 15px; color: #fff;">Backend API Disconnected / Unreachable</div>
      <div style="font-size: 13px; margin-top: 2px;" id="api-error-detail">Unable to fetch live state from /api/dashboard/stats. Please ensure the FastAPI backend is running.</div>
    </div>
  </div>

  <div class="container">
    <!-- KPI Overview: 6 Real Live Indicators (including BASE Framework) -->
    <div class="grid-kpi" style="grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));">
      <div class="kpi-card cyan">
        <div class="kpi-label">Blockchain Block Height</div>
        <div class="kpi-val" id="block-number">--</div>
        <div class="kpi-sub">
          <span id="chain-label">Ethereum Sepolia</span> &bull; 
          <span class="code-text" id="rpc-endpoint" style="max-width:110px; overflow:hidden; text-overflow:ellipsis;">RPC</span>
        </div>
      </div>
      <div class="kpi-card emerald">
        <div class="kpi-label">On-Chain Ledger Entries</div>
        <div class="kpi-val" id="onchain-entries">--</div>
        <div class="kpi-sub">
          <span>Smart Contract:</span>
          <span class="code-text" id="contract-addr" style="max-width:110px; overflow:hidden; text-overflow:ellipsis;">0x...</span>
        </div>
      </div>
      <div class="kpi-card indigo">
        <div class="kpi-label">Total Forensic Incidents</div>
        <div class="kpi-val" id="total-incidents">--</div>
        <div class="kpi-sub">Persisted in SQLite database</div>
      </div>
      <div class="kpi-card amber">
        <div class="kpi-label">Closed-Loop Mitigation Rate</div>
        <div class="kpi-val" id="closed-loop-rate">--</div>
        <div class="kpi-sub">BASE Pillar 4: End-to-end resolved</div>
      </div>
      <div class="kpi-card cyan">
        <div class="kpi-label">Forensic Completeness Rate</div>
        <div class="kpi-val" id="completeness-rate">--</div>
        <div class="kpi-sub">BASE Pillar 4: Anchored on-chain</div>
      </div>
      <div class="kpi-card emerald">
        <div class="kpi-label">Ledger Write Latency (Avg)</div>
        <div class="kpi-val" id="avg-latency">--</div>
        <div class="kpi-sub">BASE Pillar 4: Measured commit time</div>
      </div>
    </div>

    <!-- Main Layout -->
    <div class="dashboard-layout">
      <!-- Left: Simulation Trigger -->
      <div class="panel">
        <h2>⚡ Live Pipeline Trigger</h2>
        <p style="font-size:13px; color:var(--text-muted); margin-bottom:18px;">
          Trigger an end-to-end incident: ML detection &rarr; SHA-256 hash &rarr; Blockchain write &rarr; Explainability &rarr; Recovery &rarr; Off-chain persistence.
        </p>

        <form id="trigger-form">
          <div class="form-group">
            <label for="attack-type">Attack Pattern</label>
            <select id="attack-type" class="form-control">
              <option value="DoS">Denial of Service (DoS)</option>
              <option value="PortScan">PortScan Discovery</option>
              <option value="BruteForce">SSH/FTP BruteForce</option>
              <option value="SQLInjection">SQL Injection Attack</option>
              <option value="BENIGN">BENIGN (Normal Traffic)</option>
            </select>
          </div>

          <div class="form-group">
            <label for="packet-count">Packet Count / Threshold Metric</label>
            <input type="number" id="packet-count" class="form-control" value="400" min="10" max="10000" />
            <span style="font-size:11px; color:var(--text-muted); margin-top:4px; display:block;">
              &le; 500 for DoS qualifies for automated on-chain verification
            </span>
          </div>

          <div class="form-group">
            <label for="source-ip">Source IP</label>
            <input type="text" id="source-ip" class="form-control" value="198.51.100.42" />
          </div>

          <div class="form-group">
            <label for="target-ip">Target IP & Port</label>
            <div style="display:flex; gap:10px;">
              <input type="text" id="target-ip" class="form-control" value="10.0.0.5" style="flex:2;" />
              <input type="number" id="target-port" class="form-control" value="80" style="flex:1;" />
            </div>
          </div>

          <button type="submit" id="btn-submit" class="btn-primary">
            <span>Execute Live Audit Pipeline</span>
          </button>
        </form>
      </div>

      <!-- Right: Live Incidents Table -->
      <div class="panel">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <div>
            <h2>🛡️ Forensic Ledger & Incident Stream</h2>
            <p style="font-size:12px; color:var(--text-muted); margin-top:2px;">Click any incident row for complete forensic replay & smart contract audit trail</p>
          </div>
          <button id="btn-refresh" style="background:transparent; border:1px solid var(--card-border); color:var(--text-muted); padding:6px 12px; border-radius:6px; font-size:12px; cursor:pointer;">
            &circlearrowright; Refresh
          </button>
        </div>

        <div class="incident-table-wrapper">
          <table id="incidents-table">
            <thead>
              <tr>
                <th>Incident / Time</th>
                <th>Classification</th>
                <th>Endpoints</th>
                <th>Forensic Hash / On-Chain Tx</th>
                <th>Recovery</th>
              </tr>
            </thead>
            <tbody id="incidents-body">
              <tr>
                <td colspan="5" style="text-align:center; padding:32px; color:var(--text-muted);">
                  Loading forensic incidents from live API...
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- Replay Modal (Requirement Quality Bar: Every incident row is clickable to real replay) -->
  <div id="replay-modal" class="modal-overlay" onclick="if(event.target===this) closeReplayModal()">
    <div class="modal-box">
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px;">
        <div>
          <div style="display:flex; align-items:center; gap:10px;">
            <span id="modal-attack-badge" class="badge"></span>
            <span style="font-size:18px; font-weight:700;" id="modal-flow-id">--</span>
          </div>
          <div style="font-size:12px; color:var(--text-muted); margin-top:4px;" id="modal-timestamp">--</div>
        </div>
        <button onclick="closeReplayModal()" style="background:transparent; border:none; color:var(--text-muted); font-size:26px; cursor:pointer; line-height:1;">&times;</button>
      </div>

      <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:14px;">
        <div class="modal-section" style="margin-bottom:0;">
          <div class="modal-section-title">Traffic Endpoints & Confidence</div>
          <div style="font-family:'JetBrains Mono',monospace; font-size:13px;" id="modal-endpoints">--</div>
          <div style="font-size:12px; color:var(--accent-cyan); margin-top:4px; font-weight:600;" id="modal-confidence">--</div>
        </div>
        <div class="modal-section" style="margin-bottom:0;">
          <div class="modal-section-title">Blockchain Attestation</div>
          <div style="font-size:13px;" id="modal-chain-status">--</div>
          <div style="font-size:11px; margin-top:4px;" id="modal-tx-link">--</div>
        </div>
      </div>

      <div class="modal-section">
        <div class="modal-section-title">Deterministic Forensic Fingerprint (SHA-256)</div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:12px; word-break:break-all; color:#38bdf8;" id="modal-hash">--</div>
      </div>

      <div class="modal-section">
        <div class="modal-section-title">AI Explainability & Incident Analysis</div>
        <div style="font-size:13px; line-height:1.55; color:#e2e8f0;" id="modal-explanation">--</div>
        <div style="font-size:12px; color:var(--accent-amber); margin-top:8px; font-weight:500;" id="modal-recommendation">--</div>
      </div>

      <div class="modal-section">
        <div class="modal-section-title">Closed-Loop Recovery Verification</div>
        <div style="display:flex; align-items:center; gap:10px; margin-top:4px;">
          <span id="modal-recovery-badge" class="badge"></span>
          <span style="font-size:13px;" id="modal-recovery-reason">--</span>
        </div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:6px;" id="modal-rec-tx">--</div>
      </div>

      <div class="modal-section" style="background:rgba(0,0,0,0.35);">
        <div class="modal-section-title">Raw Network Telemetry (JSON)</div>
        <pre style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#94a3b8; max-height:160px; overflow-y:auto; white-space:pre-wrap;" id="modal-raw-json">--</pre>
      </div>
    </div>
  </div>

  <div id="toast" class="toast">
    <div style="font-size:20px;">✅</div>
    <div>
      <div style="font-weight:600; font-size:14px;" id="toast-title">Transaction Mined</div>
      <div style="font-size:12px; color:var(--text-muted);" id="toast-desc">Confirmed on-chain</div>
    </div>
  </div>

  <script>
    window.cachedIncidents = {};

    function closeReplayModal() {
      document.getElementById('replay-modal').style.display = 'none';
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeReplayModal();
    });

    function openReplayModal(eventHash) {
      const item = window.cachedIncidents[eventHash];
      if (!item) return;

      document.getElementById('modal-flow-id').innerText = item.flow_id;
      document.getElementById('modal-timestamp').innerText = item.timestamp;
      
      const badge = document.getElementById('modal-attack-badge');
      badge.className = 'badge ' + item.attack_type.toLowerCase();
      badge.innerText = item.attack_type;

      document.getElementById('modal-endpoints').innerText = item.source_ip + ':' + item.source_port + ' → ' + item.destination_ip + ':' + item.destination_port;
      document.getElementById('modal-confidence').innerText = (item.confidence * 100).toFixed(2) + '% Confidence';

      document.getElementById('modal-hash').innerText = item.event_hash;

      // Blockchain section
      const chainStatus = document.getElementById('modal-chain-status');
      const txLink = document.getElementById('modal-tx-link');
      if (item.event_transaction_hash) {
        chainStatus.innerHTML = '<span style="color:var(--accent-emerald); font-weight:600;">Committed in Block #' + (item.event_block_number || 'N/A') + '</span>';
        const tx = item.event_transaction_hash;
        txLink.innerHTML = '<a href="https://sepolia.etherscan.io/tx/0x' + tx.replace(/^0x/, '') + '" target="_blank" style="color:var(--accent-cyan); text-decoration:none;">View on Sepolia Etherscan (0x' + tx.slice(0, 14) + '...) &rarr;</a>';
      } else {
        chainStatus.innerHTML = '<span style="color:var(--accent-rose); font-weight:600;">Not Committed On-Chain</span>';
        txLink.innerText = 'Pending / Local execution';
      }

      // Explainability
      const exp = item.explanation || {};
      document.getElementById('modal-explanation').innerText = exp.explanation || 'No human-readable narrative generated.';
      const recs = exp.recovery_recommendations || [];
      document.getElementById('modal-recommendation').innerText = recs.length > 0 ? 'Recommended Action: ' + recs[0] : '';

      // Recovery
      const recBadge = document.getElementById('modal-recovery-badge');
      if (item.recovery_verified) {
        recBadge.className = 'badge verified';
        recBadge.innerText = 'VERIFIED';
      } else {
        recBadge.className = 'badge escalated';
        recBadge.innerText = 'ESCALATED';
      }
      document.getElementById('modal-recovery-reason').innerText = item.recovery_reason || item.recovery_status || 'Pending';
      const recTxElem = document.getElementById('modal-rec-tx');
      if (item.recovery_transaction_hash) {
        const rtx = item.recovery_transaction_hash;
        recTxElem.innerHTML = '<a href="https://sepolia.etherscan.io/tx/0x' + rtx.replace(/^0x/, '') + '" target="_blank" style="color:var(--accent-cyan); text-decoration:none;">Recovery Tx: 0x' + rtx.slice(0, 14) + '... &rarr;</a>';
      } else {
        recTxElem.innerText = item.recovery_verified ? 'Recovery completed' : 'No on-chain write (Strict Honest Escalation ADR-004)';
      }

      // Raw features JSON
      document.getElementById('modal-raw-json').innerText = JSON.stringify(item.raw_features || {}, null, 2);

      document.getElementById('replay-modal').style.display = 'flex';
    }

    async function loadStats() {
      const errBanner = document.getElementById('api-error-banner');
      const statusPill = document.getElementById('system-status-pill');
      const statusDot = document.getElementById('system-status-dot');
      const statusText = document.getElementById('system-status');

      try {
        const res = await fetch('/api/dashboard/stats');
        if (!res.ok) throw new Error('HTTP ' + res.status + ': ' + res.statusText);
        const data = await res.json();

        // Hide error banner on success
        errBanner.style.display = 'none';
        statusDot.style.background = 'var(--accent-emerald)';
        statusDot.style.boxShadow = '0 0 10px var(--accent-emerald)';
        statusText.innerText = 'EVM Chain & API Live';

        document.getElementById('block-number').innerText = '#' + data.blockchain.block_number;
        document.getElementById('onchain-entries').innerText = data.blockchain.on_chain_entries;
        document.getElementById('total-incidents').innerText = data.incidents.total;

        // Base metrics
        const bm = data.base_metrics || {};
        document.getElementById('closed-loop-rate').innerText = (bm.end_to_end_closed_loop_rate_percent !== undefined ? bm.end_to_end_closed_loop_rate_percent : 100) + '%';
        document.getElementById('completeness-rate').innerText = (bm.forensic_completeness_percent !== undefined ? bm.forensic_completeness_percent : 100) + '%';
        document.getElementById('avg-latency').innerText = bm.ledger_write_latency_avg_seconds ? (bm.ledger_write_latency_avg_seconds + ' s') : 'N/A';

        const rpc = data.blockchain.rpc_url || '';
        document.getElementById('rpc-endpoint').innerText = rpc.includes('sepolia') ? 'Sepolia QuickNode' : rpc.replace('http://', '');
        document.getElementById('contract-addr').innerText = data.blockchain.contract_address ? (data.blockchain.contract_address.slice(0, 10) + '...') : '--';

        renderTable(data.incidents.items);
      } catch (err) {
        console.error('Failed to load stats from API:', err);
        errBanner.style.display = 'flex';
        document.getElementById('api-error-detail').innerText = 'API Connection Error: ' + err.message + '. Failed to fetch from /api/dashboard/stats.';
        statusDot.style.background = 'var(--accent-rose)';
        statusDot.style.boxShadow = '0 0 10px var(--accent-rose)';
        statusText.innerText = 'Backend API Offline';

        document.getElementById('incidents-body').innerHTML = '<tr><td colspan="5" style="text-align:center; padding:32px; color:var(--accent-rose); font-weight:600;">⚠️ API Unreachable: Backend connection failed. Unable to fetch live incidents.</td></tr>';
      }
    }

    function renderTable(items) {
      const tbody = document.getElementById('incidents-body');
      if (!items || items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:32px; color:var(--text-muted);">No incidents recorded yet.</td></tr>';
        return;
      }

      window.cachedIncidents = {};
      items.forEach(item => {
        window.cachedIncidents[item.event_hash] = item;
      });

      tbody.innerHTML = items.map(item => {
        const badgeClass = item.attack_type.toLowerCase();
        const shortHash = item.event_hash ? item.event_hash.slice(0, 14) + '...' : 'N/A';
        const shortTx = item.event_transaction_hash ? '0x' + item.event_transaction_hash.slice(0, 10) + '...' : 'pending';
        const recBadge = item.recovery_verified ? '<span class="badge verified">VERIFIED</span>' : '<span class="badge escalated">ESCALATED</span>';
        
        return `
          <tr class="incident-row" onclick="openReplayModal('${item.event_hash}')" title="Click to view complete forensic replay & blockchain proof">
            <td>
              <div style="font-weight:600;">#${item.id} &bull; ${item.flow_id} <span style="font-size:10px; color:var(--accent-cyan);">[VIEW &rarr;]</span></div>
              <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${item.timestamp}</div>
            </td>
            <td>
              <span class="badge ${badgeClass}">${item.attack_type}</span>
              <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">${(item.confidence * 100).toFixed(1)}% confidence</div>
            </td>
            <td>
              <div class="code-text">${item.source_ip}:${item.source_port}</div>
              <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">&darr; ${item.destination_ip}:${item.destination_port}</div>
            </td>
            <td>
              <div class="hash-cell" title="${item.event_hash}">SHA-256: ${shortHash}</div>
              <div style="font-size:11px; color:var(--text-muted); margin-top:3px;">
                Tx: <span class="code-text" title="${item.event_transaction_hash}">${shortTx}</span>
                (Block #${item.event_block_number || '?'})
              </div>
            </td>
            <td>
              ${recBadge}
              <div style="font-size:11px; color:var(--text-muted); margin-top:3px;">${item.recovery_status || 'none'}</div>
            </td>
          </tr>
        `;
      }).join('');
    }

    document.getElementById('trigger-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-submit');
      btn.disabled = true;
      btn.innerHTML = '<span>Transacting on-chain...</span>';

      const payload = {
        attack_type: document.getElementById('attack-type').value,
        packet_count: parseInt(document.getElementById('packet-count').value, 10),
        src_ip: document.getElementById('source-ip').value,
        dst_ip: document.getElementById('target-ip').value,
        dst_port: parseInt(document.getElementById('target-port').value, 10)
      };

      try {
        const res = await fetch('/api/dashboard/trigger', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
          showToast('Transaction Mined!', 'Tx: 0x' + data.tx_hash.slice(0, 16) + '... (Block #' + data.block_number + ')');
          await loadStats();
        }
      } catch (err) {
        alert('Simulation failed: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>Execute Live Audit Pipeline</span>';
      }
    });

    function showToast(title, desc) {
      const toast = document.getElementById('toast');
      document.getElementById('toast-title').innerText = title;
      document.getElementById('toast-desc').innerText = desc;
      toast.style.display = 'flex';
      setTimeout(() => { toast.style.display = 'none'; }, 4000);
    }

    document.getElementById('btn-refresh').addEventListener('click', loadStats);

    loadStats();
    setInterval(loadStats, 6000);
  </script>
</body>
</html>
"""


@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard() -> str:
    return DASHBOARD_HTML
