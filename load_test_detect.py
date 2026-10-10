"""
Sprint 5 -- Load Test: /detect endpoint (off-chain pipeline only)
=================================================================
Uses unittest.mock.patch.dict to forcibly blank blockchain env vars
before any code reads them, so no live Sepolia writes occur.

WHAT IS TESTED
--------------
  hashing -> ML explain -> recovery sim -> SQLite write (no blockchain)

WHAT IS NOT TESTED (INTENTIONALLY)
-----------------------------------
  Live Sepolia RPC calls. Each real blockchain write took 8-35 s in
  earlier runs (block confirmation dominated). That is the real
  production bottleneck, not this Python pipeline.

HOW TO RUN
----------
  cd "d:/project copy/ChainForensics"
  .venv\\Scripts\\python load_test_detect.py
"""

from __future__ import annotations

import json
import os
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from unittest.mock import patch

# ── Blank blockchain keys via patch.dict so they cannot be read ──────
_BLANK_BLOCKCHAIN = {
    "CHAINFORENSIS_RPC_URL": "",
    "CHAINFORENSIS_PRIVATE_KEY": "",
    "CHAINFORENSIS_CONTRACT_ADDRESS": "",
    "SEPOLIA_RPC_URL": "",
    "SEPOLIA_PRIVATE_KEY": "",
    "SEPOLIA_CONTRACT_ADDRESS": "",
}

# Apply the patch at module level — will stay active for the entire run
_env_patcher = patch.dict(os.environ, _BLANK_BLOCKCHAIN, clear=False)
_env_patcher.start()

# ── Now load dotenv for API key ONLY (override=False won't clobber blanks) ──
from dotenv import load_dotenv  # noqa: E402
load_dotenv(dotenv_path="d:/project copy/ChainForensics/.env", override=False)

# ── Import app AFTER patch is active ─────────────────────────────────
from fastapi.testclient import TestClient   # noqa: E402
from chainforensics.api.main import app     # noqa: E402

API_KEY = os.environ.get("CHAINFORENSIS_API_KEY", "test-key")
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

# ── Test configuration ────────────────────────────────────────────────
BURST_SIZES      = [1, 5, 10, 20, 40]  # concurrent workers per wave
REQUESTS_PER_BURST = 20                # total requests per wave
# ─────────────────────────────────────────────────────────────────────


def make_payload() -> dict[str, Any]:
    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": "2024-01-15T10:30:00Z",
        "source": {"ip": "192.168.1.100", "port": 54321},
        "destination": {"ip": "10.0.0.1", "port": 443},
        "attack_type": "DDoS",
        "confidence": 0.92,
        "raw_features": {
            "packet_count": 15000,
            "byte_count": 7340032,
            "duration_seconds": 30.5,
        },
    }


def single_request(client: TestClient, payload: dict, worker_id: int) -> dict:
    t0 = time.perf_counter()
    try:
        resp = client.post("/incidents/detect", headers=HEADERS, json=payload)
        elapsed = time.perf_counter() - t0
        return {
            "worker": worker_id,
            "status_code": resp.status_code,
            "ok": resp.status_code in (200, 201),
            "latency_ms": round(elapsed * 1000, 2),
            "error": None,
        }
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return {
            "worker": worker_id,
            "status_code": 0,
            "ok": False,
            "latency_ms": round(elapsed * 1000, 2),
            "error": str(exc),
        }


def run_burst(client: TestClient, concurrency: int, n_requests: int) -> dict:
    results: list[dict] = []
    payloads = [make_payload() for _ in range(n_requests)]

    wall_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(single_request, client, payloads[i], i): i
            for i in range(n_requests)
        }
        for fut in as_completed(futures):
            results.append(fut.result())
    wall_elapsed = time.perf_counter() - wall_start

    lats = sorted(r["latency_ms"] for r in results)
    ok   = [r for r in results if r["ok"]]
    fail = [r for r in results if not r["ok"]]

    def pct(p: float) -> float:
        return round(lats[max(0, int(p * len(lats)) - 1)], 1)

    return {
        "concurrency":      concurrency,
        "total_requests":   n_requests,
        "successes":        len(ok),
        "failures":         len(fail),
        "success_rate_pct": round(100 * len(ok) / n_requests, 1),
        "wall_time_s":      round(wall_elapsed, 3),
        "throughput_rps":   round(n_requests / wall_elapsed, 2),
        "latency_ms": {
            "min":  round(min(lats), 1),
            "max":  round(max(lats), 1),
            "mean": round(statistics.mean(lats), 1),
            "p50":  pct(0.50),
            "p95":  pct(0.95),
            "p99":  pct(0.99),
        },
        "failure_details": [
            {"worker": r["worker"], "status": r["status_code"], "err": r["error"]}
            for r in fail
        ],
    }


def main() -> None:
    SEP = "=" * 68

    print(f"\n{SEP}")
    print("  ChainForensics -- /detect Burst Load Test")
    print(SEP)

    rpc_val = os.environ.get("CHAINFORENSIS_RPC_URL", "(unset)")
    print(f"\n  Blockchain env patched: CHAINFORENSIS_RPC_URL='{rpc_val}'")
    assert not rpc_val, f"RPC_URL must be empty — got '{rpc_val}'"
    print("  Pipeline: hash -> ML explain -> recovery sim -> SQLite (no blockchain)\n")

    client = TestClient(app, raise_server_exceptions=False)
    all_results: list[dict] = []

    for concurrency in BURST_SIZES:
        print(
            f"  -> concurrency={concurrency:>2}  requests={REQUESTS_PER_BURST} ...",
            end="", flush=True,
        )
        result = run_burst(client, concurrency, REQUESTS_PER_BURST)
        all_results.append(result)
        print(" done.")
        lat = result["latency_ms"]
        print(
            f"     success={result['successes']}/{result['total_requests']} "
            f"wall={result['wall_time_s']}s  rps={result['throughput_rps']}  "
            f"p50={lat['p50']}ms p95={lat['p95']}ms p99={lat['p99']}ms"
        )
        if result["failures"]:
            print(f"     [!] Failures: {result['failure_details'][:3]}")

    # ── JSON report ───────────────────────────────────────────────────
    report_path = "d:/project copy/ChainForensics/load_test_report.json"
    with open(report_path, "w") as fh:
        json.dump({
            "test_scope": (
                "POST /incidents/detect — off-chain pipeline only. "
                "Blockchain env vars blanked via unittest.mock.patch.dict. "
                "No Sepolia RPC calls made."
            ),
            "disclaimer": (
                "IMPORTANT: This test does NOT reflect production latency. "
                "Live Sepolia writes in earlier runs took 8-35 s per request "
                "(dominated by block confirmation + QuickNode RPC latency). "
                "Nonce serialization limits concurrent Sepolia writes to ~1-2 req/min. "
                "This test only validates the off-chain Python/SQLite pipeline."
            ),
            "results": all_results,
        }, fh, indent=2)

    peak  = max(all_results, key=lambda r: r["throughput_rps"])
    worst = max(all_results, key=lambda r: r["latency_ms"]["p99"])
    total_fail = sum(r["failures"] for r in all_results)

    print(f"\n{SEP}")
    print("  HONEST FINDINGS")
    print(SEP)
    print(
        f"  Peak off-chain throughput : {peak['throughput_rps']} req/s "
        f"at concurrency={peak['concurrency']}"
    )
    print(
        f"  Worst p99 latency         : {worst['latency_ms']['p99']} ms "
        f"at concurrency={worst['concurrency']}"
    )
    print(f"  Total failures            : {total_fail}")
    print()
    print("  BOTTLENECKS (honest):")
    print("  [1] Python GIL: threads share interpreter lock -- CPU-bound work")
    print("      (ML inference, hashing) does not parallelize under threads.")
    print("      Latency rises with concurrency even with many workers.")
    print("  [2] SQLite single write-lock: concurrent DB inserts serialize.")
    print("      WAL journal mode would partially help; Postgres would scale better.")
    print("  [3] Sepolia blockchain (NOT in this test): 8-35 s per write observed.")
    print("      Nonce must increment serially per wallet. Practical limit: ~1-2 req/min.")
    print("      This is not a Python bottleneck -- it is a blockchain constraint.")
    print(f"\n  JSON report: {report_path}\n")


if __name__ == "__main__":
    main()
