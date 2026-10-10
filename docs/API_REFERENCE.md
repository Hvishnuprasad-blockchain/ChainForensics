# ChainForensics API Reference

> **Version:** 1.0.0  
> **Base URL:** `http://localhost:8000`  
> **Network:** Ethereum Sepolia (contract `0xB12BB431DbfB42A2FDfF608aec09e8e7413dEc3C`)

All endpoints except `GET /health` and `GET /` require the `x-api-key` header.

---

## Authentication

Every protected endpoint requires:

```
x-api-key: <CHAINFORENSIS_API_KEY value>
```

Missing or invalid keys return:

```json
HTTP 401
{"error": "Request could not be completed.", "correlation_id": "<uuid>"}
```

If `CHAINFORENSIS_API_KEY` is not configured on the server:

```json
HTTP 500
{"error": "Request could not be completed.", "correlation_id": "<uuid>"}
```

The API key is compared using `secrets.compare_digest()` (constant-time, timing-attack resistant).

---

## Endpoints

### `GET /health`

Public. Returns service status.

**Response 200:**
```json
{
  "status": "ok",
  "service": "ChainForensics API"
}
```

---

### `GET /protected-health`

Authenticated. Returns service status with auth confirmation.

**Response 200:**
```json
{
  "status": "ok",
  "service": "ChainForensics API",
  "authentication": "api-key"
}
```

---

### `POST /incidents/detect`

Submit a network flow for real-time forensic detection.

**Pipeline executed per request:**
1. Canonicalize event → compute SHA-256 hash
2. Check for duplicate (idempotent — returns cached result if same hash already stored)
3. Generate AI explanation
4. Simulate recovery
5. Write event hash to Sepolia blockchain (if env configured) and verify recovery on-chain
6. Persist full incident to SQLite

**Request body:**
```json
{
  "flow_id": "CF-FLOW-001",
  "timestamp": "2026-09-30T12:00:00Z",
  "source": {"ip": "10.0.0.99", "port": 54321},
  "destination": {"ip": "192.168.1.10", "port": 80},
  "attack_type": "DoS",
  "confidence": 0.95,
  "raw_features": {
    "packet_count": 300,
    "flow_duration": 5000
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `flow_id` | string | ✅ | Unique identifier for the network flow |
| `timestamp` | ISO-8601 string | ✅ | Event timestamp |
| `source.ip` | string | ✅ | Source IPv4 address |
| `source.port` | int 1–65535 | ✅ | Source port |
| `destination.ip` | string | ✅ | Destination IPv4 address |
| `destination.port` | int 1–65535 | ✅ | Destination port |
| `attack_type` | string | ✅ | Attack class (`BENIGN`, `DoS`, `PortScan`, `BruteForce`, or unknown) |
| `confidence` | float 0.0–1.0 | ✅ | Model confidence score |
| `raw_features` | object | ✅ | Network flow features used for detection |

**Response 201 (new incident):**
```json
{
  "incident": {
    "id": 1,
    "flow_id": "CF-FLOW-001",
    "event_hash": "a3f9b2c1...(64 hex chars)",
    "attack_type": "DoS",
    "confidence": 0.95,
    "recovery_status": "verified",
    "recovery_verified": true,
    "event_transaction_hash": "0xd1e23fd6...",
    "event_block_number": 11814200
  }
}
```

**Response 200 (duplicate — idempotent):** Same body as 201, from cache.

> **Honest note on latency:** When Sepolia blockchain writes are enabled, each `POST /detect` call blocks until a block is confirmed (~8–35 s observed). Off-chain-only latency (blockchain env absent) is ~22–600 ms depending on concurrency.

---

### `GET /incidents`

List all persisted forensic incidents, with optional filters.

**Query Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `attack_type` | string | — | Filter by attack type (`BENIGN`, `DoS`, `PortScan`, `BruteForce`) |
| `detection_status` | string | — | Filter by detection status (e.g., `detected`) |
| `recovery_status` | string | — | Filter by recovery status (`pending`, `verified`, `escalated`) |
| `limit` | int | 100 | Results per page (1–500) |
| `offset` | int | 0 | Pagination offset |

**Response 200:**
```json
{
  "items": [
    {
      "id": 1,
      "flow_id": "CF-FLOW-001",
      "timestamp": "2026-09-30T12:00:00Z",
      "source_ip": "10.0.0.99",
      "source_port": 54321,
      "destination_ip": "192.168.1.10",
      "destination_port": 80,
      "attack_type": "DoS",
      "confidence": 0.95,
      "raw_features": {"packet_count": 300},
      "event_hash": "a3f9b2c1...(64 hex chars)",
      "detection_status": "detected",
      "event_transaction_hash": "0xd1e23fd6....",
      "event_block_number": 11814200,
      "ledger_write_latency_seconds": 8.219,
      "recovery_status": "verified",
      "recovery_reason": "Simulated verification succeeded because packet_count=300 is within the recovery threshold of 500.",
      "recovery_entry_index": 0,
      "recovery_transaction_hash": "0xef12....",
      "recovery_verified": true
    }
  ],
  "total": 1
}
```

---

### `GET /incidents/{event_hash}`

Retrieve one complete incident by its SHA-256 event hash.

**Path Parameters:**

| Parameter | Description |
|---|---|
| `event_hash` | 64-character hex SHA-256 hash of the forensic event |

**Response 200:**
```json
{
  "incident": { ... }
}
```

**Response 404:**
```json
{"detail": "Incident not found."}
```

---

### `GET /metrics`  &  `GET /metrics/base`

Both routes return the same BASE framework metrics calculated from all persisted incident history.

**Response 200:**
```json
{
  "total_incidents": 5,
  "forensic_completeness": 0.8,
  "recovery_verification_rate": 0.6,
  "avg_ledger_write_latency_seconds": 12.5,
  "closed_loop_rate": 0.6
}
```

| Field | Formula |
|---|---|
| `forensic_completeness` | `count(event_tx_hash IS NOT NULL) / total_incidents` |
| `recovery_verification_rate` | `count(recovery_verified=True) / total_incidents` |
| `avg_ledger_write_latency_seconds` | Mean of `ledger_write_latency_seconds` across blockchain-confirmed incidents |
| `closed_loop_rate` | `count(event_tx_hash IS NOT NULL AND recovery_verified=True) / total_incidents` |

---

### `GET /api/dashboard/stats`

Public (no API key required). Returns live backend state for the dashboard UI.

**Response 200:**
```json
{
  "blockchain": {
    "connected": true,
    "rpc_url": "https://...",
    "contract_address": "0xB12BB...",
    "block_number": 11814200,
    "on_chain_entries": 3
  },
  "incidents": {
    "total": 3,
    "verified": 2,
    "items": [...]
  },
  "base_metrics": { ... }
}
```

---

### `GET /`

Public. Serves the live dashboard HTML (browser UI).

---

## Incident Field Reference

| Field | Type | Description |
|---|---|---|
| `id` | int | Auto-incremented DB primary key |
| `flow_id` | string | Unique identifier for the network flow |
| `timestamp` | string | ISO-8601 timestamp of the event |
| `source_ip` / `source_port` | string / int | Traffic origin |
| `destination_ip` / `destination_port` | string / int | Traffic target |
| `attack_type` | string | Detected class: `BENIGN`, `DoS`, `PortScan`, `BruteForce` |
| `confidence` | float | Model confidence score [0.0, 1.0] |
| `raw_features` | object | Network flow features submitted with the event |
| `event_hash` | string | SHA-256 of the canonical forensic event (64 hex chars) |
| `detection_status` | string | Always `detected` for ingested events |
| `event_transaction_hash` | string \| null | Sepolia TX hash from `logEvent()` call |
| `event_block_number` | int \| null | Sepolia block number where event was mined |
| `ledger_write_latency_seconds` | float \| null | Time from TX submission to receipt confirmation |
| `recovery_status` | string | `pending`, `verified`, or `escalated` |
| `recovery_reason` | string \| null | Human-readable reason for recovery outcome |
| `recovery_entry_index` | int \| null | On-chain ledger index (verified recoveries only) |
| `recovery_transaction_hash` | string \| null | TX hash of `markRecoveryVerified()` call |
| `recovery_verified` | bool | `true` only when recovery was confirmed on-chain |

---

## Error Response Format

All errors return:
```json
{
  "error": "Request could not be completed.",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

The `correlation_id` matches the server log entry for debugging. No internal exception details are ever returned to callers.

---

## Example — Full cURL Session

```bash
# 1. Health check (no auth required)
curl http://localhost:8000/health

# 2. Submit a traffic detection event
curl -X POST http://localhost:8000/incidents/detect \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "flow_id": "flow-001",
    "timestamp": "2026-09-30T12:00:00Z",
    "source": {"ip": "10.0.0.1", "port": 54321},
    "destination": {"ip": "192.168.1.1", "port": 80},
    "attack_type": "DoS",
    "confidence": 0.95,
    "raw_features": {"packet_count": 300}
  }'

# 3. List all incidents
curl -H "x-api-key: YOUR_API_KEY" http://localhost:8000/incidents

# 4. Filter by attack type and recovery status
curl -H "x-api-key: YOUR_API_KEY" \
     "http://localhost:8000/incidents?attack_type=DoS&recovery_status=verified"

# 5. Get BASE framework metrics
curl -H "x-api-key: YOUR_API_KEY" http://localhost:8000/metrics

# 6. Get single incident by hash
curl -H "x-api-key: YOUR_API_KEY" \
     "http://localhost:8000/incidents/a3f9b2c1...64chars..."
```
