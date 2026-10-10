# ChainForensics — Setup Guide

> **Audience:** A brand-new engineer with nothing installed. Follow every step in order.

---

## Prerequisites

| Tool | Required Version | Notes |
|---|---|---|
| Python | 3.11 or newer | 3.14.x is confirmed working |
| Node.js | 18 or newer | Required for Hardhat (smart contract compiler/node) |
| npm | 8 or newer | Ships with Node.js |
| Git | Any recent version | For cloning |

Verify before starting:
```bash
python --version   # Must be 3.11+
node --version     # Must be 18+
npm --version
```

---

## Step 1 — Clone the Repository

```bash
git clone <your-repo-url> ChainForensics
cd ChainForensics
```

---

## Step 2 — Create the Python Virtual Environment

```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

You should see `(.venv)` in your prompt before proceeding.

---

## Step 3 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs: numpy, pandas, scikit-learn, joblib, web3, FastAPI, uvicorn, SQLAlchemy, pydantic, python-dotenv, pytest, pytest-cov, httpx, flake8.

> **Windows note:** scikit-learn requires Visual C++ redistributables. If you get a DLL error on import, install the [Microsoft Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe) and retry.

---

## Step 4 — Install Node.js Dependencies (for Hardhat)

```bash
npm install
```

This installs Hardhat 3 and the Hardhat toolbox.

---

## Step 5 — Compile the Smart Contract

```bash
npm run hardhat:compile
```

Expected output: `Compiled 1 Solidity file successfully`. This generates `artifacts/contracts/ForensicLedger.sol/ForensicLedger.json` which the Python client reads for the ABI.

> **If this step is skipped**, the Python blockchain client will raise `FileNotFoundError: Hardhat contract artifact not found`.

---

## Step 6 — Configure Environment Variables

Copy the example template:

```bash
# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```

### Option A — Local Hardhat (development / offline)

Edit `.env`:

```ini
CHAINFORENSIS_RPC_URL=http://127.0.0.1:8545
CHAINFORENSIS_PRIVATE_KEY=<your-hardhat-account-private-key>
CHAINFORENSIS_CONTRACT_ADDRESS=<deployed-contract-address>
CHAINFORENSIS_API_KEY=<generate-a-strong-random-string>
```

With this option you must complete Steps 7 and 8 below.

### Option B — Ethereum Sepolia Testnet (recommended)

Edit `.env` with your QuickNode (or other provider) Sepolia endpoint:

```ini
CHAINFORENSIS_RPC_URL=https://<your-quicknode-endpoint>.quiknode.pro/<token>/
CHAINFORENSIS_PRIVATE_KEY=<your-wallet-private-key-with-test-eth>
CHAINFORENSIS_CONTRACT_ADDRESS=<deployed-ForensicLedger-address-on-sepolia>
CHAINFORENSIS_API_KEY=<generate-a-strong-random-string>
```

With this option you **skip Steps 7 and 8** — no local node is needed.

> **Note:** A working Sepolia deployment is already pre-configured in the project's `.env`. Contract address: `0xB12BB431DbfB42A2FDfF608aec09e8e7413dEc3C`. The wallet and QuickNode token in that file are for development use only and must be rotated before any production deployment.

**How to generate a secure API key:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

> **Never commit `.env` to version control.** It is listed in `.gitignore`.

---

## Step 7 — Start the Local Hardhat Node (Option A only — skip for Sepolia)

Open a **separate terminal window** (keep it running):

```bash
npm run hardhat:node
```

Expected output:
```
Started HTTP and WebSocket JSON-RPC server at http://127.0.0.1:8545/

Accounts
========
Account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (10000 ETH)
Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
...
```

Copy **Account #0**'s private key into `CHAINFORENSIS_PRIVATE_KEY` in `.env`.

---

## Step 8 — Deploy the Smart Contract (Option A only — skip for Sepolia)

In your original terminal (with the venv active):

```bash
npm run hardhat:deploy
```

Expected output:
```
ForensicLedger deployed to: 0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6
```

Copy the deployed address into `CHAINFORENSIS_CONTRACT_ADDRESS` in `.env`.

---

## Step 9 — Initialize the Database

```bash
python -m chainforensics.database.init_db
```

Expected output:
```
ChainForensics SQLite database initialized successfully.
```

This creates `chainforensics.db` with the `incidents` table.

---

## Step 10 — Run the Test Suite

```bash
# Run all non-blockchain-integration tests (these pass without Hardhat)
pytest tests/ --ignore=tests/test_blockchain_local.py \
              --ignore=tests/test_blockchain_duplicate.py \
              --ignore=tests/test_sprint4_integration.py \
              --ignore=tests/test_sprint5_real_persistence.py \
              -v

# Run the FULL suite including blockchain integration (requires Hardhat node from Step 7)
pytest tests/ -v
```

---

## Step 11 — Start the API Server

```bash
uvicorn chainforensics.api.main:app --reload --host 0.0.0.0 --port 8000
```

Verify it's running:
```bash
curl http://localhost:8000/health
# Expected: {"status":"ok","service":"ChainForensics API"}
```

Test authenticated access:
```bash
curl -H "x-api-key: <your-CHAINFORENSIS_API_KEY>" http://localhost:8000/incidents
# Expected: {"items":[],"total":0}
```

---

## Step 12 — Train a Detection Model (Optional — a pre-trained model is included)

If you have downloaded the CICIDS-2017 dataset to `data/raw/`:

```bash
python -m chainforensics.cli retrain data/raw/Monday-WorkingHours.pcap_ISCX.csv \
    --models-dir models \
    --logs-dir logs
```

The trained model is saved to `models/detector_v<timestamp>.joblib`. 

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `FileNotFoundError: Hardhat contract artifact not found` | Step 5 (compile) was skipped | Run `npm run hardhat:compile` |
| `ConnectionRefusedError` on blockchain calls | Hardhat node not running | Start with `npm run hardhat:node` in a separate terminal |
| `DLL load failed while importing` (Windows, sklearn) | Application Control policy blocking C extensions | Install [VC++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe); or contact your IT department about the Application Control policy |
| `API key is not configured` (HTTP 500) | `CHAINFORENSIS_API_KEY` not set in `.env` | Set the variable and restart the server |
| `Incident not found` on hash lookup | The incident hash was not persisted to DB | Ensure `create_incident()` was called before querying |
| `DuplicateHash` from blockchain | Same event logged twice | Each unique forensic event has a unique hash; check for duplicate submissions |
