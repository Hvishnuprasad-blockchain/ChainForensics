import os
import time

from chainforensics.event_builder import (
    build_forensic_event,
    hash_forensic_event,
)
from chainforensics.blockchain.abi import load_forensic_ledger_abi
from chainforensics.blockchain.client import BlockchainClient


CONTRACT_ADDRESS = "0xB12BB431DbfB42A2FDfF608aec09e8e7413dEc3C"


def load_env_file():
    """Load values from local .env without printing secrets."""
    env_path = ".env"

    if not os.path.exists(env_path):
        raise FileNotFoundError(".env file not found")

    with open(env_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)

            if key and value:
                os.environ[key.strip()] = value.strip()


def main():

    print("=" * 60)
    print("CHAINFORENSICS PYTHON -> SEPOLIA INTEGRATION TEST")
    print("=" * 60)

    # =========================================================
    # 1. LOAD ENVIRONMENT
    # =========================================================

    load_env_file()

    rpc_url = os.environ.get("SEPOLIA_RPC_URL")
    private_key = os.environ.get("SEPOLIA_PRIVATE_KEY")

    if not rpc_url:
        raise RuntimeError("SEPOLIA_RPC_URL is missing")

    if not private_key:
        raise RuntimeError("SEPOLIA_PRIVATE_KEY is missing")

    print("\n[1/6] Environment loaded")

    # =========================================================
    # 2. BUILD REAL FORENSIC EVENT
    # =========================================================

    event = build_forensic_event(
        flow_id=f"CF-SEPOLIA-{int(time.time())}",
        timestamp=time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime()
        ),
        src_ip="192.168.1.100",
        src_port=49152,
        dst_ip="10.0.0.25",
        dst_port=443,
        attack_type="PortScan",
        confidence=0.97,
        raw_features={
            "packet_count": 150,
            "flow_duration": 2.41,
            "destination_port": 443,
        },
    )

    print("[2/6] Forensic event created")
    print("      Flow ID:", event["flow_id"])
    print("      Attack:", event["attack_type"])

    # =========================================================
    # 3. GENERATE REAL SHA-256
    # =========================================================

    event_hash = hash_forensic_event(event)

    print("[3/6] REAL SHA-256 generated")
    print("      Hash:", event_hash)
    print("      Length:", len(event_hash))

    if len(event_hash) != 64:
        raise RuntimeError(
            "Invalid SHA-256 length. Expected 64 hexadecimal characters."
        )

    # =========================================================
    # 4. CONNECT TO SEPOLIA
    # =========================================================

    abi = load_forensic_ledger_abi()

    client = BlockchainClient(
        rpc_url=rpc_url,
        private_key=private_key,
        contract_address=CONTRACT_ADDRESS,
        contract_abi=abi,
    )

    print("[4/6] Connected to Sepolia")
    print("      Wallet:", client.account.address)
    print("      Contract:", CONTRACT_ADDRESS)

    # =========================================================
    # 5. WRITE REAL FORENSIC SHA-256 TO SEPOLIA
    # =========================================================

    print("\n[5/6] Writing forensic hash to Sepolia...")

    result = client.log_event(
        event_hash,
        event_context=event["flow_id"],
    )

    print("      Transaction:", result.tx_hash)
    print("      Block:", result.block_number)
    print("      Gas used:", result.gas_used)
    print(
        "      Latency:",
        f"{result.latency_seconds:.3f}s"
    )
    print("      Attempts:", result.attempts)

    # =========================================================
    # 6. READ BACK AND VERIFY
    # =========================================================

    print("\n[6/6] Reading entry back from Sepolia...")

    count = client.get_entry_count()

    if count == 0:
        raise RuntimeError(
            "Blockchain contains no ledger entries."
        )

    index = count - 1

    entry = client.get_entry(index)

    blockchain_hash = entry["event_hash"]

    print("      Entry index:", index)
    print("      Blockchain hash:", blockchain_hash)
    print("      Recorder:", entry["recorder"])
    print(
        "      Recovery verified:",
        entry["recovery_verified"]
    )

    # =========================================================
    # CONVERT BLOCKCHAIN bytes32 -> HEX STRING
    # =========================================================

    if isinstance(blockchain_hash, bytes):
        blockchain_hash_hex = blockchain_hash.hex()
    else:
        blockchain_hash_hex = str(blockchain_hash)

        if blockchain_hash_hex.startswith("0x"):
            blockchain_hash_hex = blockchain_hash_hex[2:]

    # Remove 0x from Python hash if present
    expected_hash = event_hash.lower().replace("0x", "")

    actual_hash = blockchain_hash_hex.lower().replace("0x", "")

    print("\n      Expected SHA-256:")
    print("      ", expected_hash)

    print("\n      Blockchain hash:")
    print("      ", actual_hash)

    # =========================================================
    # FINAL HASH VERIFICATION
    # =========================================================

    if actual_hash != expected_hash:
        raise RuntimeError(
            "\nHASH MISMATCH!\n"
            f"Python SHA-256: {expected_hash}\n"
            f"Blockchain:     {actual_hash}"
        )

    # =========================================================
    # SUCCESS
    # =========================================================

    print("\n" + "=" * 60)
    print("✅ PYTHON SHA-256 -> SEPOLIA VERIFICATION PASSED")
    print("=" * 60)

    print("\nSprint 2 blockchain pipeline:")

    print("Python forensic event       ✅")
    print("Canonical JSON              ✅")
    print("SHA-256                     ✅")
    print("Python Web3 client          ✅")
    print("Sepolia connection          ✅")
    print("Sepolia transaction         ✅")
    print("On-chain storage            ✅")
    print("Read-back verification      ✅")
    print("Hash equality               ✅")


if __name__ == "__main__":
    main()