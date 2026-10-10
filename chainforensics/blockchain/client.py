from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

from web3 import Web3


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class BlockchainWriteResult:
    """
    Result of a synchronous blockchain write.
    """

    tx_hash: str
    block_number: int
    gas_used: int
    latency_seconds: float
    attempts: int


class BlockchainClient:
    """
    ChainForensics network-agnostic web3.py wrapper.

    NETWORK-AGNOSTIC DESIGN GUARANTEE:
    This exact code, completely unmodified, operates seamlessly against:
      - Local Hardhat / Ganache node (development & automated testing)
      - Ethereum Sepolia testnet (staging & live verification)
      - Mainnet or any EVM-compatible L1/L2 network

    Zero code changes are required when switching networks. The target network,
    signing identity, and contract deployment are supplied strictly via environment
    configuration (`CHAINFORENSIS_RPC_URL`, `CHAINFORENSIS_PRIVATE_KEY`, and
    `CHAINFORENSIS_CONTRACT_ADDRESS`).

    Capabilities:
      Sprint 2:
        - log_event(): Synchronous on-chain forensic hash logging with latency timing
        - get_entry(): Query forensic event record by ledger index
        - get_entry_count(): Total immutable events committed to the ledger
      Sprint 4:
        - mark_recovery_verified(): Owner-authorized recovery verification
    """

    def __init__(
        self,
        *,
        rpc_url: str,
        private_key: str,
        contract_address: str,
        contract_abi: list[dict[str, Any]],
        max_retries: int = 3,
        base_delay_seconds: float = 0.5,
    ) -> None:

        if not rpc_url:
            raise ValueError(
                "rpc_url must not be empty"
            )

        if not private_key:
            raise ValueError(
                "private_key must not be empty"
            )

        if not contract_address:
            raise ValueError(
                "contract_address must not be empty"
            )

        if max_retries < 0:
            raise ValueError(
                "max_retries must be >= 0"
            )

        if base_delay_seconds < 0:
            raise ValueError(
                "base_delay_seconds must be >= 0"
            )

        self.rpc_url = rpc_url
        self.max_retries = max_retries
        self.base_delay_seconds = base_delay_seconds

        # ---------------------------------------------------------
        # WEB3 CONNECTION
        # ---------------------------------------------------------

        self.web3 = Web3(
            Web3.HTTPProvider(rpc_url)
        )

        # ---------------------------------------------------------
        # ACCOUNT
        # ---------------------------------------------------------

        self.account = self.web3.eth.account.from_key(
            private_key
        )

        # ---------------------------------------------------------
        # CONTRACT
        # ---------------------------------------------------------

        self.contract_address = Web3.to_checksum_address(
            contract_address
        )

        self.contract = self.web3.eth.contract(
            address=self.contract_address,
            abi=contract_abi,
        )

        LOGGER.info(
            "BlockchainClient initialized: %s",
            self.account.address,
        )

    # =============================================================
    # RETRY HELPER
    # =============================================================

    def _with_retry(
        self,
        operation_name: str,
        operation: Callable[[], Any],
        *,
        event_context: str = "",
    ) -> Any:
        """
        Execute an RPC operation with exponential backoff.
        """

        total_attempts = self.max_retries + 1

        for attempt in range(
            1,
            total_attempts + 1,
        ):
            try:

                result = operation()

                LOGGER.debug(
                    "Blockchain operation succeeded: %s "
                    "attempt=%d/%d context=%s",
                    operation_name,
                    attempt,
                    total_attempts,
                    event_context,
                )

                return result

            except Exception as exc:

                if attempt >= total_attempts:

                    LOGGER.error(
                        "Blockchain operation failed: %s "
                        "attempts=%d context=%s error=%r",
                        operation_name,
                        attempt,
                        event_context,
                        exc,
                    )

                    raise

                delay = (
                    self.base_delay_seconds
                    * (2 ** (attempt - 1))
                )

                LOGGER.warning(
                    "Blockchain retry: %s "
                    "attempt=%d/%d "
                    "delay=%.3fs "
                    "error=%r",
                    operation_name,
                    attempt,
                    total_attempts,
                    delay,
                    exc,
                )

                time.sleep(delay)

        raise RuntimeError(
            "Retry loop terminated unexpectedly."
        )

    # =============================================================
    # GENERIC CONTRACT TRANSACTION
    # =============================================================

    def _send_contract_transaction(
        self,
        *,
        function: Any,
        operation_name: str,
        event_context: str = "",
    ) -> BlockchainWriteResult:
        """
        Build, sign, send and confirm a smart-contract transaction.
        """

        attempts_used = 0

        started = time.perf_counter()

        def submit_transaction():
            nonlocal attempts_used

            attempts_used += 1

            # -----------------------------------------------------
            # NONCE
            # -----------------------------------------------------

            nonce = self.web3.eth.get_transaction_count(
                self.account.address,
                "pending",
            )

            # -----------------------------------------------------
            # GAS
            # -----------------------------------------------------

            try:

                gas_estimate = function.estimate_gas(
                    {
                        "from": self.account.address,
                    }
                )

                gas_limit = int(
                    gas_estimate * 1.20
                )

            except Exception:

                # Safe fallback for Hardhat/Sepolia.
                gas_limit = 500_000

            # -----------------------------------------------------
            # BUILD TRANSACTION
            # -----------------------------------------------------

            # Add 25% priority buffer so transactions are mined in the immediate next block
            est_gas_price = self.web3.eth.gas_price
            effective_gas_price = max(int(est_gas_price * 1.25), 1_500_000_000)

            transaction = function.build_transaction(
                {
                    "from": self.account.address,
                    "nonce": nonce,
                    "chainId": self.web3.eth.chain_id,
                    "gas": gas_limit,
                    "gasPrice": effective_gas_price,
                }
            )

            # -----------------------------------------------------
            # SIGN
            # -----------------------------------------------------

            signed = self.account.sign_transaction(
                transaction
            )

            # -----------------------------------------------------
            # SEND
            # -----------------------------------------------------

            return self.web3.eth.send_raw_transaction(
                signed.raw_transaction
            )

        # ---------------------------------------------------------
        # SEND WITH RETRY
        # ---------------------------------------------------------

        tx_hash = self._with_retry(
            operation_name,
            submit_transaction,
            event_context=event_context,
        )

        # ---------------------------------------------------------
        # WAIT FOR RECEIPT
        # ---------------------------------------------------------

        receipt = self._with_retry(
            "wait_for_transaction_receipt",
            lambda: self.web3.eth.wait_for_transaction_receipt(
                tx_hash
            ),
            event_context=event_context,
        )

        latency = (
            time.perf_counter()
            - started
        )

        # ---------------------------------------------------------
        # VERIFY RECEIPT
        # ---------------------------------------------------------

        if receipt["status"] != 1:

            raise RuntimeError(
                f"Blockchain transaction reverted: "
                f"{tx_hash.hex()}"
            )

        result = BlockchainWriteResult(
            tx_hash=tx_hash.hex(),
            block_number=int(
                receipt["blockNumber"]
            ),
            gas_used=int(
                receipt["gasUsed"]
            ),
            latency_seconds=latency,
            attempts=attempts_used,
        )

        LOGGER.info(
            "Blockchain write successful: "
            "operation=%s "
            "tx=%s "
            "block=%d "
            "gas=%d "
            "latency=%.3fs "
            "attempts=%d",
            operation_name,
            result.tx_hash,
            result.block_number,
            result.gas_used,
            result.latency_seconds,
            result.attempts,
        )

        return result

    # =============================================================
    # READ: ENTRY COUNT
    # =============================================================

    def get_entry_count(self) -> int:
        """
        Return the number of forensic events stored on-chain.
        """

        result = self._with_retry(
            "getEntryCount",
            lambda: (
                self.contract
                .functions
                .getEntryCount()
                .call()
            ),
        )

        return int(result)

    # =============================================================
    # READ: ENTRY
    # =============================================================

    def get_entry(
        self,
        index: int,
    ) -> dict[str, Any]:
        """
        Read one forensic ledger entry.
        """

        if not isinstance(index, int):
            raise TypeError(
                "Entry index must be an integer."
            )

        if index < 0:
            raise ValueError(
                "Entry index cannot be negative."
            )

        count = self.get_entry_count()

        if index >= count:
            raise IndexError(
                f"Entry index {index} does not exist. "
                f"Current entry count: {count}"
            )

        result = self._with_retry(
            "getEntry",
            lambda: (
                self.contract
                .functions
                .getEntry(index)
                .call()
            ),
            event_context=f"index={index}",
        )

        return {
            "event_hash": result[0],
            "timestamp": int(result[1]),
            "recorder": result[2],
            "recovery_verified": bool(result[3]),
        }

    # =============================================================
    # SPRINT 2
    # WRITE FORENSIC EVENT
    # =============================================================

    def log_event(
        self,
        event_hash: str,
        *,
        event_context: str = "",
    ) -> BlockchainWriteResult:
        """
        Store a forensic SHA-256 hash on-chain.
        """

        if not isinstance(event_hash, str):
            raise TypeError(
                "event_hash must be a hexadecimal string."
            )

        normalized_hash = event_hash.strip()

        if normalized_hash.startswith("0x"):
            normalized_hash = normalized_hash[2:]

        if len(normalized_hash) != 64:
            raise ValueError(
                "event_hash must contain exactly "
                "64 hexadecimal characters."
            )

        try:

            event_hash_bytes = bytes.fromhex(
                normalized_hash
            )

        except ValueError as exc:

            raise ValueError(
                "event_hash contains "
                "non-hexadecimal characters."
            ) from exc

        if len(event_hash_bytes) != 32:
            raise ValueError(
                "event_hash must contain exactly 32 bytes."
            )

        function = (
            self.contract
            .functions
            .logEvent(
                event_hash_bytes
            )
        )

        return self._send_contract_transaction(
            function=function,
            operation_name="logEvent",
            event_context=(
                event_context
                or normalized_hash
            ),
        )

    # =============================================================
    # SPRINT 4
    # MARK RECOVERY VERIFIED
    # =============================================================

    def mark_recovery_verified(
        self,
        index: int,
    ) -> BlockchainWriteResult:
        """
        Permanently mark an existing forensic event
        as recovery verified.

        IMPORTANT:

        This method does NOT decide whether recovery succeeded.

        The Sprint 4 verifier makes that decision.

        This method only performs the actual:

            markRecoveryVerified(index)

        smart-contract transaction.
        """

        # ---------------------------------------------------------
        # VALIDATE INDEX TYPE
        # ---------------------------------------------------------

        if not isinstance(index, int):
            raise TypeError(
                "Recovery entry index must be an integer."
            )

        # ---------------------------------------------------------
        # VALIDATE INDEX VALUE
        # ---------------------------------------------------------

        if index < 0:
            raise ValueError(
                "Recovery entry index cannot be negative."
            )

        # ---------------------------------------------------------
        # VERIFY ENTRY EXISTS
        # ---------------------------------------------------------

        count = self.get_entry_count()

        if index >= count:
            raise IndexError(
                f"Cannot verify recovery for index {index}. "
                f"Only {count} ledger entries exist."
            )

        # ---------------------------------------------------------
        # BUILD SMART-CONTRACT CALL
        # ---------------------------------------------------------

        function = (
            self.contract
            .functions
            .markRecoveryVerified(
                index
            )
        )

        # ---------------------------------------------------------
        # SEND TRANSACTION
        # ---------------------------------------------------------

        return self._send_contract_transaction(
            function=function,
            operation_name="markRecoveryVerified",
            event_context=f"index={index}",
        )