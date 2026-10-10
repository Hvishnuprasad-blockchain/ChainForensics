import hre from "hardhat";

async function main() {
    const { ethers } = await hre.network.connect();

    const contractAddress = "0xB12BB431DbfB42A2FDfF608aec09e8e7413dEc3C";

    const ledger = await ethers.getContractAt(
        "ForensicLedger",
        contractAddress
    );

    console.log("Connected to ForensicLedger:");
    console.log(await ledger.getAddress());

    // Test forensic SHA-256-style bytes32 value
    const testHash = ethers.keccak256(
        ethers.toUtf8Bytes("ChainForensics-Sepolia-Test-001")
    );

    console.log("\nTest hash:");
    console.log(testHash);

    // Check current count
    const beforeCount = await ledger.getEntryCount();
    console.log("\nEntries before:", beforeCount.toString());

    // ---------------------------------------------------------
    // WRITE
    // ---------------------------------------------------------

    console.log("\nSending logEvent transaction...");

    const tx = await ledger.logEvent(testHash);

    console.log("Transaction hash:");
    console.log(tx.hash);

    console.log("\nWaiting for confirmation...");

    const receipt = await tx.wait();

    console.log("Confirmed in block:");
    console.log(receipt.blockNumber);

    // ---------------------------------------------------------
    // READ
    // ---------------------------------------------------------

    const afterCount = await ledger.getEntryCount();

    console.log("\nEntries after:", afterCount.toString());

    const index = afterCount - 1n;

    const entry = await ledger.getEntry(index);

    console.log("\nRetrieved entry:");
    console.log("Hash:", entry[0]);
    console.log("Timestamp:", entry[1].toString());
    console.log("Recorder:", entry[2]);
    console.log("Recovery verified:", entry[3]);

    // ---------------------------------------------------------
    // VERIFY
    // ---------------------------------------------------------

    if (entry[0].toLowerCase() !== testHash.toLowerCase()) {
        throw new Error("HASH MISMATCH!");
    }

    console.log("\n=================================");
    console.log("SEPOLIA WRITE + READ TEST PASSED");
    console.log("=================================");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});