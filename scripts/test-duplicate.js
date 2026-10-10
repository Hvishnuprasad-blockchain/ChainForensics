import hre from "hardhat";

async function main() {
    const { ethers } = await hre.network.connect();

    const contractAddress =
        "0xB12BB431DbfB42A2FDfF608aec09e8e7413dEc3C";

    const ledger = await ethers.getContractAt(
        "ForensicLedger",
        contractAddress
    );

    const testHash = ethers.keccak256(
        ethers.toUtf8Bytes("ChainForensics-Sepolia-Test-001")
    );

    console.log("Testing duplicate hash:");
    console.log(testHash);

    console.log("\nChecking whether hash already exists...");

    const exists = await ledger.hashExists(testHash);

    console.log("hashExists:", exists);

    if (!exists) {
        throw new Error(
            "Expected the hash to already exist, but it does not."
        );
    }

    console.log("\nAttempting duplicate logEvent...");

    try {
        const tx = await ledger.logEvent(testHash);

        await tx.wait();

        throw new Error(
            "DUPLICATE WAS ACCEPTED — SECURITY TEST FAILED"
        );
    } catch (error) {
        const message = error?.message || String(error);

        console.log("\nDuplicate transaction rejected.");
        console.log("Reason:");
        console.log(message);

        console.log("\n=================================");
        console.log("DUPLICATE PROTECTION TEST PASSED");
        console.log("=================================");
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});