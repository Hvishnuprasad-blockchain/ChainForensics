import hre from "hardhat";

async function main() {
    const { ethers } = await hre.network.connect();

    const ledger = await ethers.deployContract("ForensicLedger");

    await ledger.waitForDeployment();

    console.log(
        "ForensicLedger deployed to:",
        await ledger.getAddress()
    );
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});