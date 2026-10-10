import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.getOrCreate();
describe("ForensicLedger", function () {
  let ledger;
  let owner;
  let recorder;

  beforeEach(async function () {
    [owner, recorder] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory("ForensicLedger");

    ledger = await Factory.deploy();

    await ledger.waitForDeployment();
  });

  it("logs a valid event and reads it back", async function () {
    const eventHash = ethers.keccak256(
      ethers.toUtf8Bytes("event-001")
    );

    const tx = await ledger
      .connect(recorder)
      .logEvent(eventHash);

    const receipt = await tx.wait();

    expect(receipt.status).to.equal(1);

    const count = await ledger.getEntryCount();

    expect(count).to.equal(1n);

    const entry = await ledger.getEntry(0);

    expect(entry[0]).to.equal(eventHash);
    expect(entry[2]).to.equal(recorder.address);
    expect(entry[3]).to.equal(false);

    console.log(
      "Gas used for logEvent:",
      receipt.gasUsed.toString()
    );
  });

  it("rejects duplicate event hashes", async function () {
    const eventHash = ethers.keccak256(
      ethers.toUtf8Bytes("duplicate-event")
    );

    await ledger.logEvent(eventHash);

    await expect(
      ledger.logEvent(eventHash)
    ).to.be.revertedWithCustomError(
      ledger,
      "DuplicateHash"
    );
  });

  it("rejects an empty hash", async function () {
    await expect(
      ledger.logEvent(ethers.ZeroHash)
    ).to.be.revertedWithCustomError(
      ledger,
      "EmptyHash"
    );
  });

  it("rejects out-of-range reads", async function () {
    await expect(
      ledger.getEntry(0)
    ).to.be.revertedWithCustomError(
      ledger,
      "IndexOutOfBounds"
    );

    await expect(
      ledger.getEventHash(0)
    ).to.be.revertedWithCustomError(
      ledger,
      "IndexOutOfBounds"
    );

    await expect(
      ledger.isRecoveryVerified(0)
    ).to.be.revertedWithCustomError(
      ledger,
      "IndexOutOfBounds"
    );
  });

  it("rejects out-of-range recovery writes", async function () {
    await expect(
      ledger.markRecoveryVerified(0)
    ).to.be.revertedWithCustomError(
      ledger,
      "IndexOutOfBounds"
    );
  });

  it("marks recovery as verified", async function () {
    const eventHash = ethers.keccak256(
      ethers.toUtf8Bytes("recovery-event")
    );

    await ledger.logEvent(eventHash);

    await ledger.markRecoveryVerified(0);

    expect(
      await ledger.isRecoveryVerified(0)
    ).to.equal(true);
  });

  it("rejects recovery verification from a non-owner", async function () {
    const eventHash = ethers.keccak256(
      ethers.toUtf8Bytes("owner-test")
    );

    await ledger.logEvent(eventHash);

    await expect(
      ledger.connect(recorder).markRecoveryVerified(0)
    ).to.be.revertedWithCustomError(
      ledger,
      "NotOwner"
    );
  });
});