const { expect }      = require("chai");
const { ethers }      = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

describe("DocVerifier", function () {

  // ─── Shared fixture ───────────────────────────────────────────────────────
  // Deploys a fresh contract before each test that calls loadFixture().

  async function deployFixture() {
    const [owner, issuer, stranger] = await ethers.getSigners();
    const DocVerifier = await ethers.getContractFactory("DocVerifier");
    const contract    = await DocVerifier.deploy();
    return { contract, owner, issuer, stranger };
  }

  // Deterministic sample hash — represents "the SHA-256 of some document"
  const SAMPLE_HASH = ethers.keccak256(ethers.toUtf8Bytes("sample-document-content"));
  const SAMPLE_IPFS = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

  // ─── Deployment ───────────────────────────────────────────────────────────

  describe("Deployment", function () {
    it("sets the deployer as owner", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      expect(await contract.owner()).to.equal(owner.address);
    });
  });

  // ─── anchorDocument ───────────────────────────────────────────────────────

  describe("anchorDocument", function () {
    it("stores the issuer, timestamp, and IPFS hash on-chain", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);

      const doc = await contract.documents(SAMPLE_HASH);
      expect(doc.issuer).to.equal(issuer.address);
      expect(doc.timestamp).to.be.gt(0);
      expect(doc.ipfsHash).to.equal(SAMPLE_IPFS);
      expect(doc.revoked).to.be.false;
    });

    it("emits DocumentAnchored with docHash and issuer indexed", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      await expect(contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS))
        .to.emit(contract, "DocumentAnchored")
        .withArgs(SAMPLE_HASH, issuer.address);
    });

    it("reverts when the same hash is anchored a second time", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);
      await expect(
        contract.connect(issuer).anchorDocument(SAMPLE_HASH, "different-ipfs")
      ).to.be.revertedWith("Document already verified.");
    });

    it("allows different hashes to be anchored independently", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      const hashB = ethers.keccak256(ethers.toUtf8Bytes("another-document"));
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);
      await expect(
        contract.connect(issuer).anchorDocument(hashB, "ipfs://other")
      ).to.not.be.reverted;
    });
  });

  // ─── verifyDocument ───────────────────────────────────────────────────────

  describe("verifyDocument", function () {
    it("returns issuer, timestamp, and ipfsHash for a registered document", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);

      const [retIssuer, retTs, retIpfs] = await contract.verifyDocument(SAMPLE_HASH);
      expect(retIssuer).to.equal(issuer.address);
      expect(retTs).to.be.gt(0n);
      expect(retIpfs).to.equal(SAMPLE_IPFS);
    });

    it("reverts for an unknown hash", async function () {
      const { contract } = await loadFixture(deployFixture);
      const unknownHash = ethers.keccak256(ethers.toUtf8Bytes("does-not-exist"));
      await expect(
        contract.verifyDocument(unknownHash)
      ).to.be.revertedWith("Document not verified.");
    });
  });

  // ─── revokeDocument ───────────────────────────────────────────────────────

  describe("revokeDocument", function () {
    it("issuer can revoke their own document", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);
      await expect(contract.connect(issuer).revokeDocument(SAMPLE_HASH))
        .to.emit(contract, "DocumentRevoked")
        .withArgs(SAMPLE_HASH, issuer.address);
    });

    it("sets revoked flag to true after revocation", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);
      await contract.connect(issuer).revokeDocument(SAMPLE_HASH);
      expect(await contract.isRevoked(SAMPLE_HASH)).to.be.true;
    });

    it("reverts when a non-issuer tries to revoke", async function () {
      const { contract, issuer, stranger } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);
      await expect(
        contract.connect(stranger).revokeDocument(SAMPLE_HASH)
      ).to.be.revertedWith("Only the document issuer can revoke.");
    });

    it("reverts when revoking an already-revoked document", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);
      await contract.connect(issuer).revokeDocument(SAMPLE_HASH);
      await expect(
        contract.connect(issuer).revokeDocument(SAMPLE_HASH)
      ).to.be.revertedWith("Document already revoked.");
    });

    it("reverts when revoking a hash that was never anchored", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      const unregistered = ethers.keccak256(ethers.toUtf8Bytes("never-registered"));
      await expect(
        contract.connect(issuer).revokeDocument(unregistered)
      ).to.be.revertedWith("Document not found.");
    });

    it("owner cannot revoke documents issued by others", async function () {
      const { contract, owner, issuer } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);
      await expect(
        contract.connect(owner).revokeDocument(SAMPLE_HASH)
      ).to.be.revertedWith("Only the document issuer can revoke.");
    });

    it("multiple issuers can each revoke their own documents", async function () {
      const { contract, issuer, stranger } = await loadFixture(deployFixture);
      const hash1 = ethers.keccak256(ethers.toUtf8Bytes("doc-1"));
      const hash2 = ethers.keccak256(ethers.toUtf8Bytes("doc-2"));

      await contract.connect(issuer).anchorDocument(hash1, SAMPLE_IPFS);
      await contract.connect(stranger).anchorDocument(hash2, SAMPLE_IPFS);

      // Each can revoke their own
      await expect(contract.connect(issuer).revokeDocument(hash1)).to.not.be.reverted;
      await expect(contract.connect(stranger).revokeDocument(hash2)).to.not.be.reverted;

      expect(await contract.isRevoked(hash1)).to.be.true;
      expect(await contract.isRevoked(hash2)).to.be.true;
    });
  });

  // ─── isRevoked ────────────────────────────────────────────────────────────

  describe("isRevoked", function () {
    it("returns false for a valid (non-revoked) document", async function () {
      const { contract, issuer } = await loadFixture(deployFixture);
      await contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS);
      expect(await contract.isRevoked(SAMPLE_HASH)).to.be.false;
    });

    it("returns false for an unregistered hash (does not revert)", async function () {
      const { contract } = await loadFixture(deployFixture);
      const unknownHash = ethers.keccak256(ethers.toUtf8Bytes("not-registered"));
      expect(await contract.isRevoked(unknownHash)).to.be.false;
    });
  });

  // ─── pause / unpause ─────────────────────────────────────────────────────

  describe("pause / unpause", function () {
    it("owner can pause the contract", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      await expect(contract.connect(owner).pause())
        .to.emit(contract, "Paused")
        .withArgs(owner.address);
      expect(await contract.paused()).to.be.true;
    });

    it("owner can unpause the contract", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      await contract.connect(owner).pause();
      await expect(contract.connect(owner).unpause())
        .to.emit(contract, "Unpaused")
        .withArgs(owner.address);
      expect(await contract.paused()).to.be.false;
    });

    it("anchorDocument reverts when contract is paused", async function () {
      const { contract, owner, issuer } = await loadFixture(deployFixture);
      await contract.connect(owner).pause();
      await expect(
        contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS)
      ).to.be.revertedWith("Contract is paused.");
    });

    it("anchorDocument succeeds again after unpause", async function () {
      const { contract, owner, issuer } = await loadFixture(deployFixture);
      await contract.connect(owner).pause();
      await contract.connect(owner).unpause();
      await expect(
        contract.connect(issuer).anchorDocument(SAMPLE_HASH, SAMPLE_IPFS)
      ).to.not.be.reverted;
    });

    it("non-owner cannot pause", async function () {
      const { contract, stranger } = await loadFixture(deployFixture);
      await expect(
        contract.connect(stranger).pause()
      ).to.be.revertedWith("Not the contract owner.");
    });

    it("reverts when trying to pause an already-paused contract", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      await contract.connect(owner).pause();
      await expect(
        contract.connect(owner).pause()
      ).to.be.revertedWith("Already paused.");
    });

    it("reverts when trying to unpause a non-paused contract", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      await expect(
        contract.connect(owner).unpause()
      ).to.be.revertedWith("Not paused.");
    });
  });

  // ─── transferOwnership ────────────────────────────────────────────────────

  describe("transferOwnership", function () {
    it("owner can transfer ownership to a new address", async function () {
      const { contract, owner, stranger } = await loadFixture(deployFixture);
      await expect(contract.connect(owner).transferOwnership(stranger.address))
        .to.emit(contract, "OwnershipTransferred")
        .withArgs(owner.address, stranger.address);
      expect(await contract.owner()).to.equal(stranger.address);
    });

    it("new owner can exercise owner-only functions after transfer", async function () {
      const { contract, owner, stranger } = await loadFixture(deployFixture);
      await contract.connect(owner).transferOwnership(stranger.address);
      // stranger is now owner and should be able to pause
      await expect(
        contract.connect(stranger).pause()
      ).to.not.be.reverted;
    });

    it("previous owner loses owner-only access after transfer", async function () {
      const { contract, owner, stranger } = await loadFixture(deployFixture);
      await contract.connect(owner).transferOwnership(stranger.address);
      await expect(
        contract.connect(owner).pause()
      ).to.be.revertedWith("Not the contract owner.");
    });

    it("reverts when transferring to the zero address", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      await expect(
        contract.connect(owner).transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWith("New owner is the zero address.");
    });

    it("reverts when a non-owner tries to transfer ownership", async function () {
      const { contract, stranger, issuer } = await loadFixture(deployFixture);
      await expect(
        contract.connect(stranger).transferOwnership(issuer.address)
      ).to.be.revertedWith("Not the contract owner.");
    });
  });
});
