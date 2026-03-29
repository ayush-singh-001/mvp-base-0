/**
 * Deploy script for DocVerifier.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js                     # local Hardhat network (dry run)
 *   npx hardhat run scripts/deploy.js --network sepolia   # live Sepolia deployment
 *
 * After deploying to Sepolia, update CONTRACT_ADDRESS in:
 *   ../verifier-client/src/config/contract.js
 *
 * To verify source on Etherscan (requires ETHERSCAN_API_KEY in .env):
 *   npx hardhat verify --network sepolia <DEPLOYED_ADDRESS>
 */

const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("──────────────────────────────────────────");
  console.log("Deploying DocVerifier");
  console.log("──────────────────────────────────────────");
  console.log("Deployer :", deployer.address);

  const balance = await deployer.provider.getBalance(deployer.address);
  console.log("Balance  :", ethers.formatEther(balance), "ETH");

  if (balance === 0n) {
    throw new Error("Deployer wallet has zero balance. Fund it with Sepolia ETH first.");
  }

  const DocVerifier = await ethers.getContractFactory("DocVerifier");
  console.log("\nDeploying contract…");

  const contract = await DocVerifier.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();

  console.log("\n✓ DocVerifier deployed");
  console.log("  Address :", address);
  console.log("  Etherscan:", `https://sepolia.etherscan.io/address/${address}`);
  console.log("\n⚠  Next step: update CONTRACT_ADDRESS in");
  console.log("   ../verifier-client/src/config/contract.js");
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
