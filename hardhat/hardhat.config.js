require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: { enabled: true, runs: 200 }
    }
  },
  networks: {
    // Local Hardhat node — used by default for `npx hardhat test`
    hardhat: {},

    // Ethereum Sepolia Testnet — production deployment target
    sepolia: {
      url:      process.env.SEPOLIA_RPC_URL || "https://ethereum-sepolia.publicnode.com",
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [`0x${process.env.DEPLOYER_PRIVATE_KEY}`] : []
    }
  },
  // Optional: verify contract source on Etherscan after deployment
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY || ""
  }
};
