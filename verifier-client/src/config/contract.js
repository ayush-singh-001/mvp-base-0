// Single source of truth for all on-chain configuration.
// Import from here — never hardcode the address or ABI in a component.
//
// Contract : DocVerifier v2  (hardhat/contracts/DocVerifier.sol)
// Network  : Ethereum Sepolia Testnet
// Features : anchorDocument · verifyDocument · isRevoked · revokeDocument

export const CONTRACT_ADDRESS = "0x66DDBF0516100F3b4717e62b5068D5b7473E1418";

// Public Sepolia JSON-RPC endpoint used as a read-only fallback
// when MetaMask is not available (e.g. during verification).
export const SEPOLIA_RPC_URL = "https://ethereum-sepolia.publicnode.com";

export const ABI = [
  {
    inputs: [
      { internalType: "bytes32", name: "_docHash", type: "bytes32" },
      { internalType: "string",  name: "_ipfsHash", type: "string"  }
    ],
    name: "anchorDocument",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, internalType: "bytes32", name: "docHash", type: "bytes32" },
      { indexed: true, internalType: "address", name: "issuer",  type: "address" }
    ],
    name: "DocumentAnchored",
    type: "event"
  },
  {
    inputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
    name: "documents",
    outputs: [
      { internalType: "address", name: "issuer",    type: "address" },
      { internalType: "uint256", name: "timestamp", type: "uint256" },
      { internalType: "string",  name: "ipfsHash",  type: "string"  },
      { internalType: "bool",    name: "revoked",   type: "bool"    }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [{ internalType: "bytes32", name: "_docHash", type: "bytes32" }],
    name: "verifyDocument",
    outputs: [
      { internalType: "address", name: "", type: "address" },
      { internalType: "uint256", name: "", type: "uint256" },
      { internalType: "string",  name: "", type: "string"  }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [{ internalType: "bytes32", name: "_docHash", type: "bytes32" }],
    name: "isRevoked",
    outputs: [{ internalType: "bool", name: "", type: "bool" }],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [{ internalType: "bytes32", name: "_docHash", type: "bytes32" }],
    name: "revokeDocument",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, internalType: "bytes32", name: "docHash",   type: "bytes32" },
      { indexed: true, internalType: "address", name: "revokedBy", type: "address" }
    ],
    name: "DocumentRevoked",
    type: "event"
  },
  // ─── Admin: pause / unpause / transferOwnership ───────────────────────
  {
    inputs: [],
    name: "pause",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [],
    name: "unpause",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [{ internalType: "address", name: "_newOwner", type: "address" }],
    name: "transferOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [],
    name: "paused",
    outputs: [{ internalType: "bool", name: "", type: "bool" }],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [],
    name: "owner",
    outputs: [{ internalType: "address", name: "", type: "address" }],
    stateMutability: "view",
    type: "function"
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, internalType: "address", name: "previous", type: "address" },
      { indexed: true, internalType: "address", name: "newOwner", type: "address" }
    ],
    name: "OwnershipTransferred",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [{ indexed: true, internalType: "address", name: "by", type: "address" }],
    name: "Paused",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [{ indexed: true, internalType: "address", name: "by", type: "address" }],
    name: "Unpaused",
    type: "event"
  }
];
