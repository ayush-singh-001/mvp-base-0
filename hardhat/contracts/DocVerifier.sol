// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  DocVerifier
 * @notice Immutable registry for SHA-256 document fingerprints.
 *         Anyone can anchor a document; only the document issuer can revoke it.
 *
 * v3 additions vs v2:
 *   - `paused` state + pause() / unpause() for emergency stop.
 *   - `anchorDocument` is gated by whenNotPaused.
 *   - `transferOwnership()` for operational handoff.
 *
 * On re-deploy: update CONTRACT_ADDRESS in
 *   verifier-client/src/config/contract.js
 */
contract DocVerifier {

    // ─── State ────────────────────────────────────────────────────────────

    struct Document {
        address issuer;     // Wallet that anchored the document
        uint256 timestamp;  // Block timestamp at anchoring (unix seconds)
        string  ipfsHash;   // IPFS CID — "ipfs_placeholder" until Pinata is configured
        bool    revoked;    // True once a privileged revocation has been issued
    }

    address public owner;
    bool    public paused;
    mapping(bytes32 => Document) public documents;

    // ─── Events ───────────────────────────────────────────────────────────

    event DocumentAnchored    (bytes32 indexed docHash,  address indexed issuer);
    event DocumentRevoked     (bytes32 indexed docHash,  address indexed revokedBy);
    event OwnershipTransferred(address indexed previous, address indexed newOwner);
    event Paused              (address indexed by);
    event Unpaused            (address indexed by);

    // ─── Modifiers ────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner.");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract is paused.");
        _;
    }

    // ─── Constructor ──────────────────────────────────────────────────────

    constructor() {
        owner  = msg.sender;
        paused = false;
    }

    // ─── Admin functions ──────────────────────────────────────────────────

    /**
     * @notice Transfers contract ownership to a new address.
     * @param  _newOwner Cannot be the zero address.
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "New owner is the zero address.");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    /**
     * @notice Halts new document anchoring. Existing records are unaffected.
     *         Use as an emergency stop during a security incident.
     */
    function pause() external onlyOwner {
        require(!paused, "Already paused.");
        paused = true;
        emit Paused(msg.sender);
    }

    /**
     * @notice Resumes new document anchoring.
     */
    function unpause() external onlyOwner {
        require(paused, "Not paused.");
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ─── Write functions ──────────────────────────────────────────────────

    /**
     * @notice Permanently records a document hash on-chain.
     * @param  _docHash  SHA-256 hash of the document (bytes32).
     * @param  _ipfsHash IPFS CID of the stored file, or "ipfs_placeholder".
     *
     * Reverts when paused or the same hash has already been anchored.
     */
    function anchorDocument(bytes32 _docHash, string calldata _ipfsHash)
        external
        whenNotPaused
    {
        require(documents[_docHash].timestamp == 0, "Document already verified.");
        documents[_docHash] = Document({
            issuer:    msg.sender,
            timestamp: block.timestamp,
            ipfsHash:  _ipfsHash,
            revoked:   false
        });
        emit DocumentAnchored(_docHash, msg.sender);
    }

    /**
     * @notice Marks a previously anchored document as revoked.
     *         Revocation is irreversible and can only be done by the document's issuer.
     * @param  _docHash SHA-256 hash of the document to revoke.
     */
    function revokeDocument(bytes32 _docHash) external {
        require(documents[_docHash].timestamp != 0, "Document not found.");
        require(!documents[_docHash].revoked,        "Document already revoked.");
        require(
            msg.sender == documents[_docHash].issuer,
            "Only the document issuer can revoke."
        );
        documents[_docHash].revoked = true;
        emit DocumentRevoked(_docHash, msg.sender);
    }

    // ─── Read functions ───────────────────────────────────────────────────

    /**
     * @notice Returns on-chain metadata for a registered document.
     * @return issuer    Address that anchored the document.
     * @return timestamp Unix timestamp of the anchoring block.
     * @return ipfsHash  IPFS CID stored at anchor time.
     *
     * Reverts if the document is not registered.
     */
    function verifyDocument(bytes32 _docHash)
        external view
        returns (address issuer, uint256 timestamp, string memory ipfsHash)
    {
        Document storage doc = documents[_docHash];
        require(doc.timestamp != 0, "Document not verified.");
        return (doc.issuer, doc.timestamp, doc.ipfsHash);
    }

    /**
     * @notice Returns true if the document has been revoked by the owner.
     *         Returns false for both unregistered and valid (non-revoked) documents.
     */
    function isRevoked(bytes32 _docHash) external view returns (bool) {
        return documents[_docHash].revoked;
    }
}
