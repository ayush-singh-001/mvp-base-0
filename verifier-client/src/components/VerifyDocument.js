import React, { useState } from "react";
import { ethers } from "ethers";
import axios from "axios";
import { CONTRACT_ADDRESS, ABI, SEPOLIA_RPC_URL } from "../config/contract";
import ResultCard from "./ResultCard";

/**
 * Compute SHA-256 hash of a File entirely in the browser using SubtleCrypto.
 * Returns a 0x-prefixed lowercase hex string — identical to what the backend
 * produces with Node's crypto.createHash('sha256').
 */
async function hashFileSHA256(file) {
  const buffer      = await file.arrayBuffer();
  const hashBuffer  = await window.crypto.subtle.digest("SHA-256", buffer);
  const hashArray   = Array.from(new Uint8Array(hashBuffer));
  const hashHex     = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  return "0x" + hashHex;
}

function VerifyDocument({ network = "ethereum" }) {
  const [file, setFile]       = useState(null);
  const [stage, setStage]     = useState("idle"); // idle | hashing | querying | done | error
  const [message, setMessage] = useState("");
  const [result, setResult]   = useState(null);  // { docHash, onChain, offChain }
  const isFabric = network === "fabric";

  const resetState = () => {
    setStage("idle");
    setMessage("");
    setResult(null);
  };

  const handleVerify = async () => {
    if (!file) {
      setStage("error");
      setMessage("Please select a file to verify.");
      return;
    }

    setStage("hashing");
    setMessage("Computing file fingerprint locally…");
    setResult(null);

    try {
      const docHash = await hashFileSHA256(file);

      // ── Fabric path ───────────────────────────────────────────────────────
      if (isFabric) {
        setStage("querying");
        setMessage("Querying the Hyperledger Fabric ledger…");
        const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:5000";
        try {
          const res = await axios.get(`${apiUrl}/api/fabric/document/${docHash}`);
          const d   = res.data;
          // Map Fabric response to the same onChain shape ResultCard expects
          setResult({
            docHash,
            onChain: {
              issuer:    d.issuer,
              timestamp: d.timestamp ? Math.floor(new Date(d.timestamp).getTime() / 1000) : 0,
              ipfsHash:  d.ipfsCid || "",
            },
            offChain: {
              fileName:    d.fileName,
              aiScore:     d.aiScore,
              aiProvider:  d.aiProvider,
              aiDetails:   d.aiDetails,
              isAuthentic: d.isAuthentic,
              ipfsCid:     d.ipfsCid,
              createdAt:   d.createdAt,
            },
            revoked: d.revoked || false,
          });
        } catch (fabricErr) {
          if (fabricErr.response?.status === 404) {
            // Hash not on Fabric ledger
            setResult({ docHash, onChain: null, offChain: null, revoked: false });
          } else {
            throw new Error(`Fabric query failed: ${fabricErr.response?.data?.error || fabricErr.message}`);
          }
        }
        setStage("done");
        setMessage("");
        return;
      }

      // ── Ethereum path ──────────────────────────────────────────────────────
      setStage("querying");
      setMessage("Querying the Sepolia blockchain…");

      // Step 2 — Read-only contract call.
      // Prefer MetaMask's provider if available; fall back to a public Sepolia RPC
      // so users can verify without any wallet installed.
      let provider;
      if (window.ethereum) {
        provider = new ethers.BrowserProvider(window.ethereum);
      } else {
        provider = new ethers.JsonRpcProvider(SEPOLIA_RPC_URL);
      }

      const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

      let onChain = null;
      try {
        // verifyDocument() reverts with "Document not verified." if not found
        const [issuer, timestamp, ipfsHash] = await contract.verifyDocument(docHash);
        onChain = {
          issuer,
          timestamp: Number(timestamp), // BigInt → Number (safe; block timestamps fit in 53-bit int)
          ipfsHash,
        };
      } catch (verifyErr) {
        // Distinguish an expected contract revert (hash not found) from a genuine
        // RPC / network failure — only swallow the error in the expected case.
        const msg = (verifyErr?.reason ?? verifyErr?.message ?? "").toLowerCase();
        const isExpectedRevert =
          msg.includes("document not verified") ||
          msg.includes("call revert exception") ||
          msg.includes("execution reverted");
        if (isExpectedRevert) {
          onChain = null; // Hash is not on-chain — expected, not an error
        } else {
          throw new Error(`Blockchain query failed: ${verifyErr.message}`);
        }
      }

      // Step 2b — Check revocation status (only if the document was found on-chain)
      let revoked = false;
      if (onChain !== null) {
        try {
          revoked = await contract.isRevoked(docHash);
        } catch {
          revoked = false; // non-fatal — conservative default is not-revoked
        }
      }

      // Step 3 — Fetch off-chain metadata from backend (best-effort; don't block on failure)
      let offChain = null;
      try {
        const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:5000";
        const res = await axios.get(`${apiUrl}/api/document/${docHash}`);
        offChain = res.data;
      } catch {
        offChain = null; // backend may be offline or the record may not exist
      }

      setResult({ docHash, onChain, offChain, revoked });
      setStage("done");
      setMessage("");

    } catch (err) {
      setStage("error");
      setMessage(err.message || "Verification failed due to an unexpected error.");
    }
  };

  return (
    <div className="panel">
      <h2>Verify Document</h2>
      <p className="panel-description">
        {isFabric
          ? "Upload any document to check whether its fingerprint is anchored on the Hyperledger Fabric private ledger. No wallet required."
          : "Upload any document to check whether its fingerprint is registered on-chain. No wallet required — the check is read-only."
        }
      </p>

      <div className="file-input-row">
        <label className="file-label">
          {file ? file.name : "Choose file…"}
          <input
            type="file"
            onChange={(e) => {
              setFile(e.target.files[0]);
              resetState();
            }}
          />
        </label>

        <button
          className="btn btn-secondary"
          onClick={handleVerify}
          disabled={stage === "hashing" || stage === "querying"}
        >
          {stage === "hashing"  ? "Hashing…"        :
           stage === "querying" ? "Querying chain…"  :
           "Verify Document"}
        </button>
      </div>

      {/* In-progress states */}
      {(stage === "hashing" || stage === "querying") && (
        <div className="status-box status-analyzing">
          <span className="status-dot" />
          <p className="status-message">{message}</p>
        </div>
      )}

      {/* Error state */}
      {stage === "error" && (
        <div className="status-box status-error">
          <span className="status-dot" />
          <p className="status-message">{message}</p>
        </div>
      )}

      {/* Result */}
      {stage === "done" && result && (
        <ResultCard
          docHash={result.docHash}
          onChain={result.onChain}
          offChain={result.offChain}
          revoked={result.revoked}
        />
      )}
    </div>
  );
}

export default VerifyDocument;
