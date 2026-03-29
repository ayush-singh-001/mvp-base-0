import React, { useState } from "react";
import { ethers } from "ethers";
import { CONTRACT_ADDRESS, ABI, SEPOLIA_RPC_URL } from "../config/contract";

/**
 * Compute SHA-256 hash of a File entirely in the browser using SubtleCrypto.
 * Returns a 0x-prefixed lowercase hex string.
 */
async function hashFileSHA256(file) {
  const buffer     = await file.arrayBuffer();
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
  const hashArray  = Array.from(new Uint8Array(hashBuffer));
  const hashHex    = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  return "0x" + hashHex;
}

function formatAddress(addr) {
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function formatTimestamp(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

/**
 * RevokeDocument
 *
 * Owner-only panel. Looks up a document on-chain (by file upload or manual hash),
 * shows a confirmation preview with issuer details, then calls revokeDocument()
 * via MetaMask. Non-owner attempts are caught with a clear error.
 *
 * Also exposes pause / unpause / transferOwnership controls for the contract owner.
 */
function RevokeDocument() {
  const [inputMode, setInputMode] = useState("file"); // "file" | "hash"
  const [file, setFile]           = useState(null);
  const [hashInput, setHashInput] = useState("");
  const [stage, setStage]         = useState("idle"); // idle | hashing | previewing | confirming | waiting | success | error
  const [message, setMessage]     = useState("");
  const [preview, setPreview]     = useState(null);  // { docHash, issuer, timestamp }
  const [txHash, setTxHash]       = useState("");

  // ── Admin controls (pause/unpause/transferOwnership) ─────────────────────
  const [adminStage, setAdminStage]     = useState("idle");
  const [adminMessage, setAdminMessage] = useState("");
  const [newOwnerInput, setNewOwnerInput] = useState("");

  const resetRevoke = () => {
    setStage("idle");
    setMessage("");
    setPreview(null);
    setTxHash("");
  };

  // ── Helpers ───────────────────────────────────────────────────────────────

  const resolveHash = async () => {
    if (inputMode === "file") {
      if (!file) {
        setStage("error");
        setMessage("Please select a file.");
        return null;
      }
      setStage("hashing");
      setMessage("Computing file fingerprint locally…");
      return await hashFileSHA256(file);
    } else {
      const h = hashInput.trim();
      if (!h.match(/^0x[0-9a-fA-F]{64}$/)) {
        setStage("error");
        setMessage("Invalid hash — expected a 0x-prefixed 64-character hex string (SHA-256).");
        return null;
      }
      return h;
    }
  };

  const getSignerOnSepolia = async () => {
    if (!window.ethereum) throw new Error("MetaMask not detected.");
    const provider = new ethers.BrowserProvider(window.ethereum);
    const network  = await provider.getNetwork();
    if (network.chainId !== 11155111n) {
      throw new Error(
        `Wrong network — MetaMask is on chainId ${network.chainId}. ` +
        `Please switch to Ethereum Sepolia and try again.`
      );
    }
    return provider.getSigner();
  };

  // ── Revoke flow ───────────────────────────────────────────────────────────

  const handlePreview = async () => {
    resetRevoke();
    const docHash = await resolveHash();
    if (!docHash) return;

    setStage("previewing");
    setMessage("Looking up document on-chain…");

    try {
      let provider;
      if (window.ethereum) {
        provider = new ethers.BrowserProvider(window.ethereum);
      } else {
        provider = new ethers.JsonRpcProvider(SEPOLIA_RPC_URL);
      }


      const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

      let issuer, timestamp;
      try {
        [issuer, timestamp] = await contract.verifyDocument(docHash);
      } catch (err) {
        const msg = (err?.reason ?? err?.message ?? "").toLowerCase();
        if (msg.includes("document not verified") || msg.includes("execution reverted")) {
          setStage("error");
          setMessage("No on-chain record found for this hash. It may not have been issued through this system.");
          return;
        }
        throw err;
      }

      const alreadyRevoked = await contract.isRevoked(docHash);
      if (alreadyRevoked) {
        setStage("error");
        setMessage("This document is already revoked on-chain.");
        return;
      }

      setPreview({ docHash, issuer, timestamp: Number(timestamp) });
      setStage("confirming");
      setMessage("");
    } catch (err) {
      setStage("error");
      setMessage(`Blockchain lookup failed: ${err.message}`);
    }
  };

  const handleRevoke = async () => {
    if (!preview) return;
    try {
      const signer   = await getSignerOnSepolia();
      const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);

      setStage("waiting");
      setMessage("Transaction submitted. Waiting for Sepolia confirmation…");

      const tx = await contract.revokeDocument(preview.docHash);
      await tx.wait();

      setTxHash(tx.hash);
      setStage("success");
      setMessage("Document revoked successfully. It will now show as ⚠ REVOKED to all verifiers.");
    } catch (err) {
      setStage("error");
      const reason = err.reason || err.data?.message || err.message || "";
      if (reason.toLowerCase().includes("only the document issuer")) {
        setMessage("Revocation failed: you can only revoke documents you anchored.");
      } else if (reason.toLowerCase().includes("user rejected")) {
        setMessage("Transaction cancelled in MetaMask.");
      } else {
        setMessage(reason || "An unexpected error occurred.");
      }
    }
  };

  // ── Admin control handlers (pause / unpause / transfer) ───────────────────

  const runAdminTx = async (action) => {
    setAdminStage("waiting");
    setAdminMessage("Waiting for MetaMask…");
    try {
      const signer   = await getSignerOnSepolia();
      const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);

      let tx;
      if (action === "pause")    tx = await contract.pause();
      if (action === "unpause")  tx = await contract.unpause();
      if (action === "transfer") {
        if (!ethers.isAddress(newOwnerInput.trim())) {
          setAdminStage("error");
          setAdminMessage("Invalid Ethereum address for new owner.");
          return;
        }
        tx = await contract.transferOwnership(newOwnerInput.trim());
      }

      setAdminMessage("Confirming on Sepolia…");
      await tx.wait();
      setAdminStage("success");
      setAdminMessage(
        action === "pause"    ? "Contract paused. New issuance is halted." :
        action === "unpause"  ? "Contract unpaused. Issuance resumed." :
        `Ownership transferred to ${newOwnerInput.trim().slice(0, 10)}…`
      );
    } catch (err) {
      setAdminStage("error");
      const reason = err.reason || err.data?.message || err.message || "";
      if (reason.toLowerCase().includes("not the contract owner")) {
        setAdminMessage("Action failed: connected wallet is not the contract owner.");
      } else if (reason.toLowerCase().includes("user rejected")) {
        setAdminMessage("Transaction cancelled in MetaMask.");
      } else {
        setAdminMessage(reason || "An unexpected error occurred.");
      }
    }
  };

  const activeDisabled = ["hashing", "previewing", "waiting"].includes(stage);

  return (
    <div className="panel">
      <h2>Admin Panel</h2>
      <p className="panel-description">
        You can revoke documents you anchored. Admin functions (pause/unpause) require the contract owner's wallet.
      </p>

      {/* ─── Section: Revoke Document ──────────────────────────────────── */}
      <p className="result-section-title" style={{ marginBottom: "12px" }}>Revoke a Document</p>

      {/* Mode toggle */}
      <div className="toggle-row">
        <button
          className={`toggle-btn ${inputMode === "file" ? "toggle-active" : ""}`}
          onClick={() => { setInputMode("file"); resetRevoke(); }}
        >
          Upload File
        </button>
        <button
          className={`toggle-btn ${inputMode === "hash" ? "toggle-active" : ""}`}
          onClick={() => { setInputMode("hash"); resetRevoke(); }}
        >
          Enter Hash
        </button>
      </div>

      {/* File input */}
      {inputMode === "file" && (
        <div className="file-input-row" style={{ marginTop: "12px" }}>
          <label className="file-label">
            {file ? file.name : "Choose file…"}
            <input type="file" onChange={(e) => { setFile(e.target.files[0]); resetRevoke(); }} />
          </label>
          <button className="btn btn-secondary" onClick={handlePreview} disabled={activeDisabled}>
            {(stage === "hashing" || stage === "previewing") ? "Looking up…" : "Look Up Document"}
          </button>
        </div>
      )}

      {/* Hash input */}
      {inputMode === "hash" && (
        <div className="hash-input-row" style={{ marginTop: "12px" }}>
          <input
            type="text"
            className="hash-input"
            placeholder="0x…  (64-character SHA-256 hex)"
            value={hashInput}
            onChange={(e) => { setHashInput(e.target.value); resetRevoke(); }}
          />
          <button className="btn btn-secondary" onClick={handlePreview} disabled={activeDisabled}>
            {stage === "previewing" ? "Looking up…" : "Look Up Document"}
          </button>
        </div>
      )}

      {/* In-progress */}
      {["hashing", "previewing", "waiting"].includes(stage) && (
        <div className="status-box status-analyzing">
          <span className="status-dot" />
          <p className="status-message">{message}</p>
        </div>
      )}

      {/* Error */}
      {stage === "error" && (
        <div className="status-box status-error">
          <span className="status-dot" />
          <p className="status-message">{message}</p>
        </div>
      )}

      {/* Confirmation preview */}
      {stage === "confirming" && preview && (
        <div className="revoke-confirm-box">
          <p className="revoke-confirm-title">Document found — confirm revocation</p>
          <div className="result-row">
            <span className="result-label">Hash</span>
            <span className="result-value">
              <code>{preview.docHash.slice(0, 18)}…{preview.docHash.slice(-8)}</code>
            </span>
          </div>
          <div className="result-row">
            <span className="result-label">Issuer</span>
            <span className="result-value">
              <a
                href={`https://sepolia.etherscan.io/address/${preview.issuer}`}
                target="_blank"
                rel="noreferrer"
              >
                {formatAddress(preview.issuer)}
              </a>
            </span>
          </div>
          <div className="result-row">
            <span className="result-label">Anchored On</span>
            <span className="result-value">{formatTimestamp(preview.timestamp)}</span>
          </div>
          <p className="revoke-warning">
            ⚠ This action is irreversible. The document will permanently show as REVOKED to all verifiers.
          </p>
          <button className="btn btn-danger" onClick={handleRevoke}>
            Revoke Document
          </button>
        </div>
      )}

      {/* Success */}
      {stage === "success" && (
        <div className="status-box status-success">
          <span className="status-dot" />
          <div>
            <p className="status-message">{message}</p>
            {txHash && (
              <p className="status-detail">
                <span>Tx:</span>
                <a
                  href={`https://sepolia.etherscan.io/tx/${txHash}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {txHash.slice(0, 10)}…{txHash.slice(-8)}
                </a>
              </p>
            )}
          </div>
        </div>
      )}

      {/* ─── Section: Contract Controls ────────────────────────────────── */}
      <div className="result-divider" style={{ margin: "28px 0 20px" }} />
      <p className="result-section-title" style={{ marginBottom: "14px" }}>Contract Controls</p>

      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "16px" }}>
        <button className="btn btn-secondary" onClick={() => runAdminTx("pause")}>
          ⏸ Pause Issuance
        </button>
        <button className="btn btn-secondary" onClick={() => runAdminTx("unpause")}>
          ▶ Unpause Issuance
        </button>
      </div>

      <div className="hash-input-row">
        <input
          type="text"
          className="hash-input"
          placeholder="New owner address (0x…)"
          value={newOwnerInput}
          onChange={(e) => { setNewOwnerInput(e.target.value); setAdminStage("idle"); setAdminMessage(""); }}
        />
        <button className="btn btn-danger" onClick={() => runAdminTx("transfer")}>
          Transfer Ownership
        </button>
      </div>

      {/* Admin status */}
      {adminStage === "waiting" && (
        <div className="status-box status-analyzing" style={{ marginTop: "14px" }}>
          <span className="status-dot" />
          <p className="status-message">{adminMessage}</p>
        </div>
      )}
      {adminStage === "success" && (
        <div className="status-box status-success" style={{ marginTop: "14px" }}>
          <span className="status-dot" />
          <p className="status-message">{adminMessage}</p>
        </div>
      )}
      {adminStage === "error" && (
        <div className="status-box status-error" style={{ marginTop: "14px" }}>
          <span className="status-dot" />
          <p className="status-message">{adminMessage}</p>
        </div>
      )}
    </div>
  );
}

export default RevokeDocument;
