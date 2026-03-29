import React, { useState } from "react";
import { ethers } from "ethers";
import axios from "axios";
import { CONTRACT_ADDRESS, ABI } from "../config/contract";

function IssueDocument({ network = "ethereum" }) {
  const [file, setFile]       = useState(null);
  const [stage, setStage]     = useState("idle"); // idle | analyzing | anchoring | waiting | success | error
  const [message, setMessage] = useState("");
  const [docHash, setDocHash] = useState("");
  const [txHash, setTxHash]   = useState("");
  const [ipfsCid, setIpfsCid] = useState(null);
  const isFabric = network === "fabric";

  const resetState = () => {
    setStage("idle");
    setMessage("");
    setDocHash("");
    setTxHash("");
    setIpfsCid(null);
  };

  // ── Fabric path ─────────────────────────────────────────────────────────────
  const handleIssueFabric = async () => {
    setStage("analyzing");
    setMessage("Uploading to Fabric — AI check + IPFS + anchor…");

    const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:5000";
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(`${apiUrl}/api/fabric/analyze`, formData);
      const { docHash: hash, aiScore, aiProvider, ipfsCid: cid } = res.data;
      setDocHash(hash);
      if (cid) setIpfsCid(cid);
      setTxHash(""); // no Ethereum tx on Fabric
      setStage("success");
      setMessage(
        `Document anchored on Hyperledger Fabric. ` +
        `AI score: ${aiScore != null ? aiScore.toFixed(1) + "%" : "n/a"} (${aiProvider || "mock"})`
      );
    } catch (err) {
      setStage("error");
      setMessage(err.response?.data?.error || err.message || "Fabric anchor failed.");
    }
  };

  // ── Ethereum path ────────────────────────────────────────────────────────────
  const handleIssueEthereum = async () => {
    const formData = new FormData();
    formData.append("file", file);

    try {
      // Step 1 — Backend: SHA-256 hash + AI check + optional Pinata upload
      const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:5000";
      const res = await axios.post(`${apiUrl}/api/analyze`, formData);
      const { docHash: hash, aiScore, aiProvider, ipfsCid: cid } = res.data;
      setDocHash(hash);
      if (cid) setIpfsCid(cid);

      const providerLabel = aiProvider && !aiProvider.startsWith("mock")
        ? `AI passed — ${aiProvider} score: ${aiScore.toFixed(1)}%`
        : `AI check passed (mock score: ${Math.floor(aiScore)}%)`;

      setStage("anchoring");
      setMessage(`${providerLabel}. Waiting for MetaMask…`);

      // Step 2 — On-chain: anchor via MetaMask
      if (!window.ethereum) {
        setStage("error");
        setMessage("MetaMask not detected. Please install the MetaMask extension to issue documents.");
        return;
      }

      const provider = new ethers.BrowserProvider(window.ethereum);

      // Guard: confirm MetaMask is on Sepolia (chainId 11155111) before spending gas
      const net = await provider.getNetwork();
      if (net.chainId !== 11155111n) {
        setStage("error");
        setMessage(
          `Wrong network — MetaMask is on chainId ${net.chainId}. ` +
          `Please switch to the Ethereum Sepolia Testnet and try again.`
        );
        return;
      }

      const signer   = await provider.getSigner();
      const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);

      const tx = await contract.anchorDocument(hash, cid || "ipfs_placeholder");
      setStage("waiting");
      setMessage("Transaction submitted. Waiting for Sepolia confirmation (may take ~15s)…");
      await tx.wait();

      setTxHash(tx.hash);
      setStage("success");
      setMessage("Document anchored successfully.");

    } catch (err) {
      setStage("error");
      const reason = err.reason || err.data?.message || err.message || "";
      if (reason.toLowerCase().includes("document already verified")) {
        setMessage("This document is already anchored on-chain — it cannot be re-issued. Use the Verify tab to look it up.");
      } else if (reason.toLowerCase().includes("user rejected")) {
        setMessage("Transaction cancelled in MetaMask.");
      } else {
        setMessage(err.response?.data?.error || reason || "An unexpected error occurred.");
      }
    }
  };

  // ── Dispatcher ───────────────────────────────────────────────────────────────
  const handleIssue = async () => {
    if (!file) {
      setStage("error");
      setMessage("Please select a file first.");
      return;
    }

    const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
    if (file.size > MAX_FILE_SIZE) {
      setStage("error");
      setMessage(
        `File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). ` +
        `Maximum allowed size is 10 MB.`
      );
      return;
    }

    setStage("analyzing");
    setMessage("");

    if (isFabric) {
      return handleIssueFabric();
    }
    return handleIssueEthereum();
  };

  return (
    <div className="panel">
      <h2>Issue Document</h2>
      <p className="panel-description">
        {isFabric
          ? "Upload a document to anchor its SHA-256 fingerprint on the Hyperledger Fabric private ledger via the backend gateway (no wallet required)."
          : "Upload a document to compute its SHA-256 fingerprint, run an AI authenticity check, and anchor the hash on the Ethereum Sepolia blockchain via MetaMask."
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
          className="btn btn-primary"
          onClick={handleIssue}
          disabled={["analyzing", "anchoring", "waiting"].includes(stage)}
        >
          {stage === "analyzing" ? "Analyzing…"
           : stage === "anchoring" ? "Open MetaMask…"
           : stage === "waiting"   ? "Confirming…"
           : "Issue Document"}
        </button>
      </div>

      {stage !== "idle" && (
        <div className={`status-box status-${stage}`}>
          <span className="status-dot" />
          <div>
            <p className="status-message">{message}</p>

            {stage === "success" && (
              <>
                <p className="status-detail">
                  <span>Hash:</span>
                  <code>{docHash}</code>
                </p>
                {!isFabric && txHash && (
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
                {isFabric && (
                  <p className="status-detail">
                    <span>Ledger:</span>
                    <code>Hyperledger Fabric (mychannel)</code>
                  </p>
                )}
                {ipfsCid && (
                  <p className="status-detail">
                    <span>IPFS:</span>
                    <a
                      href={`https://gateway.pinata.cloud/ipfs/${ipfsCid}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {ipfsCid.slice(0, 12)}…
                    </a>
                  </p>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default IssueDocument;
