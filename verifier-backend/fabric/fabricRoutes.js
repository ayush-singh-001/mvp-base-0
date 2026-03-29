'use strict';
/**
 * fabric/fabricRoutes.js
 * Express router for Fabric-backed routes.
 *
 * Routes:
 *   POST /api/fabric/analyze        – AI-gate + AnchorDocument on Fabric + MongoDB
 *   GET  /api/fabric/document/:hash – VerifyDocument on Fabric + MongoDB metadata
 *   POST /api/fabric/revoke         – RevokeDocument on Fabric
 *
 * Mounted in server.js when FABRIC_ENABLED=true:
 *   app.use('/api/fabric', require('./fabric/fabricRoutes'));
 */

const express  = require('express');
const multer   = require('multer');
const crypto   = require('crypto');
const router   = express.Router();

const { getContract }       = require('./gateway');
const { getThreshold, checkAuthenticity } = require('../lib/aiCheck');
const { pinToIPFS }         = require('../lib/ipfs');
const DocModel              = require('../models/Document');
const { requireAuth }       = require('../middleware/auth');

// 10 MB cap (same as main upload endpoint)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ── POST /api/fabric/analyze ─────────────────────────────────────────────────
// 1. Compute SHA-256 hash
// 2. AI check (same gate as Ethereum route)
// 3. IPFS upload (optional)
// 4. AnchorDocument on Fabric (Private Data Collection)
// 5. Persist metadata to MongoDB
router.post('/analyze', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });

    const fileBuffer = req.file.buffer;
    const fileName   = req.file.originalname;
    const mimeType   = req.file.mimetype;

    // A. Hash
    const docHash  = '0x' + crypto.createHash('sha256').update(fileBuffer).digest('hex');
    const threshold = getThreshold(mimeType);

    // B. AI gate
    const aiResult = await checkAuthenticity(fileBuffer, fileName, mimeType);
    if (aiResult.score > threshold) {
      return res.status(400).json({
        error:      'AI check failed: content appears synthetic or forged.',
        aiScore:    aiResult.score,
        aiProvider: aiResult.provider,
        threshold
      });
    }

    // C. IPFS
    let ipfsCid = null;
    try {
      ipfsCid = await pinToIPFS(fileBuffer, fileName);
      if (ipfsCid) console.log(`[Fabric] [IPFS] Pinned: ${ipfsCid}`);
    } catch (pinErr) {
      console.warn('[Fabric] [IPFS] Pinata upload failed (non-fatal):', pinErr.message);
    }

    // D. Anchor on Fabric
    const contract = await getContract();
    // AnchorDocument(docHash, ipfsCid)
    await contract.submitTransaction('AnchorDocument', docHash, ipfsCid ?? '');
    console.log(`[Fabric] Anchored: ${docHash}`);

    // E. Persist to MongoDB
    const isAuthentic = aiResult.score <= threshold;
    await DocModel.findOneAndUpdate(
      { docHash },
      {
        docHash, fileName,
        aiScore:    aiResult.score,
        aiProvider: aiResult.provider,
        aiDetails:  aiResult.details,
        isAuthentic,
        ipfsCid,
        network: 'fabric'
      },
      { upsert: true, new: true }
    );

    res.json({
      success:    true,
      docHash,
      aiScore:    aiResult.score,
      aiProvider: aiResult.provider,
      ipfsCid,
      network:    'fabric'
    });

  } catch (err) {
    console.error('[Fabric] /api/fabric/analyze error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/fabric/document/:hash ───────────────────────────────────────────
// Queries both Fabric (on-chain truth) and MongoDB (off-chain metadata).
router.get('/document/:hash', async (req, res) => {
  try {
    const docHash  = req.params.hash;
    const contract = await getContract();

    // On-chain data (from Private Data Collection)
    let fabricDoc;
    try {
      const resultBytes = await contract.evaluateTransaction('VerifyDocument', docHash);
      fabricDoc = JSON.parse(Buffer.from(resultBytes).toString());
    } catch (ccErr) {
      // Chaincode throws "document not found" – treat as 404
      if (ccErr.message?.includes('not found')) {
        return res.status(404).json({ error: 'Document not found on Fabric ledger.' });
      }
      throw ccErr;
    }

    // Off-chain metadata (may not exist if anchored from another node)
    const dbDoc = await DocModel.findOne({ docHash });

    res.json({
      // On-chain fields (authoritative)
      docHash:   fabricDoc.docHash,
      issuer:    fabricDoc.issuer,
      timestamp: fabricDoc.timestamp,
      ipfsCid:   fabricDoc.ipfsCid || null,
      revoked:   fabricDoc.revoked,
      network:   'fabric',
      // Off-chain enrichment (may be null)
      fileName:    dbDoc?.fileName   ?? null,
      aiScore:     dbDoc?.aiScore    ?? null,
      aiProvider:  dbDoc?.aiProvider ?? null,
      aiDetails:   dbDoc?.aiDetails  ?? null,
      isAuthentic: dbDoc?.isAuthentic ?? null,
      createdAt:   dbDoc?.createdAt  ?? null
    });

  } catch (err) {
    console.error('[Fabric] /api/fabric/document error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/fabric/revoke ──────────────────────────────────────────────────
// Body: { docHash: "0x..." }  — requires JWT admin token
router.post('/revoke', requireAuth, express.json(), async (req, res) => {
  try {
    const { docHash } = req.body;
    if (!docHash) return res.status(400).json({ error: 'docHash is required.' });

    const contract = await getContract();
    await contract.submitTransaction('RevokeDocument', docHash);
    console.log(`[Fabric] Revoked: ${docHash}`);

    res.json({ success: true, docHash, revoked: true, network: 'fabric' });

  } catch (err) {
    console.error('[Fabric] /api/fabric/revoke error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/fabric/pause  /  POST /api/fabric/unpause ─────────────────────
// Both require JWT admin token.
router.post('/pause', requireAuth, async (_req, res) => {
  try {
    const contract = await getContract();
    await contract.submitTransaction('PauseNetwork');
    res.json({ success: true, paused: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/unpause', requireAuth, async (_req, res) => {
  try {
    const contract = await getContract();
    await contract.submitTransaction('UnpauseNetwork');
    res.json({ success: true, paused: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/fabric/status ───────────────────────────────────────────────────
// Returns current Fabric network state (paused, owner).
router.get('/status', async (_req, res) => {
  try {
    const contract    = await getContract();
    const resultBytes = await contract.evaluateTransaction('GetNetworkState');
    const state       = JSON.parse(Buffer.from(resultBytes).toString());
    res.json({ ...state, network: 'fabric' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
