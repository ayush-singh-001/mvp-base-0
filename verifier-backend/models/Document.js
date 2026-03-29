'use strict';
/**
 * models/Document.js
 * Shared Mongoose model for off-chain document metadata.
 * Imported by both the Ethereum routes (server.js) and the Fabric routes.
 *
 * Indexes:
 *   docHash        – unique (primary lookup)
 *   network + createdAt – compound (filtered timeline queries / dashboards)
 *   isAuthentic    – single (stats: count authentic vs rejected)
 *   ipfsCid        – single (lookup by CID, sparse — null rows excluded)
 */
const mongoose = require('mongoose');

const DocSchema = new mongoose.Schema({
  docHash:     { type: String, required: true, unique: true, index: true },
  fileName:    { type: String, required: true },
  aiScore:     { type: Number },
  aiProvider:  { type: String, default: 'mock' },
  aiDetails:   { type: mongoose.Schema.Types.Mixed, default: null },
  isAuthentic: { type: Boolean, index: true },
  ipfsCid:     { type: String, default: null },
  network:     { type: String, enum: ['ethereum', 'fabric'], default: 'ethereum' },
  createdAt:   { type: Date, default: Date.now }
});

// Compound index for filtered timeline queries (e.g. "all Fabric docs, newest first")
DocSchema.index({ network: 1, createdAt: -1 });

// Sparse index for IPFS CID lookups (null values are excluded → smaller index)
DocSchema.index({ ipfsCid: 1 }, { sparse: true });

// Mongoose caches models; this guard prevents "OverwriteModelError" in tests.
module.exports = mongoose.models.Document || mongoose.model('Document', DocSchema);
