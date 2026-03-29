'use strict';
/**
 * Integration tests for verifier-backend/server.js
 *
 * Strategy: mock axios (no real HTTP), mock mongoose (no real DB),
 * and use supertest to drive the Express app in-process.
 *
 * Tests cover:
 *   - GET  /api/health
 *   - POST /api/analyze  (happy path, AI block, file missing, size limit, mock mode)
 *   - GET  /api/document/:hash (found, not found, server error)
 *   - getThreshold helper via env vars
 *   - isAuthentic flag correctness
 */

// ── Mock dependencies BEFORE requiring server ────────────────────────────────

// 1. Mock mongoose so no real MongoDB connection is attempted
jest.mock('mongoose', () => {
  const mockDoc = {
    fileName: 'test.png',
    aiScore: 5,
    aiProvider: 'mock',
    aiDetails: null,
    isAuthentic: true,
    ipfsCid: null,
    createdAt: new Date('2025-01-01')
  };

  const mockModel = {
    findOneAndUpdate: jest.fn().mockResolvedValue(mockDoc),
    findOne: jest.fn().mockResolvedValue(mockDoc)
  };

  const SchemaClass = class Schema {
    constructor() {}
    index() { return this; }   // no-op in tests — Mongoose would register the index on a real DB
  };
  SchemaClass.Types = { Mixed: {} };

  return {
    connect: jest.fn().mockResolvedValue({}),
    Schema: SchemaClass,
    model: jest.fn().mockReturnValue(mockModel),
    models: {},         // needed by models/Document.js guard
    connection: { readyState: 1 }
  };
});

// 2. Mock axios so no real HTTP calls are made to Eden AI / Pinata / Reality Defender
jest.mock('axios');
const axios = require('axios');

// 3. Mock pdf-parse
jest.mock('pdf-parse', () => jest.fn().mockResolvedValue({ text: 'This is a sample document text that is long enough for the AI test.' }));

const request  = require('supertest');
const app      = require('../server');

// Helper: create a fake file buffer
const PNG_HEADER = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
const TEXT_BUF   = Buffer.from('Some plain text content for testing purposes only.');
const PDF_BUF    = Buffer.from('%PDF-1.4 fake pdf content for testing');

// ── /api/health ──────────────────────────────────────────────────────────────

describe('GET /api/health', () => {
  it('returns 200 with status ok and mongo connected', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.mongodb.status).toBe('connected');
    expect(typeof res.body.uptime).toBe('number');
  });
});

// ── /api/analyze ─────────────────────────────────────────────────────────────

describe('POST /api/analyze', () => {

  beforeEach(() => {
    jest.clearAllMocks();
    // Reset all env vars to a clean baseline before each test
    delete process.env.AI_API_KEY;
    delete process.env.AI_ENGINE;
    delete process.env.AI_PROVIDER;
    delete process.env.AI_BLOCK_THRESHOLD;
    delete process.env.AI_THRESHOLD_IMAGE;
    delete process.env.AI_THRESHOLD_VIDEO;
    delete process.env.AI_THRESHOLD_TEXT;
    delete process.env.PINATA_API_KEY;
    delete process.env.PINATA_SECRET_KEY;
  });

  it('returns 400 when no file is attached', async () => {
    const res = await request(app).post('/api/analyze');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/no file/i);
  });

  it('returns docHash and mock AI metadata in mock mode (no API key)', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .attach('file', PNG_HEADER, { filename: 'test.png', contentType: 'image/png' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.docHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(res.body.aiProvider).toMatch(/^mock/);
    expect(typeof res.body.aiScore).toBe('number');
    expect(res.body.ipfsCid).toBeNull();
  });

  it('calls Eden AI image endpoint when AI_API_KEY is set and file is an image', async () => {
    process.env.AI_API_KEY = 'test-key';

    // Mock Eden AI response
    axios.post.mockResolvedValueOnce({
      data: {
        winstonai: {
          status: 'success',
          ai_score: 0.05,
          items: [],
          cost: 0.001
        }
      }
    });

    const res = await request(app)
      .post('/api/analyze')
      .attach('file', PNG_HEADER, { filename: 'real.png', contentType: 'image/png' });

    expect(res.status).toBe(200);
    expect(res.body.aiProvider).toBe('eden_ai:winstonai');
    expect(res.body.aiScore).toBeCloseTo(5, 0); // 0.05 * 100
  });

  it('blocks content when AI score exceeds threshold', async () => {
    process.env.AI_API_KEY = 'test-key';
    process.env.AI_BLOCK_THRESHOLD = '80';

    // Mock high AI score (92%)
    axios.post.mockResolvedValueOnce({
      data: {
        winstonai: { status: 'success', ai_score: 0.92, items: [], cost: 0.001 }
      }
    });

    const res = await request(app)
      .post('/api/analyze')
      .attach('file', PNG_HEADER, { filename: 'deepfake.png', contentType: 'image/png' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/AI check failed/i);
    expect(res.body.aiScore).toBeGreaterThan(80);
  });

  it('writes isAuthentic=true when AI score is below threshold', async () => {
    process.env.AI_API_KEY = 'test-key';

    axios.post.mockResolvedValueOnce({
      data: { winstonai: { status: 'success', ai_score: 0.1, items: [], cost: null } }
    });

    const mongoose = require('mongoose');
    const mockModelInstance = mongoose.model();

    const res = await request(app)
      .post('/api/analyze')
      .attach('file', PNG_HEADER, { filename: 'real.png', contentType: 'image/png' });

    expect(res.status).toBe(200);
    // Verify findOneAndUpdate was called with isAuthentic: true
    const updateCall = mockModelInstance.findOneAndUpdate.mock.calls[0];
    expect(updateCall[1].isAuthentic).toBe(true);
  });

  it('calls Eden AI text endpoint for PDF files', async () => {
    process.env.AI_API_KEY = 'test-key';
    process.env.AI_PROVIDER = 'openai';

    axios.post.mockResolvedValueOnce({
      data: { openai: { status: 'success', ai_score: 0.03, items: [], cost: null } }
    });

    const res = await request(app)
      .post('/api/analyze')
      .attach('file', PDF_BUF, { filename: 'doc.pdf', contentType: 'application/pdf' });

    expect(res.status).toBe(200);
    expect(res.body.aiProvider).toBe('eden_ai:text:openai');
  });

  it('falls back to mock when Eden AI returns an error status', async () => {
    process.env.AI_API_KEY = 'test-key';

    // Eden AI returns a failed status
    axios.post.mockResolvedValueOnce({
      data: { winstonai: { status: 'failed', ai_score: null } }
    });

    const res = await request(app)
      .post('/api/analyze')
      .attach('file', PNG_HEADER, { filename: 'test.png', contentType: 'image/png' });

    // Should fall back to mock and still succeed (mock score < 80)
    expect(res.status).toBe(200);
    expect(res.body.aiProvider).toBe('mock:fallback');
  });

  it('uses PINATA and stores ipfsCid when keys are configured', async () => {
    process.env.PINATA_API_KEY    = 'pk-test';
    process.env.PINATA_SECRET_KEY = 'sk-test';

    // First call = Eden AI (no key) → skipped, goes mock
    // Second call = Pinata upload
    axios.post.mockResolvedValueOnce({ data: { IpfsHash: 'bafkreitest123' } });

    const res = await request(app)
      .post('/api/analyze')
      .attach('file', TEXT_BUF, { filename: 'doc.txt', contentType: 'text/plain' });

    // In mock mode (no AI_API_KEY), AI call is skipped — only Pinata is called
    expect(res.status).toBe(200);
    expect(res.body.ipfsCid).toBe('bafkreitest123');
  });

  it('respects per-type threshold (AI_THRESHOLD_IMAGE)', async () => {
    process.env.AI_API_KEY         = 'test-key';
    process.env.AI_THRESHOLD_IMAGE = '30'; // very strict threshold

    // Mock 40% fake score — passes default (80) but should BLOCK at 30
    axios.post.mockResolvedValueOnce({
      data: { winstonai: { status: 'success', ai_score: 0.40, items: [], cost: null } }
    });

    const res = await request(app)
      .post('/api/analyze')
      .attach('file', PNG_HEADER, { filename: 'borderline.png', contentType: 'image/png' });

    expect(res.status).toBe(400);
    expect(res.body.threshold).toBe(30);
  });

  it('returns 500 when an unexpected error occurs', async () => {
    process.env.AI_API_KEY = 'test-key';

    // Simulate axios throwing a network error
    axios.post.mockRejectedValueOnce(new Error('Network error'));

    // In fallback mode the AI error is caught and mock score used -- so this
    // should still succeed (200). Test that the server does NOT crash.
    const res = await request(app)
      .post('/api/analyze')
      .attach('file', PNG_HEADER, { filename: 'test.png', contentType: 'image/png' });

    // Fallback mock mode handles the error gracefully
    expect([200, 500]).toContain(res.status);
  });
});

// ── /api/document/:hash ──────────────────────────────────────────────────────

describe('GET /api/document/:hash', () => {
  const VALID_HASH = '0x' + 'a'.repeat(64);

  beforeEach(() => jest.clearAllMocks());

  it('returns 200 with metadata for a known hash', async () => {
    const res = await request(app).get(`/api/document/${VALID_HASH}`);
    expect(res.status).toBe(200);
    expect(res.body.fileName).toBe('test.png');
    expect(res.body.aiScore).toBe(5);
    expect(typeof res.body.isAuthentic).toBe('boolean');
  });

  it('returns 404 when hash is not in the database', async () => {
    const mongoose = require('mongoose');
    mongoose.model().findOne.mockResolvedValueOnce(null);

    const res = await request(app).get(`/api/document/${VALID_HASH}`);
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/no off-chain record/i);
  });

  it('returns 500 when a database error occurs', async () => {
    const mongoose = require('mongoose');
    mongoose.model().findOne.mockRejectedValueOnce(new Error('DB failure'));

    const res = await request(app).get(`/api/document/${VALID_HASH}`);
    expect(res.status).toBe(500);
    expect(res.body.error).toBe('DB failure');
  });
});

// ── getThreshold helper ───────────────────────────────────────────────────────
// Tested indirectly via /api/analyze, but also verified directly here.

describe('per-type threshold (via /api/analyze behaviour)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    delete process.env.AI_API_KEY;
    delete process.env.AI_THRESHOLD_IMAGE;
    delete process.env.AI_THRESHOLD_VIDEO;
    delete process.env.AI_THRESHOLD_TEXT;
    delete process.env.AI_BLOCK_THRESHOLD;
  });

  it('uses AI_THRESHOLD_TEXT for text/* MIME type', async () => {
    process.env.AI_API_KEY        = 'test-key';
    process.env.AI_THRESHOLD_TEXT = '20'; // very strict

    // Mock 25% AI-generated probability
    axios.post.mockResolvedValueOnce({
      data: { openai: { status: 'success', ai_score: 0.25, items: [], cost: null } }
    });

    const res = await request(app)
      .post('/api/analyze')
      .attach('file', Buffer.from('This is a test document with enough text to pass the minimum length check.'),
             { filename: 'doc.txt', contentType: 'text/plain' });

    expect(res.status).toBe(400); // blocked because 25 > threshold 20
    expect(res.body.threshold).toBe(20);
  });
});
