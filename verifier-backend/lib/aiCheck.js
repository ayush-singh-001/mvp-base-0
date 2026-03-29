'use strict';
/**
 * lib/aiCheck.js
 * AI deepfake / synthetic-content detection helpers.
 *
 * Supports:
 *   - Eden AI  (image, text/PDF, video)
 *   - Reality Defender (images and video)
 *   - Mock fallback  (when no API key is configured)
 *
 * Exported functions:
 *   getThreshold(mimeType) → Number
 *   checkAuthenticity(buffer, fileName, mimeType) → { score, provider, details }
 */

const axios    = require('axios');
const FormData = require('form-data');

// ── Threshold helpers ─────────────────────────────────────────────────────────
function getThreshold(mimeType) {
  const fallback = Number(process.env.AI_BLOCK_THRESHOLD) || 80;
  if (!mimeType) return fallback;
  if (mimeType.startsWith('image/'))
    return Number(process.env.AI_THRESHOLD_IMAGE) || fallback;
  if (mimeType.startsWith('video/'))
    return Number(process.env.AI_THRESHOLD_VIDEO) || fallback;
  if (mimeType === 'application/pdf' || mimeType.startsWith('text/'))
    return Number(process.env.AI_THRESHOLD_TEXT) || fallback;
  return fallback;
}

// ── Eden AI: image ────────────────────────────────────────────────────────────
async function edenImageCheck(fileBuffer, fileName) {
  const edenProvider = process.env.AI_PROVIDER || 'winstonai';
  const form = new FormData();
  form.append('providers', edenProvider);
  form.append('file', fileBuffer, { filename: fileName });

  const response = await axios.post(
    'https://api.edenai.run/v2/image/ai_detection',
    form,
    { headers: { ...form.getHeaders(), Authorization: `Bearer ${process.env.AI_API_KEY}` } }
  );

  const result = response.data[edenProvider];
  if (!result || result.status !== 'success') {
    throw new Error(`Eden AI (image) provider "${edenProvider}" status: ${result?.status ?? 'unknown'}`);
  }

  const score = (result.ai_score ?? 0) * 100;
  console.log(`[AI] Eden AI image (${edenProvider}): ${score.toFixed(1)}%`);
  return {
    score,
    provider: `eden_ai:${edenProvider}`,
    details: { ai_score: result.ai_score, items: result.items ?? [], cost: result.cost ?? null }
  };
}

// ── Eden AI: text / PDF ───────────────────────────────────────────────────────
async function edenTextCheck(fileBuffer, fileName, mimeType) {
  const edenProvider = process.env.AI_PROVIDER || 'openai';

  let text;
  if (mimeType === 'application/pdf') {
    try {
      const pdfParse = require('pdf-parse');
      const parsed   = await pdfParse(fileBuffer);
      text = parsed.text;
    } catch (e) {
      console.warn('[AI] pdf-parse failed, using raw buffer as text:', e.message);
      text = fileBuffer.toString('utf8', 0, 4096);
    }
  } else {
    text = fileBuffer.toString('utf8', 0, 4096);
  }

  if (!text || text.trim().length < 10) {
    throw new Error('Extracted text is too short for AI text detection.');
  }

  const response = await axios.post(
    'https://api.edenai.run/v2/text/ai_detection',
    { providers: edenProvider, text },
    { headers: { Authorization: `Bearer ${process.env.AI_API_KEY}`, 'Content-Type': 'application/json' } }
  );

  const result = response.data[edenProvider];
  if (!result || result.status !== 'success') {
    throw new Error(`Eden AI (text) provider "${edenProvider}" status: ${result?.status ?? 'unknown'}`);
  }

  const score = (result.ai_score ?? 0) * 100;
  console.log(`[AI] Eden AI text (${edenProvider}): ${score.toFixed(1)}%`);
  return {
    score,
    provider: `eden_ai:text:${edenProvider}`,
    details: { ai_score: result.ai_score, items: result.items ?? [], cost: result.cost ?? null }
  };
}
async function edenVideoCheck(fileBuffer, fileName) {
  const edenProvider = process.env.AI_PROVIDER || 'deepware';
  const form = new FormData();
  form.append('providers', edenProvider);
  form.append('file', fileBuffer, { filename: fileName });

  const submitRes = await axios.post(
    'https://api.edenai.run/v2/video/deepfake_detection',
    form,
    { headers: { ...form.getHeaders(), Authorization: `Bearer ${process.env.AI_API_KEY}` } }
  );

  const jobId = submitRes.data?.public_id;
  if (!jobId) throw new Error('Eden AI video: no job ID returned.');

  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 3000));
    const poll = await axios.get(`https://api.edenai.run/v2/video/deepfake_detection/${jobId}`, {
      headers: { Authorization: `Bearer ${process.env.AI_API_KEY}` }
    });
    const result = poll.data?.[edenProvider];
    if (!result) continue;
    if (result.status === 'success') {
      const score = (result.ai_score ?? 0) * 100;
      console.log(`[AI] Eden AI video (${edenProvider}): ${score.toFixed(1)}%`);
      return {
        score,
        provider: `eden_ai:${edenProvider}`,
        details: { ai_score: result.ai_score, items: result.items ?? [], cost: result.cost ?? null }
      };
    }
    if (result.status === 'failed') throw new Error('Eden AI video job failed.');
  }
  throw new Error('Eden AI video: polling timeout (60s).');
}

// ── Reality Defender ─────────────────────────────────────────────────────────
async function checkWithRealityDefender(fileBuffer, fileName) {
  const RD_KEY = process.env.REALITY_DEFENDER_API_KEY;
  const form   = new FormData();
  form.append('file', fileBuffer, { filename: fileName });

  const uploadRes = await axios.post(
    'https://api.realitydefender.com/v1/upload',
    form,
    { headers: { ...form.getHeaders(), 'x-api-key': RD_KEY } }
  );

  const requestId = uploadRes.data?.requestId;
  if (!requestId) throw new Error('Reality Defender: no requestId returned.');

  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 4000));
    const poll = await axios.get(
      `https://api.realitydefender.com/v1/results/${requestId}`,
      { headers: { 'x-api-key': RD_KEY } }
    );
    const status = poll.data?.status;
    if (status === 'COMPLETED') {
      const score = (poll.data?.score ?? 0) * 100;
      console.log(`[AI] Reality Defender: ${score.toFixed(1)}%`);
      return {
        score,
        provider: 'reality_defender',
        details: { score: poll.data?.score, label: poll.data?.label }
      };
    }
    if (status === 'FAILED') throw new Error('Reality Defender analysis failed.');
  }
  throw new Error('Reality Defender: polling timeout (90s).');
}

// ── Orchestrator ──────────────────────────────────────────────────────────────
async function checkAuthenticity(fileBuffer, fileName, mimeType) {
  const engine = process.env.AI_ENGINE || 'eden_ai';

  const hasEdenKey = !!process.env.AI_API_KEY;
  const hasRDKey   = !!process.env.REALITY_DEFENDER_API_KEY;

  if (engine === 'reality_defender' && !hasRDKey) {
    console.log('[AI] No key for engine "reality_defender" -- mock score');
    return { score: Math.random() * 20, provider: 'mock', details: null };
  }
  if (engine === 'eden_ai' && !hasEdenKey) {
    console.log('[AI] No key for engine "eden_ai" -- mock score');
    return { score: Math.random() * 20, provider: 'mock', details: null };
  }

  try {
    if (engine === 'reality_defender') {
      return await checkWithRealityDefender(fileBuffer, fileName);
    }

    // Eden AI -- route by MIME type
    if (mimeType.startsWith('image/')) {
      return await edenImageCheck(fileBuffer, fileName);
    }
    if (mimeType.startsWith('video/')) {
      return await edenVideoCheck(fileBuffer, fileName);
    }
    return await edenTextCheck(fileBuffer, fileName, mimeType);

  } catch (aiErr) {
    console.warn(`[AI] ${engine} check failed -- falling back to mock:`,
      aiErr.response?.data ?? aiErr.message);
    return { score: Math.random() * 20, provider: 'mock:fallback', details: { error: aiErr.message } };
  }
}

module.exports = { getThreshold, checkAuthenticity };
