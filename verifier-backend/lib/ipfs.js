'use strict';
/**
 * lib/ipfs.js
 * Pinata IPFS upload helper.
 * Returns the IPFS CID string, or null if Pinata keys are not configured.
 */
const axios    = require('axios');
const FormData = require('form-data');

async function pinToIPFS(fileBuffer, fileName) {
  const PINATA_API_KEY    = process.env.PINATA_API_KEY;
  const PINATA_SECRET_KEY = process.env.PINATA_SECRET_KEY;
  if (!PINATA_API_KEY || !PINATA_SECRET_KEY) return null;

  const form = new FormData();
  form.append('file', fileBuffer, { filename: fileName });

  const response = await axios.post(
    'https://api.pinata.cloud/pinning/pinFileToIPFS',
    form,
    {
      headers: {
        ...form.getHeaders(),
        pinata_api_key: PINATA_API_KEY,
        pinata_secret_api_key: PINATA_SECRET_KEY
      }
    }
  );
  return response.data.IpfsHash;
}

module.exports = { pinToIPFS };
