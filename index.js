const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const PRIVATE_KEY = process.env.PRIVATE_KEY_B64 
  ? Buffer.from(process.env.PRIVATE_KEY_B64, 'base64').toString('utf8')
  : null;

const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

app.get('/', (req, res) => res.send('running'));

app.post('/webhook', async (req, res) => {
  try {
    if (!PRIVATE_KEY) {
      throw new Error('PRIVATE_KEY_B64 environment variable is missing');
    }

    const encAesKey = Buffer.from(req.body.encrypted_aes_key, 'base64');
    const encData = Buffer.from(req.body.encrypted_flow_data, 'base64');
    const iv = Buffer.from(req.body.initial_vector, 'base64');

    // Improved private key handling
    let privateKey = PRIVATE_KEY;
    if (!privateKey.includes('BEGIN PRIVATE KEY') && !privateKey.includes('BEGIN RSA PRIVATE KEY')) {
      privateKey = `-----BEGIN RSA PRIVATE KEY-----\n${privateKey}\n-----END RSA PRIVATE KEY-----`;
    }

    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      encAesKey
    );

    const tag = encData.subarray(-16);
    const body = encData.subarray(0, -16);

    const dec = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
    dec.setAuthTag(tag);

    const plainText = dec.update(body, undefined, 'utf8') + dec.final('utf8');
    const plain = JSON.parse(plainText);

    const flippedIv = Buffer.from(iv.map(b => ~b));

    // Health check
    if (plain.action === 'ping') {
      const responseData = { version: '3.0', data: { status: 'active' } };
      const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
      const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
      return res.send(result.toString('base64'));
    }

    // Forward to Make.com
    const makeResponse = await fetch(MAKE_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(plain)
    });

    const responseData = await makeResponse.json();

    // Encrypt response back
    const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
    const result = Buffer.concat([
      enc.update(JSON.stringify(responseData), 'utf8'),
      enc.final(),
      enc.getAuthTag()
    ]);

    res.send(result.toString('base64'));

  } catch (err) {
    console.error('Error:', err.message);
    console.error(err);
    res.status(500).send('error');
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Server running'));
