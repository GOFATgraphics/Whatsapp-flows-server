const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

app.get('/', (req, res) => res.send('running'));

app.post('/webhook', async (req, res) => {
  try {
    const encAesKey = Buffer.from(req.body.encrypted_aes_key, 'base64');
    const encData = Buffer.from(req.body.encrypted_flow_data, 'base64');
    const iv = Buffer.from(req.body.initial_vector, 'base64');

    const privateKeyPem = Buffer.from(PRIVATE_KEY_B64, 'base64').toString('utf8').trim();

    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      type: 'pkcs8'
    });

    const aesKey = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, encAesKey);

    const tag = encData.subarray(-16);
    const body = encData.subarray(0, -16);
    const dec = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
    dec.setAuthTag(tag);
    const plain = JSON.parse(dec.update(body, undefined, 'utf8') + dec.final('utf8'));

    const flippedIv = Buffer.from(iv.map(b => ~b));

    console.log('→ Action:', plain.action, '| Screen:', plain.screen);

    // HEALTH CHECK
    if (plain.action === 'ping') {
      const resp = { version: '3.0', data: { status: 'active' } };
      const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
      const result = Buffer.concat([enc.update(JSON.stringify(resp), 'utf8'), enc.final(), enc.getAuthTag()]);
      return res.send(result.toString('base64'));
    }

    // INITIAL SCREEN LOAD - This is the critical part
    if (plain.action === 'INIT' || !plain.screen || plain.screen === 'Trade_Details') {
      const responseData = {
        version: "3.0",
        screen: "Trade_Details",
        data: {
          direction_options: [
            { id: "purchase", title: "Purchase" },
            { id: "sale", title: "Sale" }
          ],
          category_options: [
            { id: "new_trade", title: "New Trade" },
            { id: "addendum", title: "Addendum" }
          ]
        }
      };

      const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
      const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
      return res.send(result.toString('base64'));
    }

    // Everything else → Forward to Make.com
    const makeResponse = await fetch(MAKE_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(plain)
    });

    let responseData = { version: "3.0", screen: "success_screen", data: {} };
    try {
      const text = await makeResponse.text();
      if (text && text.trim()) responseData = JSON.parse(text);
    } catch (e) {}

    const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
    const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
    res.send(result.toString('base64'));

  } catch (err) {
    console.error('ERROR:', err.message);
    res.status(500).send('error');
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Server running'));
