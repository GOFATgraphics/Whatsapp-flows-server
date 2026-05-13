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

    const privateKeyPem = Buffer.from(PRIVATE_KEY_B64, 'base64')
      .toString('utf8')
      .trim();

    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      type: 'pkcs8',
    });

    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encAesKey
    );

    const tag = encData.subarray(-16);
    const body = encData.subarray(0, -16);

    const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
    decipher.setAuthTag(tag);

    const plain = JSON.parse(
      decipher.update(body, undefined, 'utf8') + decipher.final('utf8')
    );

    const flippedIv = Buffer.from(iv.map(b => ~b));

    console.log('Received → Action:', plain.action, '| Screen:', plain.screen);

    // ================= HEALTH CHECK =================
    if (plain.action === 'ping') {
      const responseData = {
        version: '7.0',
        data: { status: 'active' },
      };

      const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
      const result = Buffer.concat([
        enc.update(JSON.stringify(responseData), 'utf8'),
        enc.final(),
        enc.getAuthTag(),
      ]);

      return res.send(result.toString('base64'));
    }

    // =============== INITIAL SCREEN =================
    if (plain.action === 'INIT' || !plain.screen) {
      const responseData = {
        version: '7.0',
        screen: 'Trade_Details',
        data: {
          direction_options: [
            { id: 'purchase', title: 'Purchase' },
            { id: 'sale', title: 'Sale' },
          ],
          category_options: [
            { id: 'new_trade', title: 'New Trade' },
            { id: 'addendum', title: 'Addendum' },
          ],
        },
      };

      const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
      const result = Buffer.concat([
        enc.update(JSON.stringify(responseData), 'utf8'),
        enc.final(),
        enc.getAuthTag(),
      ]);

      return res.send(result.toString('base64'));
    }

    // =============== SEND TO MAKE.COM =================
    console.log('Forwarding to Make.com');

    let makeData = {};

    try {
      const makeResponse = await fetch(MAKE_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(plain),
      });

      const text = await makeResponse.text();

      if (text && text.trim()) {
        makeData = JSON.parse(text);
      }
    } catch (err) {
      console.log('Make.com error:', err.message);
    }

    // ================= SAFE MERGE =================
    const responseData = {
      version: '7.0',
      screen: makeData.screen || 'success_screen',
      data: {
        // ALWAYS preserve these so buttons never disappear
        direction_options: [
          { id: 'purchase', title: 'Purchase' },
          { id: 'sale', title: 'Sale' },
        ],
        category_options: [
          { id: 'new_trade', title: 'New Trade' },
          { id: 'addendum', title: 'Addendum' },
        ],

        // allow Make.com to add extra fields safely
        ...(makeData.data || {}),
      },
    };

    const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
    const result = Buffer.concat([
      enc.update(JSON.stringify(responseData), 'utf8'),
      enc.final(),
      enc.getAuthTag(),
    ]);

    return res.send(result.toString('base64'));
  } catch (err) {
    console.error('ERROR:', err.message);
    res.status(500).send('error');
  }
});

app.listen(process.env.PORT || 3000, () =>
  console.log('Server running')
);
