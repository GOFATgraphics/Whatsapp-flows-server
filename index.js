const express = require(‘express’);
const crypto = require(‘crypto’);
const app = express();
app.use(express.json());

const PRIVATE_KEY = Buffer.from(process.env.PRIVATE_KEY_B64, ‘base64’).toString(‘utf8’);
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

app.get(’/’, function(req, res) { res.send(‘running’); });

app.post(’/webhook’, async function(req, res) {
try {
const encAesKey = Buffer.from(req.body.encrypted_aes_key, ‘base64’);
const encData = Buffer.from(req.body.encrypted_flow_data, ‘base64’);
const iv = Buffer.from(req.body.initial_vector, ‘base64’);

```
const aesKey = crypto.privateDecrypt(
  { key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  encAesKey
);

const tag = encData.subarray(-16);
const body = encData.subarray(0, -16);
const dec = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
dec.setAuthTag(tag);
const plain = JSON.parse(dec.update(body, undefined, 'utf8') + dec.final('utf8'));
const flippedIv = Buffer.from(iv.map(function(b) { return ~b; }));

console.log('Decrypted payload:', JSON.stringify(plain, null, 2));

// Handle ping
if (plain.action === 'ping') {
  const responseData = { version: '3.0', data: { status: 'active' } };
  const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
  return res.send(result.toString('base64'));
}

// Handle INIT
if (plain.action === 'INIT') {
  const responseData = {
    version: '3.0',
    screen: 'Trade_Details',
    data: {
      direction_options: [
        { id: 'purchase', title: 'Purchase' },
        { id: 'sale', title: 'Sale' }
      ],
      category_options: [
        { id: 'new_trade', title: 'New Trade' },
        { id: 'addendum', title: 'Addendum' }
      ]
    }
  };
  const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
  return res.send(result.toString('base64'));
}

// Forward to Make.com
console.log('Forwarding to Make.com:', JSON.stringify(plain, null, 2));

const makeResponse = await fetch(MAKE_WEBHOOK_URL, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(plain)
});

const rawText = await makeResponse.text();
console.log('Make.com raw response:', rawText);

let responseData;
try {
  responseData = JSON.parse(rawText);
} catch (parseErr) {
  console.error('Make.com returned non-JSON:', rawText);
  responseData = {
    version: '3.0',
    screen: 'Trade_Details',
    data: {
      error_message: 'Server error. Please try again.',
      direction_options: [
        { id: 'purchase', title: 'Purchase' },
        { id: 'sale', title: 'Sale' }
      ],
      category_options: [
        { id: 'new_trade', title: 'New Trade' },
        { id: 'addendum', title: 'Addendum' }
      ]
    }
  };
}

console.log('Sending back to WhatsApp:', JSON.stringify(responseData, null, 2));

const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
const result = Buffer.concat([
  enc.update(JSON.stringify(responseData), 'utf8'),
  enc.final(),
  enc.getAuthTag()
]);
res.send(result.toString('base64'));
```

} catch (err) {
console.error(‘Unhandled error:’, err);
res.status(500).send(‘error’);
}
});

app.listen(process.env.PORT || 3000, function() { console.log(‘running’); });
