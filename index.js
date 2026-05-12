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

// Handle INIT — show Trade_Details screen
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

// Handle Trade_Details screen — route to correct next screen
if (plain.action === 'data_exchange' && plain.screen === 'Trade_Details') {
  const category = plain.data && plain.data.trade_category;

  if (category === 'new_trade') {
    // Go to New Trade text input screen
    const responseData = {
      version: '3.0',
      screen: 'New_Trade_Screen',
      data: {}
    };
    const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
    const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
    return res.send(result.toString('base64'));
  }

  if (category === 'addendum') {
    // Fetch approved trades from Make.com to populate dropdown
    console.log('Fetching approved trades for addendum dropdown...');
    const makeResponse = await fetch(MAKE_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get_approved_trades' })
    });
    const rawText = await makeResponse.text();
    console.log('Make.com approved trades response:', rawText);

    let approvedTrades = [];
    try {
      const parsed = JSON.parse(rawText);
      approvedTrades = parsed.trades || [];
    } catch (e) {
      console.error('Failed to parse approved trades:', rawText);
    }

    const responseData = {
      version: '3.0',
      screen: 'Addendum_Screen',
      data: {
        approved_trades: approvedTrades.length > 0 ? approvedTrades : [
          { id: 'none', title: 'No approved trades found' }
        ]
      }
    };
    const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
    const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
    return res.send(result.toString('base64'));
  }
}

// Handle New_Trade_Screen submission — forward to Make.com Flow Handler
if (plain.action === 'data_exchange' && plain.screen === 'New_Trade_Screen') {
  console.log('New trade submission, forwarding to Make.com...');
  const makeResponse = await fetch(MAKE_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'new_trade',
      direction: plain.data && plain.data.direction,
      trade_text: plain.data && plain.data.trade_text
    })
  });
  const rawText = await makeResponse.text();
  console.log('Make.com new trade response:', rawText);

  // Return success screen regardless — Trade Capture handles async processing
  const responseData = {
    version: '3.0',
    screen: 'success_screen',
    data: { is_success: true, message: 'Your trade has been submitted successfully.' }
  };
  const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
  return res.send(result.toString('base64'));
}

// Handle Addendum_Screen submission
if (plain.action === 'data_exchange' && plain.screen === 'Addendum_Screen') {
  console.log('Addendum submission, forwarding to Make.com...');
  const makeResponse = await fetch(MAKE_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'addendum',
      mercancia_ref: plain.data && plain.data.selected_trade,
      addendum_text: plain.data && plain.data.addendum_text
    })
  });
  const rawText = await makeResponse.text();
  console.log('Make.com addendum response:', rawText);

  const responseData = {
    version: '3.0',
    screen: 'success_screen',
    data: { is_success: true, message: 'Your addendum has been submitted successfully.' }
  };
  const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
  return res.send(result.toString('base64'));
}

// Fallback
console.error('Unhandled action/screen:', plain.action, plain.screen);
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
res.send(result.toString('base64'));
```

} catch (err) {
console.error(‘Unhandled error:’, err);
res.status(500).send(‘error’);
}
});

app.listen(process.env.PORT || 3000, function() { console.log(‘running’); });
