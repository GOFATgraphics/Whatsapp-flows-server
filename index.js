const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());
const PRIVATE_KEY = Buffer.from(process.env.PRIVATE_KEY_B64, 'base64').toString('utf8');
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;
app.get('/', function(req, res) { res.send('running'); });
app.post('/webhook', async function(req, res) {
try {
const encAesKey = Buffer.from(req.body.encrypted_aes_key, 'base64');
const encData = Buffer.from(req.body.encrypted_flow_data, 'base64');
const iv = Buffer.from(req.body.initial_vector, 'base64');
const aesKey = crypto.privateDecrypt({ key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, encAesKey);
const tag = encData.subarray(-16);
const body = encData.subarray(0, -16);
const dec = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
dec.setAuthTag(tag);
const plain = JSON.parse(dec.update(body, undefined, 'utf8') + dec.final('utf8'));
const flippedIv = Buffer.from(iv.map(function(b) { return ~b; }));
const responseData = plain.action === 'ping' ? { version: '3.0', data: { status: 'active' } } : { version: '3.0', screen: 'SUCCESS', data: {} };
const enc = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
const result = Buffer.concat([enc.update(JSON.stringify(responseData), 'utf8'), enc.final(), enc.getAuthTag()]);
if (MAKE_WEBHOOK_URL && plain.action !== 'ping') { fetch(MAKE_WEBHOOK_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(plain) }); }
res.send(result.toString('base64'));
} catch(err) { console.error(err); res.status(500).send('error'); }
});
app.listen(process.env.PORT || 3000, function() { console.log('running'); });
