const express = require(‘express’);
const crypto = require(‘crypto’);

const app = express();
app.use(express.json());

// Your private key - paste the full content of private_key.pem here
const PRIVATE_KEY = process.env.PRIVATE_KEY;

// Your Make.com webhook URL for processing actual trades
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

function decryptRequest(body, privatePem) {
const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

// Decrypt the AES key using RSA private key
const decryptedAesKey = crypto.privateDecrypt(
{
key: privatePem,
padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
oaepHash: ‘sha256’,
},
Buffer.from(encrypted_aes_key, ‘base64’)
);

// Decrypt the flow data using AES-GCM
const iv = Buffer.from(initial_vector, ‘base64’);
const encryptedData = Buffer.from(encrypted_flow_data, ‘base64’);
const TAG_LENGTH = 16;
const encryptedBody = encryptedData.subarray(0, -TAG_LENGTH);
const authTag = encryptedData.subarray(-TAG_LENGTH);

const decipher = crypto.createDecipheriv(‘aes-128-gcm’, decryptedAesKey, iv);
decipher.setAuthTag(authTag);

const decryptedData =
decipher.update(encryptedBody, undefined, ‘utf8’) + decipher.final(‘utf8’);

return {
decryptedBody: JSON.parse(decryptedData),
aesKeyBuffer: decryptedAesKey,
ivBuffer: iv,
};
}

function encryptResponse(responseData, aesKeyBuffer, ivBuffer) {
// Flip the IV
const flippedIv = Buffer.alloc(ivBuffer.length);
for (let i = 0; i < ivBuffer.length; i++) {
flippedIv[i] = ~ivBuffer[i];
}

const cipher = crypto.createCipheriv(‘aes-128-gcm’, aesKeyBuffer, flippedIv);
const encryptedResponse = Buffer.concat([
cipher.update(JSON.stringify(responseData), ‘utf8’),
cipher.final(),
cipher.getAuthTag(),
]);

return encryptedResponse.toString(‘base64’);
}

// Health check endpoint for your server
app.get(’/’, (req, res) => {
res.send(‘WhatsApp Flows Server is running’);
});

// Main WhatsApp Flows endpoint
app.post(’/webhook’, async (req, res) => {
try {
const { decryptedBody, aesKeyBuffer, ivBuffer } = decryptRequest(
req.body,
PRIVATE_KEY
);

```
console.log('Decrypted request:', JSON.stringify(decryptedBody, null, 2));

// Check if this is a health check
if (decryptedBody.action === 'ping') {
  const response = encryptResponse(
    { version: '3.0', data: { status: 'active' } },
    aesKeyBuffer,
    ivBuffer
  );
  return res.send(response);
}

// For real flow submissions - forward to Make.com
if (MAKE_WEBHOOK_URL) {
  const makeResponse = await fetch(MAKE_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(decryptedBody),
  });
  console.log('Make.com response:', makeResponse.status);
}

// Send back success response to WhatsApp
const response = encryptResponse(
  {
    version: '3.0',
    screen: 'SUCCESS',
    data: { extension_message_response: { params: { flow_token: decryptedBody.flow_token } } },
  },
  aesKeyBuffer,
  ivBuffer
);

res.send(response);
```

} catch (err) {
console.error(‘Error processing request:’, err);
res.status(500).send(‘Internal Server Error’);
}
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
console.log(`Server running on port ${PORT}`);
});
