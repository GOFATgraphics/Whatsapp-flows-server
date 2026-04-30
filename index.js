const express = require(‘express’);
const crypto = require(‘crypto’);

const app = express();
app.use(express.json());

const PRIVATE_KEY = process.env.PRIVATE_KEY;
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

function decryptRequest(body, privatePem) {
const encryptedAesKey = Buffer.from(body.encrypted_aes_key, ‘base64’);
const encryptedFlowData = Buffer.from(body.encrypted_flow_data, ‘base64’);
const iv = Buffer.from(body.initial_vector, ‘base64’);

const decryptedAesKey = crypto.privateDecrypt(
{
key: privatePem,
padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
oaepHash: ‘sha256’,
},
encryptedAesKey
);

const TAG_LENGTH = 16;
const encryptedBody = encryptedFlowData.subarray(0, -TAG_LENGTH);
const authTag = encryptedFlowData.subarray(-TAG_LENGTH);

const decipher = crypto.createDecipheriv(‘aes-128-gcm’, decryptedAesKey, iv);
decipher.setAuthTag(authTag);

const decrypted = decipher.update(encryptedBody, undefined, ‘utf8’) + decipher.final(‘utf8’);

return {
decryptedBody: JSON.parse(decrypted),
aesKeyBuffer: decryptedAesKey,
ivBuffer: iv,
};
}

function encryptResponse(responseData, aesKeyBuffer, ivBuffer) {
const flippedIv = Buffer.alloc(ivBuffer.length);
for (let i = 0; i < ivBuffer.length; i++) {
flippedIv[i] = ~ivBuffer[i];
}

const cipher = crypto.createCipheriv(‘aes-128-gcm’, aesKeyBuffer, flippedIv);
const encrypted = Buffer.concat([
cipher.update(JSON.stringify(responseData), ‘utf8’),
cipher.final(),
cipher.getAuthTag(),
]);

return encrypted.toString(‘base64’);
}

app.get(’/’, function(req, res) {
res.send(‘WhatsApp Flows Server is running’);
});

app.post(’/webhook’, async function(req, res) {
try {
const result = decryptRequest(req.body, PRIVATE_KEY);
const decryptedBody = result.decryptedBody;
const aesKeyBuffer = result.aesKeyBuffer;
const ivBuffer = result.ivBuffer;

```
console.log('Decrypted:', JSON.stringify(decryptedBody));

if (decryptedBody.action === 'ping') {
  const response = encryptResponse(
    { version: '3.0', data: { status: 'active' } },
    aesKeyBuffer,
    ivBuffer
  );
  return res.send(response);
}

if (MAKE_WEBHOOK_URL) {
  await fetch(MAKE_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(decryptedBody),
  });
}

const response = encryptResponse(
  {
    version: '3.0',
    screen: 'SUCCESS',
    data: {
      extension_message_response: {
        params: { flow_token: decryptedBody.flow_token }
      }
    },
  },
  aesKeyBuffer,
  ivBuffer
);

res.send(response);
```

} catch (err) {
console.error(‘Error:’, err);
res.status(500).send(‘Internal Server Error’);
}
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
console.log(’Server running on port ’ + PORT);
});
