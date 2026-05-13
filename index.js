const express = require('express');
const crypto = require('crypto');

const app = express();

app.use(express.json());

const PRIVATE_KEY = Buffer.from(
  process.env.PRIVATE_KEY_B64,
  'base64'
).toString('utf8');

const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

app.get('/', function (req, res) {
  res.send('running');
});

app.post('/webhook', async function (req, res) {
  try {
    const encAesKey = Buffer.from(
      req.body.encrypted_aes_key,
      'base64'
    );

    const encData = Buffer.from(
      req.body.encrypted_flow_data,
      'base64'
    );

    const iv = Buffer.from(
      req.body.initial_vector,
      'base64'
    );

    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      encAesKey
    );

    const tag = encData.subarray(-16);
    const body = encData.subarray(0, -16);

    const dec = crypto.createDecipheriv(
      'aes-128-gcm',
      aesKey,
      iv
    );

    dec.setAuthTag(tag);

    const plain = JSON.parse(
      dec.update(body, undefined, 'utf8') +
      dec.final('utf8')
    );

    const flippedIv = Buffer.from(
      iv.map(function (b) {
        return ~b;
      })
    );

    const encrypt = (data) => {
      const enc = crypto.createCipheriv(
        'aes-128-gcm',
        aesKey,
        flippedIv
      );

      return Buffer.concat([
        enc.update(JSON.stringify(data), 'utf8'),
        enc.final(),
        enc.getAuthTag()
      ]).toString('base64');
    };

    // Health check
    if (plain.action === 'ping') {
      return res.send(
        encrypt({
          version: '3.0',
          data: {
            status: 'active'
          }
        })
      );
    }

    // Initial screen load
    if (plain.action === 'INIT') {
      return res.send(
        encrypt({
          version: '3.0',
          screen: 'Trade_Details',
          data: {}
        })
      );
    }

    // New Trade submitted
    // Fire to Make.com WITHOUT waiting
    if (plain.screen === 'New_Trade_Screen') {
      fetch(MAKE_WEBHOOK_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(plain)
      }).catch((err) => {
        console.error('Make.com error:', err);
      });

      return res.send(
        encrypt({
          version: '3.0',
          screen: 'success_screen',
          data: {}
        })
      );
    }

    // Trade_Details
    // Route to next screen
    if (plain.screen === 'Trade_Details') {
      if (plain.data.trade_category === 'new_trade') {
        return res.send(
          encrypt({
            version: '3.0',
            screen: 'New_Trade_Screen',
            data: {}
          })
        );
      }

      if (plain.data.trade_category === 'addendum') {
        // Fetch approved trades from Make.com
        const makeResponse = await fetch(
          MAKE_WEBHOOK_URL,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(plain)
          }
        );

        const responseData = await makeResponse.json();

        return res.send(encrypt(responseData));
      }
    }

    // Addendum submitted
    // Forward to Make.com and wait
    const makeResponse = await fetch(
      MAKE_WEBHOOK_URL,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(plain)
      }
    );

    const responseData = await makeResponse.json();

    res.send(encrypt(responseData));

  } catch (err) {
    console.error(err);
    res.status(500).send('error');
  }
});

app.listen(process.env.PORT || 3000, function () {
  console.log('running');
})
