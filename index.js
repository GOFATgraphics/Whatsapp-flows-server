const express = require('express');
const crypto = require('crypto');

const app = express();

app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

// ================= ENCRYPT RESPONSE =================
function encryptResponse(aesKey, iv, data) {
  const cipher = crypto.createCipheriv(
    'aes-128-gcm',
    aesKey,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return Buffer.concat([encrypted, tag]).toString('base64');
}

// ================= SEND HELPER =================
function send(res, aesKey, iv, payload) {
  return res.send(encryptResponse(aesKey, iv, payload));
}

// ================= WEBHOOK =================
app.post('/webhook', async (req, res) => {
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

    const privateKeyPem = Buffer.from(
      PRIVATE_KEY_B64,
      'base64'
    )
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

    const decipher = crypto.createDecipheriv(
      'aes-128-gcm',
      aesKey,
      iv
    );

    decipher.setAuthTag(tag);

    const plain = JSON.parse(
      decipher.update(body, undefined, 'utf8') +
      decipher.final('utf8')
    );

    const flippedIv = Buffer.from(
      iv.map((b) => ~b)
    );

    console.log(
      'Action:',
      plain.action,
      'Screen:',
      plain.screen
    );

    // ================= PING =================
    if (plain.action === 'ping') {
      return send(res, aesKey, flippedIv, {
        version: '7.0',
        data: {
          status: 'active',
        },
      });
    }

    // ================= INIT =================
    if (plain.action === 'INIT' || !plain.screen) {
      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Trade_Details',
        data: {
          direction_options: [
            {
              id: 'purchase',
              title: 'Purchase',
            },
            {
              id: 'sale',
              title: 'Sale',
            },
          ],
          category_options: [
            {
              id: 'new_trade',
              title: 'New Trade',
            },
            {
              id: 'addendum',
              title: 'Addendum',
            },
          ],
        },
      });
    }

    // ================= TRADE_DETAILS =================
    if (plain.screen === 'Trade_Details') {
      const category = plain.data?.trade_category;

      // ===== NEW TRADE =====
      if (category === 'new_trade') {
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'New_Trade_Screen',
          data: {},
        });
      }

      // ===== ADDENDUM =====
      if (category === 'addendum') {
        let approvedTrades = [
          {
            id: 'MC-0000000000',
            title: 'No trades available',
          },
        ];

        try {
          const response = await fetch(
            MAKE_WEBHOOK_URL,
            {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                action: 'get_approved_trades',
              }),
            }
          );

          const text = await response.text();

          if (text && text !== 'Accepted') {
            const makeData = JSON.parse(text);

            if (makeData.approved_trades) {
              approvedTrades =
                makeData.approved_trades;
            }
          }
        } catch (e) {
          console.log(
            'Make error:',
            e.message
          );
        }

        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Addendum_Screen',
          data: {
            approved_trades: approvedTrades,
          },
        });
      }
    }

    // ================= NEW TRADE SCREEN =================
    // Fire to Make.com WITHOUT waiting
    if (plain.screen === 'New_Trade_Screen') {
      fetch(MAKE_WEBHOOK_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          object: 'whatsapp_business_account',
          entry: [
            {
              id: '1686018449053242',
              changes: [
                {
                  value: {
                    messaging_product: 'whatsapp',
                    metadata: {
                      display_phone_number:
                        '2349036262127',
                      phone_number_id:
                        '1092681490597909',
                    },
                    contacts: [
                      {
                        profile: {
                          name: 'Trader',
                        },
                        wa_id: plain.flow_token,
                      },
                    ],
                    messages: [
                      {
                        from: plain.flow_token,
                        id: 'flow_' + Date.now(),
                        timestamp: Math.floor(
                          Date.now() / 1000
                        ).toString(),
                        type: 'interactive',
                        interactive: {
                          type: 'flow_reply',
                          flow_reply: {
                            response_json: plain.data,
                          },
                        },
                      },
                    ],
                  },
                  field: 'messages',
                },
              ],
            },
          ],
        }),
      }).catch((err) => {
        console.error(
          'Make.com error:',
          err
        );
      });

      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'success_screen',
        data: {},
      });
    }

    // ================= FALLBACK =================
    return send(res, aesKey, flippedIv, {
      version: '7.0',
      screen: 'success_screen',
      data: {},
    });

  } catch (err) {
    console.error(err);

    return res.status(500).send('error');
  }
});

// ================= SERVER =================
app.get('/', (req, res) => {
  res.send('running');
});

app.listen(process.env.PORT || 3000, () => {
  console.log('running');
});
