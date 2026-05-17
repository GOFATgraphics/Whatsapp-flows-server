const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const FLOW_HANDLER_WEBHOOK_URL = process.env.FLOW_HANDLER_WEBHOOK_URL;

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

    console.log('Action:', plain.action, 'Screen:', plain.screen);

    // ================= PING =================
    if (plain.action === 'ping') {
      return send(res, aesKey, flippedIv, {
        version: '7.0',
        data: { status: 'active' }
      });
    }

    // ================= INIT =================
    if (plain.action === 'INIT' || !plain.screen) {
      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Trade_Details',
        data: {
          direction_options: [
            { id: 'purchase', title: 'Purchase' },
            { id: 'sale', title: 'Sale' }
          ],
          trade_type_options: [
            { id: 'new_trade', title: 'New Trade' },
            { id: 'linked_trade', title: 'Linked Trade' },
            { id: 'modification', title: 'Modification' },
            { id: 'addendum', title: 'Addendum' }
          ]
        }
      });
    }

    // ================= HELPER — fetch with timeout =================
    async function fetchWithTimeout(url, options, timeoutMs = 4000) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeout);
        return response;
      } catch (e) {
        clearTimeout(timeout);
        throw e;
      }
    }

    // ================= TRADE DETAILS SCREEN =================
    if (plain.screen === 'Trade_Details') {
      const trade_type = plain.data?.trade_type;
      const direction = plain.data?.direction;

      console.log('trade_type:', trade_type, 'direction:', direction);

      // ---- New Trade ----
      if (trade_type === 'new_trade') {
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'New_Trade_Screen',
          data: { direction }
        });
      }

      // ---- Linked Trade ----
      if (trade_type === 'linked_trade') {
        let active_trades = [{ id: 'none', title: 'No active trades found' }];

        try {
          const response = await fetchWithTimeout(FLOW_HANDLER_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'get_active_trades' })
          });
          const text = await response.text();
          if (text && text !== 'Accepted') {
            const data = JSON.parse(text);
            if (data.active_trades?.length > 0) {
              active_trades = data.active_trades;
            }
          }
        } catch (e) {
          console.log('Flow Handler error:', e.message);
        }

        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Linked_Trade_Screen',
          data: { direction, active_trades }
        });
      }

      // ---- Modification ----
      if (trade_type === 'modification') {
        let approved_trades = [{ id: 'none', title: 'No approved trades found' }];

        try {
          const response = await fetchWithTimeout(FLOW_HANDLER_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'get_approved_trades' })
          });
          const text = await response.text();
          if (text && text !== 'Accepted') {
            const data = JSON.parse(text);
            if (data.approved_trades?.length > 0) {
              approved_trades = data.approved_trades;
            }
          }
        } catch (e) {
          console.log('Flow Handler error:', e.message);
        }

        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Modification_Screen',
          data: { approved_trades }
        });
      }

      // ---- Addendum ----
      if (trade_type === 'addendum') {
        let approved_trades = [{ id: 'none', title: 'No approved trades found' }];

        try {
          const response = await fetchWithTimeout(FLOW_HANDLER_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'get_approved_trades' })
          });
          const text = await response.text();
          if (text && text !== 'Accepted') {
            const data = JSON.parse(text);
            if (data.approved_trades?.length > 0) {
              approved_trades = data.approved_trades;
            }
          }
        } catch (e) {
          console.log('Flow Handler error:', e.message);
        }

        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Addendum_Screen',
          data: { approved_trades }
        });
      }
    }

    // ================= NEW TRADE SCREEN =================
    if (plain.screen === 'New_Trade_Screen') {
      fetch(FLOW_HANDLER_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'new_trade',
          direction: plain.data?.direction,
          trade_text: plain.data?.trade_text,
          from: plain.flow_token
        })
      }).catch(e => console.log('Flow Handler error:', e.message));

      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Success_Screen',
        data: {}
      });
    }

    // ================= ADDENDUM SCREEN =================
    if (plain.screen === 'Addendum_Screen') {
      fetch(FLOW_HANDLER_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'addendum',
          selected_trade: plain.data?.selected_trade,
          addendum_text: plain.data?.addendum_text,
          from: plain.flow_token
        })
      }).catch(e => console.log('Flow Handler error:', e.message));

      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Success_Screen',
        data: {}
      });
    }

    // ================= MODIFICATION SCREEN =================
    if (plain.screen === 'Modification_Screen') {
      fetch(FLOW_HANDLER_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'modification',
          selected_trade: plain.data?.selected_trade,
          modification_text: plain.data?.modification_text,
          from: plain.flow_token
        })
      }).catch(e => console.log('Flow Handler error:', e.message));

      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Success_Screen',
        data: {}
      });
    }

    // ================= LINKED TRADE SCREEN =================
    if (plain.screen === 'Linked_Trade_Screen') {
      fetch(FLOW_HANDLER_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'linked_trade',
          direction: plain.data?.direction,
          parent_trade: plain.data?.parent_trade,
          trade_text: plain.data?.trade_text,
          from: plain.flow_token
        })
      }).catch(e => console.log('Flow Handler error:', e.message));

      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Success_Screen',
        data: {}
      });
    }

    // ================= FALLBACK =================
    return send(res, aesKey, flippedIv, {
      version: '7.0',
      screen: 'Success_Screen',
      data: {}
    });

  } catch (err) {
    console.error('Server error:', err);
    res.status(500).send('error');
  }
});

function send(res, aesKey, iv, data) {
  const enc = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
  const result = Buffer.concat([
    enc.update(JSON.stringify(data), 'utf8'),
    enc.final(),
    enc.getAuthTag()
  ]);
  res.send(result.toString('base64'));
}

app.listen(3000, () => console.log('Server running'));
