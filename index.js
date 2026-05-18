const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const FLOW_HANDLER_WEBHOOK_URL = process.env.FLOW_HANDLER_WEBHOOK_URL;

app.post('/webhook', async (req, res) => {
  try {
    // ================= DECRYPT =================
    const encAesKey = Buffer.from(req.body.encrypted_aes_key, 'base64');
    const encData = Buffer.from(req.body.encrypted_flow_data, 'base64');
    const iv = Buffer.from(req.body.initial_vector, 'base64');

    const privateKeyPem = Buffer.from(PRIVATE_KEY_B64, 'base64').toString('utf8').trim();

    const privateKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem', type: 'pkcs8' });

    const aesKey = crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, encAesKey);

    const tag = encData.subarray(-16);
    const body = encData.subarray(0, -16);

    const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
    decipher.setAuthTag(tag);

    const plain = JSON.parse(decipher.update(body, undefined, 'utf8') + decipher.final('utf8'));
    const flippedIv = Buffer.from(iv.map(b => ~b));

    console.log('Action:', plain.action, 'Screen:', plain.screen);

    // PING & INIT
    if (plain.action === 'ping') {
      return send(res, aesKey, flippedIv, { version: '7.0', data: { status: 'active' } });
    }

    if (plain.action === 'INIT' || !plain.screen) {
      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Trade_Details',
        data: {
          direction_options: [{ id: 'purchase', title: 'Purchase' }, { id: 'sale', title: 'Sale' }],
          trade_type_options: [
            { id: 'new_trade', title: 'New Trade' },
            { id: 'linked_trade', title: 'Linked Trade' },
            { id: 'modification', title: 'Modification' },
            { id: 'addendum', title: 'Addendum' }
          ]
        }
      });
    }

    // ================= TRADE DETAILS SCREEN =================
    if (plain.screen === 'Trade_Details') {
      const trade_type = plain.data?.trade_type;
      const direction = plain.data?.direction;

      if (trade_type === 'new_trade') {
        return send(res, aesKey, flippedIv, { version: '7.0', screen: 'New_Trade_Screen', data: { direction } });
      }

      // For screens that need trade list
      if (['linked_trade', 'addendum', 'modification'].includes(trade_type)) {
        let trades = [{ id: 'none', title: 'No trades found' }];

        try {
          const response = await fetch(FLOW_HANDLER_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'get_approved_trades' }),
            signal: AbortSignal.timeout(8000)   // 8 second timeout
          });

          const text = await response.text();
          if (text && text !== 'Accepted') {
            const data = JSON.parse(text);
            if (data.approved_trades?.length > 0) {
              trades = data.approved_trades;
            }
          }
        } catch (e) {
          console.error('Failed to fetch trades:', e.message);
          // Fallback list so flow doesn't break
          trades = [{ id: 'none', title: 'Error loading trades - Please try again' }];
        }

        let screenName = 'Addendum_Screen';
        let dataPayload = { approved_trades: trades };

        if (trade_type === 'linked_trade') {
          screenName = 'Linked_Trade_Screen';
          dataPayload = { direction, active_trades: trades };
        } else if (trade_type === 'modification') {
          screenName = 'Modification_Screen';
        }

        return send(res, aesKey, flippedIv, { version: '7.0', screen: screenName, data: dataPayload });
      }
    }

    // ================= SUBMIT SCREENS (Fire and Forget) =================
    const screen = plain.screen;

    if (screen === 'New_Trade_Screen' || screen === 'Linked_Trade_Screen' || 
        screen === 'Addendum_Screen' || screen === 'Modification_Screen') {
      
      fireAndForget(plain);
      return sendSuccess(res, aesKey, flippedIv);
    }

    return sendSuccess(res, aesKey, flippedIv);

  } catch (err) {
    console.error('Server error:', err);
    res.status(500).send('error');
  }
});

// ====================== HELPERS ======================
function fireAndForget(plain) {
  const payload = {
    action: plain.screen === 'New_Trade_Screen' ? 'new_trade' :
            plain.screen === 'Linked_Trade_Screen' ? 'linked_trade' :
            plain.screen === 'Addendum_Screen' ? 'addendum' : 'modification',
    direction: plain.data?.direction,
    trade_text: plain.data?.trade_text,
    parent_trade: plain.data?.parent_trade,
    selected_trade: plain.data?.selected_trade,
    addendum_text: plain.data?.addendum_text,
    modification_text: plain.data?.modification_text,
    from: plain.flow_token
  };

  fetch(FLOW_HANDLER_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).catch(e => console.log('Background error:', e.message));
}

function sendSuccess(res, aesKey, iv) {
  return send(res, aesKey, iv, { version: '7.0', screen: 'Success_Screen', data: {} });
}

function send(res, aesKey, iv, data) {
  const enc = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
  const result = Buffer.concat([enc.update(JSON.stringify(data), 'utf8'), enc.final(), enc.getAuthTag()]);
  res.send(result.toString('base64'));
}

app.listen(3000, () => console.log('WhatsApp Flow Server running on port 3000'));
