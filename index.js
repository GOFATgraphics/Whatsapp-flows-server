const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const FLOW_HANDLER_WEBHOOK_URL = process.env.FLOW_HANDLER_WEBHOOK_URL;

// ================= TRADE CACHE =================
let approvedTradesCache = [];
let activeTradesCache = [];

async function refreshCache() {
  try {
    const r1 = await fetch(FLOW_HANDLER_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get_approved_trades' })
    });
    const t1 = await r1.text();
    if (t1 && t1 !== 'Accepted') {
      const d1 = JSON.parse(t1);
      if (d1.approved_trades?.length > 0) approvedTradesCache = d1.approved_trades;
    }
  } catch (e) {
    console.log('Approved trades cache error:', e.message);
  }

  try {
    const r2 = await fetch(FLOW_HANDLER_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get_active_trades' })
    });
    const t2 = await r2.text();
    if (t2 && t2 !== 'Accepted') {
      const d2 = JSON.parse(t2);
      if (d2.active_trades?.length > 0) activeTradesCache = d2.active_trades;
    }
  } catch (e) {
    console.log('Active trades cache error:', e.message);
  }

  console.log('Cache refreshed — approved:', approvedTradesCache.length, 'active:', activeTradesCache.length);
}

// Refresh every 5 minutes
setInterval(refreshCache, 5 * 60 * 1000);
// Load on startup
refreshCache();

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
      // Refresh cache in background
      refreshCache().catch(() => {});

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

    // ================= TRADE DETAILS SCREEN =================
    if (plain.screen === 'Trade_Details') {
      const trade_type = plain.data?.trade_type;
      const direction = plain.data?.direction;

      console.log('trade_type:', trade_type, 'direction:', direction);

      if (trade_type === 'new_trade') {
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'New_Trade_Screen',
          data: { direction }
        });
      }

      if (trade_type === 'linked_trade') {
        const active_trades = activeTradesCache.length > 0
          ? activeTradesCache
          : [{ id: 'none', title: 'No active trades found' }];

        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Linked_Trade_Screen',
          data: { direction, active_trades }
        });
      }

      if (trade_type === 'modification') {
        const approved_trades = approvedTradesCache.length > 0
          ? approvedTradesCache
          : [{ id: 'none', title: 'No approved trades found' }];

        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Modification_Screen',
          data: { approved_trades }
        });
      }

      if (trade_type === 'addendum') {
        const approved_trades = approvedTradesCache.length > 0
          ? approvedTradesCache
          : [{ id: 'none', title: 'No approved trades found' }];

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
