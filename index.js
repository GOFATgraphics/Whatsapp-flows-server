const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const FLOW_HANDLER_WEBHOOK_URL = process.env.FLOW_HANDLER_WEBHOOK_URL;
const ADD_NOTE_WEBHOOK_URL = process.env.ADD_NOTE_WEBHOOK_URL; // dedicated Add Note Handler webhook

// ====================== STARTUP ENV VAR CHECK ======================
if (!PRIVATE_KEY_B64) console.error('❌ MISSING ENV VAR: PRIVATE_KEY_B64');
if (!FLOW_HANDLER_WEBHOOK_URL) console.error('❌ MISSING ENV VAR: FLOW_HANDLER_WEBHOOK_URL');
if (!ADD_NOTE_WEBHOOK_URL) console.error('❌ MISSING ENV VAR: ADD_NOTE_WEBHOOK_URL');

// ====================== COMMODITY LIST (alphabetical) ======================
const COMMODITY_OPTIONS = [
  { id: 'barley', title: 'Barley' },
  { id: 'chick_peas', title: 'Chick Peas' },
  { id: 'green_peas', title: 'Green Peas' },
  { id: 'maize', title: 'Maize' },
  { id: 'mustard_seed', title: 'Mustard Seed' },
  { id: 'palm_oil', title: 'Palm Oil' },
  { id: 'pigeon_peas', title: 'Pigeon Peas' },
  { id: 'rapeseed', title: 'Rapeseed' },
  { id: 'rapeseed_meal', title: 'Rapeseed Meal' },
  { id: 'raw_cashew_nuts', title: 'Raw Cashew Nuts' },
  { id: 'red_lentils', title: 'Red Lentils' },
  { id: 'rice', title: 'Rice' },
  { id: 'sesame_seed', title: 'Sesame Seed' },
  { id: 'soybean', title: 'Soybean' },
  { id: 'soybean_meal', title: 'Soybean Meal' },
  { id: 'sugar', title: 'Sugar' },
  { id: 'wheat', title: 'Wheat' },
  { id: 'wheat_bran', title: 'Wheat Bran' }
];

// ====================== COMMODITY LOOKUP ======================
function getCommodityTitle(id) {
  if (!id) return '';
  const match = COMMODITY_OPTIONS.find(c => c.id === id);
  return match ? match.title : id;
}

// ====================== SHARED: fetch active trades from Make ======================
async function fetchActiveTrades({ direction, commodityTitle, trade_type }) {
  let trades = [{ id: 'none', title: 'No active trades found for this commodity' }];
  try {
    const requestBody = {
      action: 'get_active_trades',
      direction: direction,
      commodity: commodityTitle,
      trade_type: trade_type
    };

    console.log(`📤 get_active_trades REQUEST:`, JSON.stringify(requestBody));

    const response = await fetch(FLOW_HANDLER_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });

    const text = await response.text();

    if (text === 'Accepted') {
      console.warn(`⚠️ get_active_trades for "${trade_type}" (commodity: "${commodityTitle}") -> Make returned "Accepted". No WebhookRespond module fired. Check the router filter condition for trade_type="${trade_type}" in Trade Flow Handler.`);
    } else {
      console.log(`🔄 get_active_trades RESPONSE for "${trade_type}" (commodity: "${commodityTitle}"):`, text);
    }

    if (text && text !== 'Accepted') {
      const data = JSON.parse(text);
      const validTrades = (data.active_trades || []).filter(
        t => t && t.id && String(t.id).trim() !== '' &&
             t.title && String(t.title).trim() !== ''
      );
      if (validTrades.length > 0) {
        trades = validTrades;
      } else {
        console.warn(`⚠️ get_active_trades for "${trade_type}" (commodity: "${commodityTitle}") -> Make responded but active_trades was empty. Likely a MASTER data/filter mismatch (check product_category column) rather than a routing failure.`);
      }
    }
  } catch (e) {
    console.error(`❌ Failed to fetch trades for trade_type="${trade_type}", commodity="${commodityTitle}":`, e.message);
  }
  return trades;
}

app.post('/webhook', async (req, res) => {
  try {
    // ================= DECRYPT =================
    const encAesKey = Buffer.from(req.body.encrypted_aes_key, 'base64');
    const encData = Buffer.from(req.body.encrypted_flow_data, 'base64');
    const iv = Buffer.from(req.body.initial_vector, 'base64');

    const privateKeyPem = Buffer.from(PRIVATE_KEY_B64, 'base64').toString('utf8').trim();

    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      type: 'pkcs8'
    });

    const aesKey = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, encAesKey);

    const tag = encData.subarray(-16);
    const body = encData.subarray(0, -16);

    const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
    decipher.setAuthTag(tag);

    const plain = JSON.parse(decipher.update(body, undefined, 'utf8') + decipher.final('utf8'));
    const flippedIv = Buffer.from(iv.map(b => ~b));

    const screen = (plain.screen || '').trim();

    console.log('📥 Action:', plain.action, '| Screen:', screen, '| Type:', plain.data?.trade_type, '| Commodity:', plain.data?.commodity, '| FlowToken:', plain.flow_token);

    // ================= PING =================
    if (plain.action === 'ping') {
      return send(res, aesKey, flippedIv, { version: '7.0', data: { status: 'active' } });
    }

    // ================= INIT =================
    if (plain.action === 'INIT' || !screen) {
      const token = (plain.flow_token || '').toLowerCase();

      if (token.includes('note')) {
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Note_Commodity_Screen',
          data: { commodity_options: COMMODITY_OPTIONS }
        });
      }

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
            { id: 'similar_trade', title: 'Similar Trade' },
            { id: 'linked_trade', title: 'Linked Trade' },
            { id: 'modification', title: 'Modification' },
            { id: 'addendum', title: 'Addendum' }
          ],
          commodity_options: COMMODITY_OPTIONS
        }
      });
    }

    // ================= NOTE FLOW: commodity chosen -> fetch trades =================
    if (screen === 'Note_Commodity_Screen') {
      const commodity = plain.data?.commodity || '';
      const commodityTitle = getCommodityTitle(commodity);

      const trades = await fetchActiveTrades({
        direction: '',
        commodityTitle,
        trade_type: 'add_note'
      });

      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Add_Note_Screen',
        data: { commodity: commodityTitle, active_trades: trades }
      });
    }

    // ================= TRADE DETAILS SCREEN =================
    if (screen === 'Trade_Details') {
      const trade_type = plain.data?.trade_type;
      const direction = plain.data?.direction;
      const commodity = plain.data?.commodity || '';
      const commodityTitle = getCommodityTitle(commodity);

      if (trade_type === 'new_trade') {
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'New_Trade_Screen',
          data: { direction, commodity: commodityTitle }
        });
      }

      if (['linked_trade', 'addendum', 'modification', 'similar_trade'].includes(trade_type)) {
        const trades = await fetchActiveTrades({ direction, commodityTitle, trade_type });

        let screenName;
        let dataPayload = {};

        if (trade_type === 'linked_trade') {
          screenName = 'Linked_Trade_Screen';
          dataPayload = { direction, commodity: commodityTitle, active_trades: trades };
        } else if (trade_type === 'modification') {
          screenName = 'Modification_Screen';
          dataPayload = { commodity: commodityTitle, active_trades: trades };
        } else if (trade_type === 'similar_trade') {
          screenName = 'Similar_Trade_Screen';
          dataPayload = { direction, commodity: commodityTitle, active_trades: trades };
        } else {
          screenName = 'Addendum_Screen';
          dataPayload = { commodity: commodityTitle, active_trades: trades };
        }

        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: screenName,
          data: dataPayload
        });
      }
    }

    // ================= SUBMISSIONS =================
    fireAndForget(plain, screen);

    if (screen === 'Add_Note_Screen') {
      return send(res, aesKey, flippedIv, { version: '7.0', screen: 'Note_Success_Screen', data: {} });
    }
    return sendSuccess(res, aesKey, flippedIv);

  } catch (err) {
    console.error('Server error:', err);
    res.status(500).send('error');
  }
});

// ====================== HELPERS ======================
function fireAndForget(plain, screen) {
  const isNote = screen === 'Add_Note_Screen';

  const actionMap = {
    'New_Trade_Screen': 'new_trade',
    'Similar_Trade_Screen': 'similar_trade',
    'Linked_Trade_Screen': 'linked_trade',
    'Addendum_Screen': 'addendum',
    'Add_Note_Screen': 'add_note',
    'Modification_Screen': 'modification'
  };

  const payload = {
    action: actionMap[screen] || 'modification',

    direction: plain.data?.direction,
    commodity: getCommodityTitle(plain.data?.commodity),
    trade_text: plain.data?.trade_text,
    additional_information: plain.data?.additional_information,
    parent_trade: plain.data?.parent_trade,
    source_trade: plain.data?.source_trade,
    selected_trade: plain.data?.selected_trade,
    addendum_text: plain.data?.addendum_text,
    modification_text: plain.data?.modification_text,
    note_text: plain.data?.note_text,
    from: plain.flow_token
  };

  const targetUrl = isNote ? ADD_NOTE_WEBHOOK_URL : FLOW_HANDLER_WEBHOOK_URL;

  if (!targetUrl) {
    console.error(`❌ fireAndForget: target URL is undefined for action="${payload.action}" (isNote=${isNote}). Check ${isNote ? 'ADD_NOTE_WEBHOOK_URL' : 'FLOW_HANDLER_WEBHOOK_URL'} env var on Render.`);
    return;
  }

  fetch(targetUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(r => r.text())
    .then(text => console.log(`✅ Background ${payload.action} -> ${isNote ? 'AddNoteHandler' : 'FlowHandler'}:`, text))
    .catch(e => console.error('Background error:', e.message));
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
