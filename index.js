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

const DIRECTION_OPTIONS = [
  { id: 'purchase', title: 'Purchase' },
  { id: 'sale', title: 'Sale' }
];

const TRADE_TYPE_OPTIONS = [
  { id: 'new_trade', title: 'New Trade' },
  { id: 'cloned_trade', title: 'Cloned Trade' },
  { id: 'linked_trade', title: 'Linked Trade' },
  { id: 'modification', title: 'Modification' },
  { id: 'addendum', title: 'Addendum' },
  { id: 'back_to_back', title: 'Back-to-Back' },
  { id: 'unlink', title: 'Unlink' },
  { id: 'relink', title: 'Relink' }
];

// Letter shortcut aliases in flow_token: trade_<alias>_<wa>
// Accept short forms (new) and server ids (new_trade).
const SHORTCUT_ALIAS_TO_ID = {
  new: 'new_trade',
  new_trade: 'new_trade',
  cloned: 'cloned_trade',
  cloned_trade: 'cloned_trade',
  linked: 'linked_trade',
  linked_trade: 'linked_trade',
  modification: 'modification',
  addendum: 'addendum',
  back_to_back: 'back_to_back',
  unlink: 'unlink',
  relink: 'relink'
};

// ====================== COMMODITY LOOKUP ======================
function getCommodityTitle(id) {
  if (!id) return '';
  const match = COMMODITY_OPTIONS.find(c => c.id === id);
  return match ? match.title : id;
}

// ====================== FLOW TOKEN HELPERS ======================
function parseTradeShortcutToken(flowToken) {
  if (!flowToken) return null;
  const raw = String(flowToken).trim();
  const m = raw.match(/^trade_(.+)$/i);
  if (!m) return null;

  const rest = m[1];
  const restLower = rest.toLowerCase();
  const aliases = Object.keys(SHORTCUT_ALIAS_TO_ID).sort((a, b) => b.length - a.length);

  for (const alias of aliases) {
    const prefix = alias + '_';
    if (restLower.startsWith(prefix)) {
      const phone = rest.slice(prefix.length);
      if (!phone) return null;
      return { tradeType: SHORTCUT_ALIAS_TO_ID[alias], phone };
    }
  }
  return null;
}

function extractPhoneNumber(flowToken) {
  if (!flowToken) return '';
  const shortcut = parseTradeShortcutToken(flowToken);
  if (shortcut) return shortcut.phone;
  return String(flowToken).replace(/^note_/i, '');
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
      const token = plain.flow_token || '';
      const tokenLower = token.toLowerCase();

      // Notes Flow: note_<wa> (keep startsWith so trade_* never false-positives)
      if (tokenLower.startsWith('note_') || tokenLower.includes('note')) {
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Note_Commodity_Screen',
          data: { commodity_options: COMMODITY_OPTIONS }
        });
      }

      // Letter shortcuts: trade_<type>_<wa> → pre-set trade_type, hide type radio
      const shortcut = parseTradeShortcutToken(token);
      if (shortcut) {
        const opt = TRADE_TYPE_OPTIONS.find(o => o.id === shortcut.tradeType);
        console.log(`⌨️ Trade shortcut INIT: type=${shortcut.tradeType} phone=${shortcut.phone}`);
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Trade_Details',
          data: {
            trade_type: shortcut.tradeType,
            trade_type_options: opt ? [opt] : TRADE_TYPE_OPTIONS,
            show_trade_type: false,
            direction_options: DIRECTION_OPTIONS,
            commodity_options: COMMODITY_OPTIONS
          }
        });
      }

      // Manual open: full type picker
      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'Trade_Details',
        data: {
          trade_type_options: TRADE_TYPE_OPTIONS,
          show_trade_type: true,
          direction_options: DIRECTION_OPTIONS,
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
      let trade_type = plain.data?.trade_type;
      // Shortcut UI may hide trade_type; fall back to flow_token so Continue still routes.
      if (!trade_type) {
        const fromToken = parseTradeShortcutToken(plain.flow_token);
        if (fromToken) trade_type = fromToken.tradeType;
      }
      const commodity = plain.data?.commodity || '';
      const commodityTitle = getCommodityTitle(commodity);
      // Collected on Trade_Details; Unlink/Relink ignore it. Pass string through to New/Cloned/Linked.
      const direction = plain.data?.direction || '';

      if (trade_type === 'new_trade') {
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'New_Trade_Screen',
          data: { commodity: commodityTitle, direction }
        });
      }

      // Unlink / Relink: update existing MASTER row — no direction ask/echo (not B2B)
      if (trade_type === 'unlink' || trade_type === 'relink') {
        const trades = await fetchActiveTrades({
          direction: '',
          commodityTitle,
          trade_type
        });

        if (trade_type === 'unlink') {
          return send(res, aesKey, flippedIv, {
            version: '7.0',
            screen: 'Unlink_Screen',
            data: { commodity: commodityTitle, active_trades: trades }
          });
        }

        // Relink: second list for parent candidates (Make filters via trade_type=relink_parent)
        const parentTrades = await fetchActiveTrades({
          direction: '',
          commodityTitle,
          trade_type: 'relink_parent'
        });

        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'Relink_Screen',
          data: {
            commodity: commodityTitle,
            active_trades: trades,
            parent_trades: parentTrades
          }
        });
      }

      if (['linked_trade', 'addendum', 'modification', 'cloned_trade', 'back_to_back'].includes(trade_type)) {
        // Use Trade_Details direction for get_active when present (U/R already branched above).
        const trades = await fetchActiveTrades({ direction, commodityTitle, trade_type });

        let screenName;
        let dataPayload = {};

        if (trade_type === 'linked_trade') {
          screenName = 'Linked_Trade_Screen';
          dataPayload = { commodity: commodityTitle, active_trades: trades, direction };
        } else if (trade_type === 'modification') {
          screenName = 'Modification_Screen';
          dataPayload = { commodity: commodityTitle, active_trades: trades };
        } else if (trade_type === 'cloned_trade') {
          screenName = 'Cloned_Trade_Screen';
          dataPayload = { commodity: commodityTitle, active_trades: trades, direction };
        } else if (trade_type === 'back_to_back') {
          screenName = 'Back_to_Back_Screen';
          dataPayload = { commodity: commodityTitle, active_trades: trades };
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
    'Cloned_Trade_Screen': 'cloned_trade',
    'Linked_Trade_Screen': 'linked_trade',
    'Addendum_Screen': 'addendum',
    'Add_Note_Screen': 'add_note',
    'Modification_Screen': 'modification',
    'Back_to_Back_Screen': 'back_to_back',
    'Unlink_Screen': 'unlink',
    'Relink_Screen': 'relink'
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
    from: extractPhoneNumber(plain.flow_token)
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
