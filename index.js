const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const FLOW_HANDLER_WEBHOOK_URL = process.env.FLOW_HANDLER_WEBHOOK_URL;

// ====================== COMMODITY LIST (ALPHABETICAL) ======================
const COMMODITY_OPTIONS = [
  { id: 'alkhaleej_sugar_coarse', title: 'Al Khaleej Sugar - Coarse' },
  { id: 'alkhaleej_sugar_fine', title: 'Al Khaleej Sugar - Fine' },
  { id: 'arusha_pigeon_peas', title: 'Arusha Pigeon Peas' },
  { id: 'babati_pigeon_peas', title: 'Babati Pigeon Peas' },
  { id: 'bariadi_pigeon_peas', title: 'Bariadi Pigeon Peas' },
  { id: 'basmati_rice', title: 'Basmati Rice' },
  { id: 'brazilian_raw_sugar', title: 'Brazilian Raw Sugar' },
  { id: 'chick_peas', title: 'Chick Peas' },
  { id: 'crimsons', title: 'Crimsons' },
  { id: 'dodoma_pigeon_peas', title: 'Dodoma Pigeon Peas' },
  { id: 'green_peas', title: 'Green Peas' },
  { id: 'indian_sella_rice', title: 'Indian Sella Rice' },
  { id: 'indian_white_rice', title: 'Indian White Rice' },
  { id: 'indian_white_sugar', title: 'Indian White Sugar' },
  { id: 'laird', title: 'Laird' },
  { id: 'lakota_pigeon_peas', title: 'Lakota/Red Pigeon Peas' },
  { id: 'manjeet_100_icumsa', title: 'Manjeet - 100 Icumsa' },
  { id: 'manjeet_150_icumsa', title: 'Manjeet - 150 Icumsa' },
  { id: 'matwara_pigeon_peas', title: 'Matwara Pigeon Peas' },
  { id: 'mix_sesame_seed', title: 'Mix Sesame Seed' },
  { id: 'mustard_seed', title: 'Mustard Seed' },
  { id: 'nipper', title: 'Nipper' },
  { id: 'palm_olein_10_big', title: 'Palm Olein - 10 Ltr. Big mouth' },
  { id: 'palm_olein_10_small', title: 'Palm Olein - 10 Ltr. Small mouth' },
  { id: 'palm_olein_16_big', title: 'Palm Olein - 16 Ltr. Big mouth' },
  { id: 'palm_olein_16_tin', title: 'Palm Olein - 16 Ltr. Tin' },
  { id: 'parboiled_rice', title: 'Parboiled Rice' },
  { id: 'rapeseed_meal', title: 'Rapeseed Meal' },
  { id: 'rcn', title: 'RCN' },
  { id: 'red_lentil', title: 'Red Lentil' },
  { id: 'renuka_sugar_45', title: 'Renuka Sugar - 45 Icumsa' },
  { id: 'sesame_seed', title: 'Sesame Seed' },
  { id: 'shridutt_sugar_45', title: 'Shridutt Sugar - 45 Icumsa' },
  { id: 'south_sesame_seed', title: 'South Sesame Seed' },
  { id: 'soyabean', title: 'Soyabean' },
  { id: 'soyabean_meal', title: 'Soyabean Meal' },
  { id: 'wheat', title: 'Wheat' },
  { id: 'wheat_bran', title: 'Wheat Bran' },
  { id: 'white_sesame_seed', title: 'White Sesame Seed' },
  { id: 'white_sugar', title: 'White Sugar' },
  { id: 'white_sugar_150_icumsa', title: 'White Sugar - 150 Icumsa' },
  { id: 'yellow_maize', title: 'Yellow Maize' },
  { id: 'yellow_peas', title: 'Yellow Peas' }
];

// ====================== COMMODITY LOOKUP ======================
function getCommodityTitle(id) {
  const match = COMMODITY_OPTIONS.find(c => c.id === id);
  return match ? match.title : id;
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

    console.log('📥 Action:', plain.action, '| Screen:', plain.screen, '| Type:', plain.data?.trade_type, '| Commodity:', plain.data?.commodity);

    // ================= PING & INIT =================
    if (plain.action === 'ping') {
      return send(res, aesKey, flippedIv, { version: '7.0', data: { status: 'active' } });
    }

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
          ],
          commodity_options: COMMODITY_OPTIONS
        }
      });
    }

    // ================= TRADE DETAILS SCREEN =================
    if (plain.screen === 'Trade_Details') {
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

      if (['linked_trade', 'addendum', 'modification'].includes(trade_type)) {
        let trades = [{ id: 'none', title: 'No active trades found for this commodity' }];

        try {
          const response = await fetch(FLOW_HANDLER_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              action: 'get_active_trades',
              direction: direction,
              commodity: commodityTitle,
              trade_type: trade_type
            })
          });

          const text = await response.text();
          console.log(`🔄 get_active_trades response for ${trade_type} (commodity: ${commodityTitle}):`, text);

          if (text && text !== 'Accepted') {
            const data = JSON.parse(text);

            // SANITIZE: drop any item without a real id (protects the Flow
            // from empty/phantom rows produced upstream in Make.com)
            const validTrades = (data.active_trades || []).filter(
              t => t && t.id && String(t.id).trim() !== '' &&
                   t.title && String(t.title).trim() !== ''
            );

            if (validTrades.length > 0) {
              trades = validTrades;
            }
          }
        } catch (e) {
          console.error('Failed to fetch trades:', e.message);
        }

        let screenName;
        let dataPayload = {};

        if (trade_type === 'linked_trade') {
          screenName = 'Linked_Trade_Screen';
          dataPayload = { direction, commodity: commodityTitle, active_trades: trades };
        } else if (trade_type === 'modification') {
          screenName = 'Modification_Screen';
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
    fireAndForget(plain);
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
    commodity: getCommodityTitle(plain.data?.commodity),
    trade_text: plain.data?.trade_text,
    additional_information: plain.data?.additional_information,
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
  })
    .then(r => r.text())
    .then(text => console.log(`✅ Background ${payload.action}:`, text))
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
