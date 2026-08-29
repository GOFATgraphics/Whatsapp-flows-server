const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
app.use(express.json());

const PRIVATE_KEY = process.env.WHATSAPP_FLOW_PRIVATE_KEY;
const PASSPHRASE = process.env.WHATSAPP_FLOW_PASSPHRASE;

function decryptRequest(body) {
  const { encrypted_flow_data, encrypted_aes_key, initial_vector } = body;

  const privateKey = crypto.createPrivateKey({
    key: PRIVATE_KEY,
    passphrase: PASSPHRASE
  });

  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(encrypted_aes_key, 'base64')
  );

  const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
  const iv = Buffer.from(initial_vector, 'base64');
  const TAG_LENGTH = 16;
  const encryptedBody = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const authTag = flowDataBuffer.subarray(-TAG_LENGTH);

  const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encryptedBody), decipher.final()]);
  return { decryptedBody: JSON.parse(decrypted.toString('utf-8')), aesKey, iv };
}

function encryptResponse(response, aesKey, iv) {
  const flippedIv = Buffer.from(iv.map(byte => ~byte));
  const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(response), 'utf-8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([encrypted, authTag]).toString('base64');
}

function send(res, aesKey, flippedIv, payload) {
  const encrypted = encryptResponse(payload, aesKey, flippedIv);
  res.set('Content-Type', 'text/plain');
  return res.send(encrypted);
}

async function fetchActiveTrades({ direction, commodityTitle, trade_type }) {
  // Reads MASTER via Google Sheets API, filters by trade_status "Approved"
  // and commodity match. For linked_trade / cloned_trade / back_to_back
  // the opposite-or-same direction filtering is applied as appropriate.
  const response = await axios.post(process.env.SHEETS_LOOKUP_ENDPOINT, {
    commodity: commodityTitle,
    direction,
    trade_type
  });
  return response.data.trades || [];
}

async function fireAndForget(screenName, payload) {
  const actionMap = {
    'New_Trade_Screen': 'new_trade',
    'Cloned_Trade_Screen': 'cloned_trade',
    'Linked_Trade_Screen': 'linked_trade',
    'Addendum_Screen': 'addendum',
    'Add_Note_Screen': 'add_note',
    'Modification_Screen': 'modification',
    'Back_to_Back_Screen': 'back_to_back'
  };

  const action = actionMap[screenName];
  if (!action) return;

  try {
    await axios.post(process.env.TRADE_FLOW_HANDLER_WEBHOOK, {
      action,
      ...payload
    });
  } catch (err) {
    console.error('fireAndForget error:', err.message);
  }
}

app.post('/webhook', async (req, res) => {
  let decryptedBody, aesKey, iv;

  try {
    ({ decryptedBody, aesKey, iv } = decryptRequest(req.body));
  } catch (err) {
    console.error('Decryption error:', err.message);
    return res.status(421).send();
  }

  const flippedIv = Buffer.from(iv.map(byte => ~byte));
  const { screen, data, action } = decryptedBody;

  if (action === 'ping') {
    return send(res, aesKey, flippedIv, { version: '7.0', data: { status: 'active' } });
  }

  if (action === 'INIT') {
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
          { id: 'cloned_trade', title: 'Cloned Trade' },
          { id: 'linked_trade', title: 'Linked Trade' },
          { id: 'modification', title: 'Modification' },
          { id: 'addendum', title: 'Addendum' },
          { id: 'back_to_back', title: 'Back-to-Back' }
        ],
        commodity_options: [
          { id: 'raw_cashew_nuts', title: 'Raw Cashew Nuts' },
          { id: 'rice', title: 'Rice' },
          { id: 'sugar', title: 'Sugar' },
          { id: 'barley', title: 'Barley' },
          { id: 'maize', title: 'Maize' },
          { id: 'wheat', title: 'Wheat' },
          { id: 'wheat_bran', title: 'Wheat Bran' },
          { id: 'mustard_seed', title: 'Mustard Seed' },
          { id: 'rapeseed', title: 'Rapeseed' },
          { id: 'rapeseed_meal', title: 'Rapeseed Meal' },
          { id: 'sesame_seed', title: 'Sesame Seed' },
          { id: 'soybean', title: 'Soybean' },
          { id: 'soybean_meal', title: 'Soybean Meal' },
          { id: 'palm_oil', title: 'Palm Oil' },
          { id: 'chick_peas', title: 'Chick Peas' },
          { id: 'green_peas', title: 'Green Peas' },
          { id: 'pigeon_peas', title: 'Pigeon Peas' },
          { id: 'red_lentils', title: 'Red Lentils' }
        ]
      }
    });
  }

  if (screen === 'Trade_Details' && action === 'data_exchange') {
    const { direction, trade_type, commodity } = data;
    const commodityTitle = commodity;

    if (trade_type === 'new_trade') {
      return send(res, aesKey, flippedIv, {
        version: '7.0',
        screen: 'New_Trade_Screen',
        data: { direction, commodity: commodityTitle }
      });
    }

    if (['linked_trade', 'addendum', 'modification', 'cloned_trade', 'back_to_back'].includes(trade_type)) {
      const trades = await fetchActiveTrades({ direction, commodityTitle, trade_type });

      let screenName;
      let dataPayload = {};

      if (trade_type === 'linked_trade') {
        screenName = 'Linked_Trade_Screen';
        dataPayload = { direction, commodity: commodityTitle, active_trades: trades };
      } else if (trade_type === 'modification') {
        screenName = 'Modification_Screen';
        dataPayload = { commodity: commodityTitle, active_trades: trades };
      } else if (trade_type === 'cloned_trade') {
        screenName = 'Cloned_Trade_Screen';
        dataPayload = { direction, commodity: commodityTitle, active_trades: trades };
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

  // Terminal submissions from New_Trade_Screen, Cloned_Trade_Screen,
  // Linked_Trade_Screen, Modification_Screen, Addendum_Screen, Back_to_Back_Screen
  if (
    [
      'New_Trade_Screen',
      'Cloned_Trade_Screen',
      'Linked_Trade_Screen',
      'Modification_Screen',
      'Addendum_Screen',
      'Back_to_Back_Screen'
    ].includes(screen) &&
    action === 'data_exchange'
  ) {
    await fireAndForget(screen, data);

    return send(res, aesKey, flippedIv, {
      version: '7.0',
      screen: 'Success_Screen',
      data: {}
    });
  }

  return res.status(400).send();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
