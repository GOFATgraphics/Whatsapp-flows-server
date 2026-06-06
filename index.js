const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const FLOW_HANDLER_WEBHOOK_URL = process.env.FLOW_HANDLER_WEBHOOK_URL;

// ====================== COMMODITY LIST ======================
const COMMODITY_OPTIONS = [
  { id: 'basmati_rice_1718', title: 'Basmati Rice - 1718' },
  { id: 'brazilian_raw_sugar', title: 'Brazilian Raw Sugar' },
  { id: 'chick_peas_australia', title: 'Chick Peas - Australia' },
  { id: 'chick_peas_tanzania', title: 'Chick Peas - Tanzania' },
  { id: 'crimsons_canada', title: 'Crimsons - Canada' },
  { id: 'green_peas_canada', title: 'Green Peas - Canada' },
  { id: 'indian_sella_rice_1509', title: 'Indian Sella Rice - 1509' },
  { id: 'indian_white_rice_broken', title: 'Indian White Rice - 100% Broken' },
  { id: 'indian_white_sugar', title: 'Indian White Sugar' },
  { id: 'laird_canada', title: 'Laird - Canada' },
  { id: 'mix_sesame_tanzania', title: 'Mix Sesame Seed - Tanzania' },
  { id: 'mus_seed_russia', title: 'Mus. Seed - Russia' },
  { id: 'nipper_australia', title: 'Nipper - Australia' },
  { id: 'palm_olein_10_big', title: 'Palm Olein - 10 Ltr. Big mouth' },
  { id: 'palm_olein_10_small', title: 'Palm Olein - 10 Ltr. Small mouth' },
  { id: 'palm_olein_16_big', title: 'Palm Olein - 16 Ltr. Big mouth' },
  { id: 'palm_olein_16_tin', title: 'Palm Olein - 16 Ltr. Tin' },
  { id: 'parboiled_rice', title: 'Parboiled Rice' },
  { id: 'pigeon_peas_arusha', title: 'Arusha Pigeon Peas - Tanzania' },
  { id: 'pigeon_peas_babati', title: 'Babati Pigeon Peas - Tanzania' },
  { id: 'pigeon_peas_bariadi', title: 'Bariadi Pigeon Peas - Tanzania' },
  { id: 'pigeon_peas_dodoma', title: 'Dodoma Pigeon Peas - Tanzania' },
  {
    id: 'pigeon_peas_lakota',
    title: 'Lakota/Red Pigeon Peas - Mozambique/Malawi'
  },
  {
    id: 'pigeon_peas_matwara_moz',
    title: 'Matwara Pigeon Peas - Mozambique/Malawi'
  },
  {
    id: 'pigeon_peas_matwara_tz',
    title: 'Matwara Pigeon Peas - Tanzania'
  },
  { id: 'rapeseed_meal_india', title: 'Rapeseed Meal - India' },
  { id: 'rcn', title: 'RCN' },
  { id: 'rcn_tanzania', title: 'RCN - Tanzania' },
  { id: 'red_lentil_canada', title: 'Red Lentil - Canada' },
  { id: 'renuka_sugar_45', title: 'Renuka Sugar - 45 Icumsa' },
  { id: 'sesame_seed_mozambique', title: 'Sesame Seed - Mozambique' },
  { id: 'sesame_seed_tanzania', title: 'Sesame Seed - Tanzania' },
  { id: 'shridutt_sugar_45', title: 'Shridutt Sugar - 45 Icumsa' },
  { id: 'soyabean_meal_india', title: 'Soyabean Meal - India' },
  { id: 'soyabean_nigeria', title: 'Soyabean - Nigeria' },
  { id: 'soyabean_ukraine', title: 'Soyabean - Ukraine' },
  { id: 'sugar_150_icumsa', title: 'White Sugar - 150 Icumsa' },
  { id: 'sugar_alkhaleej_coarse', title: 'Al Khaleej Sugar - Coarse' },
  { id: 'sugar_alkhaleej_fine', title: 'Al Khaleej Sugar - Fine' },
  { id: 'sugar_manjeet_100', title: 'Manjeet - 100 Icumsa' },
  { id: 'sugar_manjeet_150', title: 'Manjeet - 150 Icumsa' },
  { id: 'wheat_apw1', title: 'Wheat - APW1' },
  { id: 'wheat_bran_angola', title: 'Wheat Bran - Angola' },
  { id: 'wheat_bran_tanzania', title: 'Wheat Bran - Tanzania' },
  { id: 'white_sesame_nigeria', title: 'White Sesame Seed - Nigeria' },
  { id: 'white_sesame_tanzania', title: 'White Sesame Seed - Tanzania' },
  { id: 'white_sugar', title: 'White Sugar' },
  { id: 'yellow_maize_india', title: 'Yellow Maize - India' },
  { id: 'yellow_peas_canada', title: 'Yellow Peas - Canada' },
  { id: 'yellow_peas_ukraine', title: 'Yellow Peas - Ukraine' },
  {
    id: 'yellow_peas_ukraine_russia',
    title: 'Yellow Peas - Ukraine/Russia'
  }
];

app.post('/webhook', async (req, res) => {
  try {
    // ================= DECRYPT =================
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
      type: 'pkcs8'
    });

    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
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
      '📥 Action:',
      plain.action,
      '| Screen:',
      plain.screen,
      '| Type:',
      plain.data?.trade_type,
      '| Commodity:',
      plain.data?.commodity
    );

    // ================= PING & INIT =================
    if (plain.action === 'ping') {
      return send(res, aesKey, flippedIv, {
        version: '7.0',
        data: {
          status: 'active'
        }
      });
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

      if (trade_type === 'new_trade') {
        return send(res, aesKey, flippedIv, {
          version: '7.0',
          screen: 'New_Trade_Screen',
          data: {
            direction,
            commodity
          }
        });
      }

      if (
        ['linked_trade', 'addendum', 'modification'].includes(
          trade_type
        )
      ) {
        let trades = [
          {
            id: 'none',
            title: 'No trades found'
          }
        ];

        try {
          const response = await fetch(
            FLOW_HANDLER_WEBHOOK_URL,
            {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                action: 'get_active_trades',
                direction,
                commodity,
                trade_type
              })
            }
          );

          const text = await response.text();

          console.log(
            `🔄 get_active_trades response for ${trade_type} (commodity: ${commodity}):`,
            text
          );

          if (text && text !== 'Accepted') {
            const data = JSON.parse(text);

            if (data.active_trades?.length > 0) {
              trades = data.active_trades;
            } else if (
              data.approved_trades?.length > 0
            ) {
              trades = data.approved_trades;
            }
          }
        } catch (e) {
          console.error(
            'Failed to fetch trades:',
            e.message
          );
        }

        let screenName;
        let dataPayload = {};

        if (trade_type === 'linked_trade') {
          screenName = 'Linked_Trade_Screen';

          dataPayload = {
            direction,
            commodity,
            active_trades: trades
          };
        } else {
          screenName =
            trade_type === 'addendum'
              ? 'Addendum_Screen'
              : 'Modification_Screen';

          dataPayload = {
            commodity,
            approved_trades: trades
          };
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

    return sendSuccess(
      res,
      aesKey,
      flippedIv
    );
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).send('error');
  }
});

// ====================== HELPERS ======================
function fireAndForget(plain) {
  const payload = {
    action:
      plain.screen === 'New_Trade_Screen'
        ? 'new_trade'
        : plain.screen === 'Linked_Trade_Screen'
        ? 'linked_trade'
        : plain.screen === 'Addendum_Screen'
        ? 'addendum'
        : 'modification',

    direction: plain.data?.direction,
    commodity: plain.data?.commodity,
    trade_text: plain.data?.trade_text,
    parent_trade: plain.data?.parent_trade,
    selected_trade: plain.data?.selected_trade,
    addendum_text: plain.data?.addendum_text,
    modification_text: plain.data?.modification_text,
    from: plain.flow_token
  };

  fetch(FLOW_HANDLER_WEBHOOK_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  })
    .then((r) => r.text())
    .then((text) =>
      console.log(
        `✅ Background ${payload.action}:`,
        text
      )
    )
    .catch((e) =>
      console.error(
        'Background error:',
        e.message
      )
    );
}

function sendSuccess(res, aesKey, iv) {
  return send(res, aesKey, iv, {
    version: '7.0',
    screen: 'Success_Screen',
    data: {}
  });
}

function send(res, aesKey, iv, data) {
  const enc = crypto.createCipheriv(
    'aes-128-gcm',
    aesKey,
    iv
  );

  const result = Buffer.concat([
    enc.update(
      JSON.stringify(data),
      'utf8'
    ),
    enc.final(),
    enc.getAuthTag()
  ]);

  res.send(result.toString('base64'));
}

app.listen(3000, () => {
  console.log(
    'WhatsApp Flow Server running on port 3000'
  );
});
