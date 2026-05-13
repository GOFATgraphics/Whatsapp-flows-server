const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64;
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

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
      return send(res, aesKey, flippedIv, { version: "7.0", data: { status: "active" } });
    }

    // ================= INIT =================
    if (plain.action === 'INIT' || !plain.screen) {
      return send(res, aesKey, flippedIv, {
        version: "7.0",
        screen: "Trade_Details",
        data: {
          direction_options: [
            { id: "purchase", title: "Purchase" },
            { id: "sale", title: "Sale" }
          ],
          category_options: [
            { id: "new_trade", title: "New Trade" },
            { id: "addendum", title: "Addendum" }
          ]
        }
      });
    }

    // ================= TRADE_DETAILS =================
    if (plain.screen === "Trade_Details") {
      const category = plain.data?.trade_category;

      if (category === "new_trade") {
        return send(res, aesKey, flippedIv, {
          version: "7.0",
          screen: "New_Trade_Screen",
          data: {}
        });
      }

      if (category === "addendum") {
        let approvedTrades = [{ id: "MC-0000000000", title: "No trades available" }];

        try {
          const response = await fetch(MAKE_WEBHOOK_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "get_approved_trades" }),
          });
          const text = await response.text();
          if (text && text !== "Accepted") {
            const makeData = JSON.parse(text);
            if (makeData.approved_trades) approvedTrades = makeData.approved_trades;
          }
        } catch (e) {
          console.log("Make error:", e.message);
        }

        return send(res, aesKey, flippedIv, {
          version: "7.0",
          screen: "Addendum_Screen",
          data: { approved_trades: approvedTrades }
        });
      }
    }

    // ================= NEW_TRADE_SCREEN =================
    if (plain.screen === "New_Trade_Screen") {
      console.log("Full payload:", JSON.stringify(plain, null, 2));

      try {
        const response = await fetch(MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: "new_trade",
            trade_text: plain.data?.trade_text,
            direction: plain.data?.direction,
            flow_token: plain.flow_token
          }),
        });
        const text = await response.text();
        console.log("Make response:", text);
      } catch (e) {
        console.log("Make error:", e.message);
      }

      return send(res, aesKey, flippedIv, {
        version: "7.0",
        screen: "success_screen",
        data: {}
      });
    }

    // ================= ADDENDUM_SCREEN =================
    if (plain.screen === "Addendum_Screen") {
      console.log("Full payload:", JSON.stringify(plain, null, 2));

      try {
        const response = await fetch(MAKE_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: "addendum",
            selected_trade: plain.data?.selected_trade,
            addendum_text: plain.data?.addendum_text,
            flow_token: plain.flow_token
          }),
        });
        const text = await response.text();
        console.log("Make response:", text);
      } catch (e) {
        console.log("Make error:", e.message);
      }

      return send(res, aesKey, flippedIv, {
        version: "7.0",
        screen: "success_screen",
        data: {}
      });
    }

    // ================= FALLBACK =================
    return send(res, aesKey, flippedIv, {
      version: "7.0",
      screen: "success_screen",
      data: {}
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("error");
  }
});

function send(res, aesKey, iv, data) {
  const enc = crypto.createCipheriv("aes-128-gcm", aesKey, iv);

  const result = Buffer.concat([
    enc.update(JSON.stringify(data), "utf8"),
    enc.final(),
    enc.getAuthTag()
  ]);

  res.send(result.toString("base64"));
}

app.listen(3000, () => console.log("Server running"));
