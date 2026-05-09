const express = require('express');
const app = express();
app.use(express.json());

const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

app.get('/', (req, res) => res.send('running'));

app.post('/webhook', async (req, res) => {
  try {
    console.log("✅ Received webhook");
    console.log("Body keys:", Object.keys(req.body));
    
    // Log private key status (without exposing it)
    console.log("PRIVATE_KEY_B64 exists:", !!process.env.PRIVATE_KEY_B64);
    console.log("PRIVATE_KEY_B64 length:", process.env.PRIVATE_KEY_B64 ? process.env.PRIVATE_KEY_B64.length : 0);

    // Simple success response for testing
    return res.send('ok');

  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).send('error');
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Server running'))
