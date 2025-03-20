const express = require('express');
const CryptoJS = require('crypto-js');
const bodyParser = require('body-parser');
require('dotenv').config(); // Load environment variables

const app = express();
app.use(bodyParser.json());

const SALT_KEY = process.env.SALT_KEY || 'secret123'; // Set via env or fallback

function verifyHmacSignature(data, signature, saltKey) {
  const dataString = typeof data === 'string' ? data : JSON.stringify(data);
  const expectedHash = CryptoJS.HmacSHA256(dataString, saltKey);
  const expectedSignature = expectedHash.toString(CryptoJS.enc.Hex);
  return expectedSignature === signature;
}

app.post('/webhook/callback', (req, res) => {
  try {
    const signature = req.headers['x-signature'];
    const payload = req.body;
    
    console.log('Received webhook:');
    console.log('Payload:', payload);
    console.log('Signature:', signature);
    
    if (!signature) {
      return res.status(400).json({ success: false, message: 'Missing signature header' });
    }
    
    const isValid = verifyHmacSignature(payload, signature, SALT_KEY);
    
    if (isValid) {
      console.log('Signature verified successfully');
      res.status(200).json({ success: true, message: 'Webhook received and signature verified' });
    } else {
      console.log('Signature verification failed');
      res.status(400).json({ success: false, message: 'Invalid signature' });
    }
    
  } catch (error) {
    console.error('Error processing webhook:', error);
    res.status(500).json({ success: false, message: 'Error processing webhook', error: error.message });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Client webhook receiver running on port ${PORT}`);
});
