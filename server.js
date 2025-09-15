// server.js (Node.js/Express example)
const express = require('express');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const path = require('path');
require('dotenv').config({ silent: true });

const app = express();
const PORT = process.env.PORT || 3000;

// Debug: Check if API key is loaded
console.log('API Key loaded:', process.env.GEMINI_API_KEY ? 'Yes' : 'No');
console.log('API Key value:', process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.substring(0, 10) + '...' : 'undefined');

// Middleware
app.use(express.json());
app.use(express.static('.'));

// Gemini API endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    console.log('Received analyze request:', req.body);
    const { message } = req.body;
    
    if (!process.env.GEMINI_API_KEY) {
      return res.status(500).json({ error: 'API key not configured' });
    }

    const MODEL_ID = "gemini-2.5-flash-preview-05-20";
    const BASE_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_ID}:generateContent`;

    const systemPrompt = "You are a cybersecurity assistant. The user has received a suspicious or potentially phishing message. Analyze the message for phishing indicators and provide a concise assessment. Return JSON as {\"riskLevel\":\"High|Medium|Low\",\"reasoning\":\"Concise explanation (5-6 lines max)\",\"officialWebsite\":\"official URL if impersonating known brand\"}. For the reasoning: Keep it brief and structured. Use bullet points if listing multiple issues. Focus on the most critical threats. For officialWebsite: If the message impersonates a known brand (PayPal, Microsoft, Amazon, etc.), provide the official website URL. If no specific brand is being impersonated, use null.";

    const payload = {
      systemInstruction: { role: "system", parts: [{ text: systemPrompt }] },
      contents: [
        {
          role: "user",
          parts: [
            {
              text: "Analyze this message for phishing risk. " +
                "Return JSON as {\"riskLevel\":\"High|Medium|Low\",\"reasoning\":\"Concise explanation (5-6 lines max)\",\"officialWebsite\":\"official URL if impersonating known brand\"}.\n\n" +
                "Message:\n" + message,
            },
          ],
        },
      ],
      generationConfig: {
        temperature: 0.2,
        responseMimeType: "application/json",
      },
    };

    const response = await fetch(`${BASE_URL}?key=${process.env.GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const jsonText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    
    if (!jsonText) {
      throw new Error('No response from Gemini');
    }

    const parsed = JSON.parse(jsonText);
    res.json(parsed);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Generate safe reply endpoint
app.post('/api/reply', async (req, res) => {
  try {
    console.log('Received reply request:', req.body);
    const { message } = req.body;
    
    if (!process.env.GEMINI_API_KEY) {
      return res.status(500).json({ error: 'API key not configured' });
    }

    const MODEL_ID = "gemini-2.5-flash-preview-05-20";
    const BASE_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_ID}:generateContent`;

    const payload = {
      contents: [
        {
          role: "user",
          parts: [
            {
              text: `You are a cybersecurity assistant.

Return STRICT JSON with these keys:
- risk level: "Low" | "Medium" | "High"
- analysis: short explanation (1–3 sentences)
- safe reply: a single short paragraph I can send back

Input:
"${message}"`,
            },
          ],
        },
      ],
      generationConfig: {
        temperature: 0.3,
        responseMimeType: "application/json",
      },
    };

    const response = await fetch(`${BASE_URL}?key=${process.env.GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    
    if (!text) {
      throw new Error('No response from Gemini');
    }

    const obj = JSON.parse(text);
    res.json(obj);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop the server');
});