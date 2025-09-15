// server.js (Node.js/Express example)
const express = require('express');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const path = require('path');
require('dotenv').config();

// Punycode detection utilities - using built-in URL API instead of deprecated punycode module

// Known legitimate domains for comparison
const LEGITIMATE_DOMAINS = [
  'paypal.com', 'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
  'netflix.com', 'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
  'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com', 'wikipedia.org',
  'ebay.com', 'shopify.com', 'stripe.com', 'square.com', 'dropbox.com',
  'adobe.com', 'salesforce.com', 'zoom.us', 'slack.com', 'discord.com',
  'bankofamerica.com', 'wellsfargo.com', 'chase.com', 'citibank.com',
  'visa.com', 'mastercard.com', 'americanexpress.com', 'discover.com'
];

// Common typos and variations for major brands
const BRAND_VARIATIONS = {
  'paypal': ['paypel', 'paypall', 'paypa1', 'paypal1', 'paypal-1', 'paypa1.com', 'paypel.com', 'paypall.com'],
  'microsoft': ['microsoft1', 'microsft', 'microsof', 'microsoft-1', 'microsft.com', 'microsof.com'],
  'google': ['google1', 'goog1e', 'goog1e.com', 'google-1', 'g00gle', 'g00gle.com'],
  'apple': ['apple0', 'app1e', 'app1e.com', 'apple-1', 'app1e.com'],
  'amazon': ['amazon01', 'amaz0n', 'amaz0n.com', 'amazon-1', 'amaz0n.com'],
  'facebook': ['faceb00k', 'faceb00k.com', 'facebook-1', 'faceb00k.com'],
  'twitter': ['tw1tter', 'tw1tter.com', 'twitter-1', 'tw1tter.com'],
  'instagram': ['instagr4m', 'instagr4m.com', 'instagram-1', 'instagr4m.com'],
  'linkedin': ['linked1n', 'linked1n.com', 'linkedin-1', 'linked1n.com'],
  'github': ['g1thub', 'g1thub.com', 'github-1', 'g1thub.com'],
  'netflix': ['netflix2', 'netf1ix', 'netf1ix.com', 'netflix-1', 'netf1ix.com'],
  'youtube': ['y0utube', 'y0utube.com', 'youtube-1', 'y0utube.com'],
  'ebay': ['eb4y', 'eb4y.com', 'ebay-1', 'eb4y.com'],
  'shopify': ['sh0pify', 'sh0pify.com', 'shopify-1', 'sh0pify.com'],
  'stripe': ['str1pe', 'str1pe.com', 'stripe-1', 'str1pe.com'],
  'dropbox': ['dr0pbox', 'dr0pbox.com', 'dropbox-1', 'dr0pbox.com'],
  'adobe': ['ad0be', 'ad0be.com', 'adobe-1', 'ad0be.com'],
  'zoom': ['z00m', 'z00m.us', 'zoom-1', 'z00m.us'],
  'slack': ['sl4ck', 'sl4ck.com', 'slack-1', 'sl4ck.com'],
  'discord': ['d1scord', 'd1scord.com', 'discord-1', 'd1scord.com']
};

// Homograph character mappings (lookalike characters)
const HOMOGRAPH_MAP = {
  'a': ['а', 'ɑ', 'α'], // Latin 'a' vs Cyrillic 'а', Greek 'α'
  'e': ['е', 'ε'], // Latin 'e' vs Cyrillic 'е', Greek 'ε'
  'o': ['о', 'ο', 'θ'], // Latin 'o' vs Cyrillic 'о', Greek 'ο'
  'p': ['р', 'ρ'], // Latin 'p' vs Cyrillic 'р', Greek 'ρ'
  'c': ['с', 'ϲ'], // Latin 'c' vs Cyrillic 'с', Greek 'ϲ'
  'x': ['х', 'χ'], // Latin 'x' vs Cyrillic 'х', Greek 'χ'
  'y': ['у', 'γ'], // Latin 'y' vs Cyrillic 'у', Greek 'γ'
  'i': ['і', 'ι', 'ι'], // Latin 'i' vs Cyrillic 'і', Greek 'ι'
  'j': ['ј'], // Latin 'j' vs Cyrillic 'ј'
  'l': ['l', 'ι'], // Latin 'l' vs Greek 'ι'
  'n': ['п'], // Latin 'n' vs Cyrillic 'п'
  'm': ['м'], // Latin 'm' vs Cyrillic 'м'
  'b': ['Ь', 'в'], // Latin 'b' vs Cyrillic 'Ь', 'в'
  'd': ['ԁ'], // Latin 'd' vs Cyrillic 'ԁ'
  'g': ['ɡ'], // Latin 'g' vs Greek 'ɡ'
  'h': ['һ'], // Latin 'h' vs Cyrillic 'һ'
  'k': ['к'], // Latin 'k' vs Cyrillic 'к'
  'q': ['ԛ'], // Latin 'q' vs Cyrillic 'ԛ'
  'r': ['г'], // Latin 'r' vs Cyrillic 'г'
  's': ['ѕ'], // Latin 's' vs Cyrillic 'ѕ'
  't': ['т'], // Latin 't' vs Cyrillic 'т'
  'u': ['υ'], // Latin 'u' vs Greek 'υ'
  'v': ['ν'], // Latin 'v' vs Greek 'ν'
  'w': ['ω'], // Latin 'w' vs Greek 'ω'
  'z': ['z'] // Latin 'z' vs various 'z' variants
};

// Function to detect homograph attacks
function detectHomographAttack(domain) {
  const results = {
    isHomograph: false,
    suspiciousChars: [],
    potentialTargets: [],
    punycodeDetected: false,
    warnings: []
  };

  try {
    // Check for Punycode encoding
    if (domain.includes('xn--')) {
      results.punycodeDetected = true;
      results.warnings.push('🚨 Punycode domain detected - may contain non-ASCII characters');
      
      try {
        // Use URL constructor to decode punycode
        const url = new URL(`http://${domain}`);
        const decoded = url.hostname;
        if (decoded !== domain) {
          results.warnings.push(`Decoded Punycode: ${decoded}`);
        }
      } catch (e) {
        results.warnings.push('Could not decode Punycode');
      }
    }

    // Check for homograph characters
    const domainLower = domain.toLowerCase();
    const suspiciousChars = [];
    
    for (let i = 0; i < domainLower.length; i++) {
      const char = domainLower[i];
      if (HOMOGRAPH_MAP[char]) {
        suspiciousChars.push({
          position: i,
          char: char,
          alternatives: HOMOGRAPH_MAP[char]
        });
      }
    }

    if (suspiciousChars.length > 0) {
      results.isHomograph = true;
      results.suspiciousChars = suspiciousChars;
      results.warnings.push(`🚨 Homograph characters detected at positions: ${suspiciousChars.map(s => s.position).join(', ')}`);
    }

    // Check against known legitimate domains
    const domainWithoutTld = domainLower.split('.').slice(0, -1).join('.');
    const potentialTargets = [];

    // First check for exact brand variations (typos)
    for (const [brand, variations] of Object.entries(BRAND_VARIATIONS)) {
      if (variations.includes(domainLower) || variations.includes(domainWithoutTld)) {
        potentialTargets.push({
          target: `${brand}.com`,
          similarity: 0.95, // High similarity for known typos
          method: 'known_typo_variation',
          officialWebsite: getOfficialWebsite(brand)
        });
        results.warnings.push(`🚨 Known phishing variation detected! This looks like a typo of ${brand}.com`);
      }
    }

    // Then check against legitimate domains with similarity algorithms
    for (const legitDomain of LEGITIMATE_DOMAINS) {
      const legitWithoutTld = legitDomain.split('.').slice(0, -1).join('.');
      
      // Check for character substitutions
      if (isSimilarDomain(domainWithoutTld, legitWithoutTld)) {
        const similarity = calculateSimilarity(domainWithoutTld, legitWithoutTld);
        if (similarity > 0.7) { // Only flag if similarity is high enough
          potentialTargets.push({
            target: legitDomain,
            similarity: similarity,
            method: 'character_substitution',
            officialWebsite: getOfficialWebsite(legitWithoutTld)
          });
        }
      }
      
      // Check for missing/extra characters
      if (isCloseDomain(domainWithoutTld, legitWithoutTld)) {
        const similarity = calculateSimilarity(domainWithoutTld, legitWithoutTld);
        if (similarity > 0.7) { // Only flag if similarity is high enough
          potentialTargets.push({
            target: legitDomain,
            similarity: similarity,
            method: 'character_addition_deletion',
            officialWebsite: getOfficialWebsite(legitWithoutTld)
          });
        }
      }
    }

    if (potentialTargets.length > 0) {
      results.potentialTargets = potentialTargets.sort((a, b) => b.similarity - a.similarity);
      results.warnings.push(`🎭 Potential impersonation of: ${potentialTargets[0].target} (${Math.round(potentialTargets[0].similarity * 100)}% similar)`);
    }

  } catch (error) {
    results.warnings.push(`Error analyzing domain: ${error.message}`);
  }

  return results;
}

// Helper function to get official website URL for a brand
function getOfficialWebsite(brand) {
  const officialSites = {
    'paypal': 'https://www.paypal.com',
    'microsoft': 'https://www.microsoft.com',
    'google': 'https://www.google.com',
    'apple': 'https://www.apple.com',
    'amazon': 'https://www.amazon.com',
    'facebook': 'https://www.facebook.com',
    'twitter': 'https://www.twitter.com',
    'instagram': 'https://www.instagram.com',
    'linkedin': 'https://www.linkedin.com',
    'github': 'https://www.github.com',
    'netflix': 'https://www.netflix.com',
    'youtube': 'https://www.youtube.com',
    'ebay': 'https://www.ebay.com',
    'shopify': 'https://www.shopify.com',
    'stripe': 'https://www.stripe.com',
    'dropbox': 'https://www.dropbox.com',
    'adobe': 'https://www.adobe.com',
    'zoom': 'https://www.zoom.us',
    'slack': 'https://www.slack.com',
    'discord': 'https://www.discord.com',
    'bankofamerica': 'https://www.bankofamerica.com',
    'wellsfargo': 'https://www.wellsfargo.com',
    'chase': 'https://www.chase.com',
    'citibank': 'https://www.citibank.com',
    'visa': 'https://www.visa.com',
    'mastercard': 'https://www.mastercard.com',
    'americanexpress': 'https://www.americanexpress.com',
    'discover': 'https://www.discover.com'
  };
  
  return officialSites[brand.toLowerCase()] || null;
}

// Helper function to check if domains are similar (character substitution)
function isSimilarDomain(domain1, domain2) {
  if (Math.abs(domain1.length - domain2.length) > 2) return false;
  
  let differences = 0;
  const maxLength = Math.max(domain1.length, domain2.length);
  
  for (let i = 0; i < maxLength; i++) {
    const char1 = domain1[i] || '';
    const char2 = domain2[i] || '';
    
    if (char1 !== char2) {
      // Check if it's a homograph substitution
      const isHomograph = HOMOGRAPH_MAP[char1]?.includes(char2) || HOMOGRAPH_MAP[char2]?.includes(char1);
      if (!isHomograph) {
        differences++;
      }
    }
  }
  
  return differences <= 2 && differences > 0;
}

// Helper function to check if domains are close (addition/deletion)
function isCloseDomain(domain1, domain2) {
  const lenDiff = Math.abs(domain1.length - domain2.length);
  if (lenDiff > 2) return false;
  
  // Check if one domain is contained in the other with minimal differences
  const shorter = domain1.length < domain2.length ? domain1 : domain2;
  const longer = domain1.length >= domain2.length ? domain1 : domain2;
  
  return longer.includes(shorter) && lenDiff <= 2;
}

// Helper function to calculate similarity percentage
function calculateSimilarity(str1, str2) {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length <= str2.length ? str1 : str2;
  
  if (longer.length === 0) return 1.0;
  
  const editDistance = levenshteinDistance(longer, shorter);
  return (longer.length - editDistance) / longer.length;
}

// Levenshtein distance calculation
function levenshteinDistance(str1, str2) {
  const matrix = [];
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[str2.length][str1.length];
}


const app = express();
const PORT = process.env.PORT || 3000;

// Debug: Check if API key is loaded
console.log('API Key loaded:', process.env.GEMINI_API_KEY ? 'Yes' : 'No');
console.log('API Key value:', process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.substring(0, 10) + '...' : 'undefined');

// Middleware
app.use(express.json());
app.use(express.static('.'));

// Punycode analysis endpoint
app.post('/api/punycode', (req, res) => {
  try {
    const { domains } = req.body;
    
    if (!domains || !Array.isArray(domains)) {
      return res.status(400).json({ error: 'Domains array is required' });
    }

    const results = domains.map(domain => {
      const analysis = detectHomographAttack(domain);
      return {
        domain,
        ...analysis
      };
    });

    res.json({ results });
  } catch (error) {
    console.error('Punycode analysis error:', error);
    res.status(500).json({ error: error.message });
  }
});

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

    // Mask PII before sending to AI
    const maskedMessage = message
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL_MASKED]')
      .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[PHONE_MASKED]')
      .replace(/\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b/g, '[CARD_MASKED]')
      .replace(/\b(?:PIN|pin|Pin)\s*(?:is|:|=)?\s*\d{3,6}\b/gi, '[PIN_MASKED]')
      .replace(/\b\d{3,6}\b/g, (match, offset, string) => {
        // Only mask if it's likely a PIN (not part of other numbers)
        const before = string.substring(Math.max(0, offset - 10), offset);
        const after = string.substring(offset + match.length, Math.min(string.length, offset + match.length + 10));
        const context = (before + after).toLowerCase();
        
        // Don't mask if it's part of a phone number, card number, or other context
        if (context.includes('phone') || context.includes('card') || context.includes('account') || 
            context.includes('number') || context.includes('id') || context.includes('code') ||
            context.includes('amount') || context.includes('$') || context.includes('dollar')) {
          return match;
        }
        
        // Mask standalone 3-6 digit numbers that could be PINs
        return '[PIN_MASKED]';
      })
      .replace(/\b[A-Za-z]{2,3}\d{4,8}\b/g, '[ACCOUNT_MASKED]')
      .replace(/\b\d{1,5}\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Place|Pl)\b/gi, '[ADDRESS_MASKED]')
      .replace(/\b(?:Mr|Mrs|Ms|Dr)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g, '[NAME_MASKED]');

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
                "Message:\n" + maskedMessage,
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
    
    // Extract domains from the message for Punycode analysis
    // Improved regex to avoid false positives like "john.smith" or "user.name"
    const domainRegex = /(?:https?:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\/[^\s]*)?/gi;
    const domains = (message.match(domainRegex) || [])
      .filter(url => {
      // Filter out common false positives
      const hostname = url.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
      
      // Skip if it looks like a name (firstname.lastname pattern) but allow brand typos
      if (/^[a-z]+\.[a-z]+$/.test(hostname) && hostname.length < 15) {
        // Allow common TLDs even if they look like names (for brand typos like paypel.com)
        const commonTlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'me', 'us'];
        const tld = hostname.split('.').pop();
        if (commonTlds.includes(tld)) {
          return true; // Allow domains with common TLDs
        }
        return false;
      }
        
        // Skip if it's a common non-domain pattern
        const skipPatterns = [
          /^[a-z]+\.[a-z]+$/, // simple name patterns
          /^\d+\.\d+/, // IP-like patterns
          /^[a-z]+\.(com|org|net|edu|gov)$/i // single word domains (likely false positives)
        ];
        
        return !skipPatterns.some(pattern => pattern.test(hostname));
      })
      .map(url => {
        try {
          const urlObj = new URL(url.startsWith('http') ? url : 'http://' + url);
          return urlObj.hostname;
        } catch {
          return url;
        }
      });

    // Perform Punycode analysis on detected domains
    const punycodeResults = domains.map(domain => ({
      domain,
      ...detectHomographAttack(domain)
    }));

    // Add Punycode analysis to the response
    const finalResponse = {
      ...parsed,
      punycodeAnalysis: punycodeResults,
      domainsAnalyzed: domains
    };

    res.json(finalResponse);
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