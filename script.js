// === Config ===

// === Local Storage Keys ===
const LS_KEY = "PHISHING_SHIELD_GEMINI_KEY";
const USER_PROFILE_KEY = "PHISHING_SHIELD_USER_PROFILE";
const THREAT_HISTORY_KEY = "PHISHING_SHIELD_THREAT_HISTORY";

// === User Profile System ===
const DEFAULT_USER_PROFILE = {
  riskTolerance: 'moderate', // Always moderate for optimal balance
  industry: 'general', // Always general for broad coverage
  languages: ['en'], // detected languages
  trustedDomains: [], // user's trusted domains
  threatHistory: [], // past threats encountered
  learningEnabled: true, // Always enabled for better detection
  personalizedAlerts: true, // Always enabled for better UX
  confidenceThreshold: 0.7 // Always balanced threshold
};

// Industry-specific phishing patterns and personalized alerts
const INDUSTRY_PATTERNS = {
  banking: {
    urgencyWords: ['account suspended', 'fraudulent activity', 'verify immediately', 'security breach'],
    moneyWords: ['wire transfer', 'account balance', 'transaction failed', 'payment declined'],
    brands: ['chase', 'bankofamerica', 'wellsfargo', 'citibank', 'visa', 'mastercard'],
    alerts: {
      bankScam: "⚠ This looks like a bank scam targeting financial professionals. Never share OTP or account details.",
      wireFraud: "⚠ Potential wire transfer fraud. Confirm all payment instructions through verified channels.",
      generic: "⚠ Financial phishing attempt detected. Contact IT security if you received this at work."
    }
  },
  healthcare: {
    urgencyWords: ['medical emergency', 'prescription ready', 'insurance claim', 'appointment confirmation'],
    moneyWords: ['copay', 'deductible', 'medical bill', 'insurance payment'],
    brands: ['medicare', 'medicaid', 'bluecross', 'aetna', 'cigna'],
    alerts: {
      insuranceScam: "⚠ Suspicious insurance claim request. Verify patient information through official channels.",
      billingFraud: "⚠ Potential billing fraud detected. Contact billing department before processing.",
      patientData: "⚠ This may be attempting to steal patient data. Report to HIPAA compliance officer.",
      generic: "⚠ Healthcare phishing attempt. Protect patient information and report to IT security."
    }
  },
  tech: {
    urgencyWords: ['security update', 'account compromised', 'data breach', 'system maintenance'],
    moneyWords: ['subscription renewal', 'license expired', 'cloud storage', 'software update'],
    brands: ['microsoft', 'google', 'apple', 'amazon', 'adobe', 'salesforce'],
    alerts: {
      credentialHarvest: "⚠ This appears to be targeting tech professionals. Never enter credentials on suspicious sites.",
      subscriptionScam: "⚠ Suspicious subscription renewal. Verify through official company portals only.",
      generic: "⚠ Tech phishing attempt detected. Report to IT security team immediately."
    }
  },
  education: {
    urgencyWords: ['grade posted', 'tuition due', 'financial aid', 'scholarship opportunity'],
    moneyWords: ['tuition payment', 'student loan', 'financial aid', 'scholarship'],
    brands: ['fafsa', 'studentloans', 'collegeboard', 'university'],
    alerts: {
      financialAidScam: "⚠ Suspicious financial aid request. Verify through official university channels.",
      tuitionFraud: "⚠ Potential tuition payment fraud. Contact financial aid office directly.",
      generic: "⚠ Educational phishing attempt. Protect student data and report to IT services."
    }
  },
  general: {
    urgencyWords: ['urgent', 'immediately', 'act now', 'limited time'],
    moneyWords: ['payment', 'invoice', 'refund', 'prize'],
    brands: ['paypal', 'amazon', 'netflix', 'spotify'],
    alerts: {
      invoiceScam: "⚠ Suspicious invoice detected. Verify with the sender before paying.",
      credentialHarvest: "⚠ This appears to be a credential harvesting attempt. Do not enter your login details.",
      generic: "⚠ This message shows signs of phishing. Exercise caution."
    }
  }
};

// Language-specific phishing patterns and personalized alerts
const LANGUAGE_PATTERNS = {
  en: {
    urgencyWords: ['urgent', 'immediately', 'act now', 'limited time', 'expires soon'],
    moneyWords: ['payment', 'invoice', 'refund', 'prize', 'lottery'],
    greetings: ['dear', 'hello', 'hi', 'greetings'],
    alerts: {
      bankScam: "⚠ This looks like a bank scam. Never share your OTP with anyone.",
      paymentFraud: "⚠ Suspicious payment request detected. Verify the sender before proceeding.",
      credentialHarvest: "⚠ This message is trying to steal your login credentials. Do not click any links.",
      generic: "⚠ This message appears to be phishing. Do not share personal information."
    }
  },
  es: {
    urgencyWords: ['urgente', 'inmediatamente', 'actúa ahora', 'tiempo limitado', 'expira pronto'],
    moneyWords: ['pago', 'factura', 'reembolso', 'premio', 'lotería'],
    greetings: ['querido', 'hola', 'saludos', 'estimado'],
    alerts: {
      bankScam: "⚠ Esto parece un fraude bancario. Nunca compartas tu OTP con nadie.",
      paymentFraud: "⚠ Solicitud de pago sospechosa detectada. Verifica el remitente antes de proceder.",
      credentialHarvest: "⚠ Este mensaje está tratando de robar tus credenciales. No hagas clic en ningún enlace.",
      generic: "⚠ Este mensaje parece ser phishing. No compartas información personal."
    }
  },
  fr: {
    urgencyWords: ['urgent', 'immédiatement', 'agissez maintenant', 'temps limité', 'expire bientôt'],
    moneyWords: ['paiement', 'facture', 'remboursement', 'prix', 'loterie'],
    greetings: ['cher', 'bonjour', 'salut', 'salutations'],
    alerts: {
      bankScam: "⚠ Cela ressemble à une arnaque bancaire. Ne partagez jamais votre OTP avec qui que ce soit.",
      paymentFraud: "⚠ Demande de paiement suspecte détectée. Vérifiez l'expéditeur avant de continuer.",
      credentialHarvest: "⚠ Ce message tente de voler vos identifiants. Ne cliquez sur aucun lien.",
      generic: "⚠ Ce message semble être du phishing. Ne partagez pas d'informations personnelles."
    }
  },
  hi: {
    urgencyWords: ['तत्काल', 'जरूरी', 'समाप्त', 'निलंबित', 'समाप्त'],
    moneyWords: ['भुगतान', 'चालान', 'वापसी', 'स्थानांतरण', 'जमा'],
    greetings: ['प्रिय', 'नमस्ते', 'सलाम', 'आदरणीय'],
    alerts: {
      bankScam: "⚠ यह बैंक घोटाला लगता है। कभी भी अपना OTP किसी के साथ साझा न करें।",
      paymentFraud: "⚠ संदिग्ध भुगतान अनुरोध का पता चला। आगे बढ़ने से पहले प्रेषक को सत्यापित करें।",
      credentialHarvest: "⚠ यह संदेश आपके लॉगिन क्रेडेंशियल चुराने की कोशिश कर रहा है। कोई भी लिंक पर क्लिक न करें।",
      generic: "⚠ यह संदेश फ़िशिंग हो सकता है, कृपया अपनी जानकारी साझा न करें।"
    }
  }
};

// === User Profile Management ===
function getUserProfile() {
  const stored = localStorage.getItem(USER_PROFILE_KEY);
  return stored ? { ...DEFAULT_USER_PROFILE, ...JSON.parse(stored) } : DEFAULT_USER_PROFILE;
}

function saveUserProfile(profile) {
  localStorage.setItem(USER_PROFILE_KEY, JSON.stringify(profile));
}

function updateThreatHistory(threat) {
  const history = JSON.parse(localStorage.getItem(THREAT_HISTORY_KEY) || '[]');
  history.unshift({
    ...threat,
    timestamp: new Date().toISOString(),
    id: Date.now()
  });
  // Keep only last 50 threats
  if (history.length > 50) history.splice(50);
  localStorage.setItem(THREAT_HISTORY_KEY, JSON.stringify(history));
}

function getThreatHistory() {
  return JSON.parse(localStorage.getItem(THREAT_HISTORY_KEY) || '[]');
}

// Language detection function
function detectLanguage(text) {
  const words = text.toLowerCase().split(/\s+/);
  const languageScores = {};
  
  for (const [lang, patterns] of Object.entries(LANGUAGE_PATTERNS)) {
    let score = 0;
    for (const word of words) {
      if (patterns.urgencyWords.includes(word) || 
          patterns.moneyWords.includes(word) || 
          patterns.greetings.includes(word)) {
        score++;
      }
    }
    languageScores[lang] = score;
  }
  
  const detectedLang = Object.keys(languageScores).reduce((a, b) => 
    languageScores[a] > languageScores[b] ? a : b
  );
  
  return languageScores[detectedLang] > 0 ? detectedLang : 'en';
}

// Generate personalized alerts based on context
function generatePersonalizedAlert(text, score, level, userProfile) {
  const detectedLanguage = detectLanguage(text);
  const languagePatterns = LANGUAGE_PATTERNS[detectedLanguage] || LANGUAGE_PATTERNS.en;
  const industryPatterns = INDUSTRY_PATTERNS[userProfile.industry] || INDUSTRY_PATTERNS.general;
  
  const lc = text.toLowerCase();
  
  // Determine threat type based on content analysis
  let threatType = 'generic';
  
  // Check for specific threat patterns
  if (lc.includes('otp') || lc.includes('verification code') || lc.includes('2fa')) {
    threatType = 'bankScam';
  } else if (lc.includes('payment') || lc.includes('invoice') || lc.includes('wire transfer')) {
    threatType = 'paymentFraud';
  } else if (lc.includes('login') || lc.includes('password') || lc.includes('credentials')) {
    threatType = 'credentialHarvest';
  } else if (lc.includes('insurance') || lc.includes('claim') || lc.includes('medical')) {
    threatType = 'insuranceScam';
  } else if (lc.includes('subscription') || lc.includes('license') || lc.includes('renewal')) {
    threatType = 'subscriptionScam';
  } else if (lc.includes('financial aid') || lc.includes('tuition') || lc.includes('scholarship')) {
    threatType = 'financialAidScam';
  }
  
  // Get appropriate alert based on language and industry
  let alert = languagePatterns.alerts[threatType] || languagePatterns.alerts.generic;
  
  // If industry-specific alert exists and is more relevant, use it
  if (industryPatterns.alerts && industryPatterns.alerts[threatType]) {
    alert = industryPatterns.alerts[threatType];
  }
  
  // Add context information
  const contextInfo = [];
  if (detectedLanguage !== 'en') {
    contextInfo.push(`Detected language: ${detectedLanguage.toUpperCase()}`);
  }
  if (userProfile.industry !== 'general') {
    contextInfo.push(`Industry context: ${userProfile.industry}`);
  }
  
  if (contextInfo.length > 0) {
    alert += `\n\nContext: ${contextInfo.join(', ')}`;
  }
  
  return {
    alert,
    threatType,
    language: detectedLanguage,
    industry: userProfile.industry,
    score,
    level
  };
}

// Confidence scoring function
function calculateConfidence(heur, ai = null) {
  let confidence = 0.5; // Base confidence
  
  // Higher confidence for known typos
  if (heur.signals.some(s => s.type === 'Brand Typo Detection')) {
    confidence += 0.3;
  }
  
  // Higher confidence for multiple signals
  if (heur.signals.length > 3) {
    confidence += 0.2;
  }
  
  // Higher confidence if AI agrees
  if (ai && ai.riskLevel === heur.level) {
    confidence += 0.2;
  }
  
  // Higher confidence for high scores
  if (heur.score > 70) {
    confidence += 0.1;
  }
  
  return Math.min(confidence, 1.0);
}

// === Utility: Safe node creation to avoid XSS ===
function createEl(tag, opts = {}) {
  const el = document.createElement(tag);
  if (opts.className) el.className = opts.className;
  if (opts.text != null) el.textContent = opts.text; // never innerHTML for user/model text
  if (opts.attrs)
    for (const [k, v] of Object.entries(opts.attrs)) el.setAttribute(k, v);
  return el;
}

// === Utility: Exponential Backoff Fetch ===
async function fetchWithBackoff(url, options, retries = 3, delay = 1000) {
  try {
    const res = await fetch(url, options);
    if (res.status === 429 && retries > 0) {
      await new Promise((r) => setTimeout(r, delay));
      return fetchWithBackoff(url, options, retries - 1, delay * 2);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  } catch (err) {
    if (retries > 0) {
      await new Promise((r) => setTimeout(r, delay));
      return fetchWithBackoff(url, options, retries - 1, delay * 2);
    }
    throw err;
  }
}

// === Heuristics (runs locally, in real time) ===
const WORDS_URGENCY = [
  "urgent","immediately","now","asap","act now","final notice","last warning","suspend","suspended","verify now","limited time","expires","deadline",
];
const WORDS_CREDS = [
  "password","passcode","otp","one-time","one time","2fa","verification code","login","log in","sign in","credentials","account details",
];
const WORDS_MONEY = [
  "gift card","crypto","bitcoin","wire","bank transfer","western union","payment","invoice","refund","prize","lottery","cash","paypal","phonePe","Gpay","Free gift","prize winner","you've won","exclusive offer","new job opportunity","you won't believe","secret","see who viewed your profile",
];
const SUSPICIOUS_TLDS = ["zip","mov","gq","tk","ml","cf","ga","top","virus","malware","ly"];
const BRAND_KEYWORDS = ["microsoft1","google1","apple0","paypal-1","amazon01","bank","netflix2","netmirror","bitcoin"];

// Known legitimate domains for comparison (same as server)
const LEGITIMATE_DOMAINS = [
  'paypal.com', 'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
  'netflix.com', 'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
  'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com', 'wikipedia.org',
  'ebay.com', 'shopify.com', 'stripe.com', 'square.com', 'dropbox.com',
  'adobe.com', 'salesforce.com', 'zoom.us', 'slack.com', 'discord.com',
  'bankofamerica.com', 'wellsfargo.com', 'chase.com', 'citibank.com',
  'visa.com', 'mastercard.com', 'americanexpress.com', 'discover.com'
];

// Common typos and variations for major brands (same as server)
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

// Function to detect brand variations in domains
function detectBrandVariations(urlObjs) {
  let brandVariationScore = 0;
  const detectedVariations = [];

  for (const urlObj of urlObjs) {
    try {
      const u = new URL(urlObj.normalized);
      const hostname = u.hostname.toLowerCase();
      const domainWithoutTld = hostname.split('.').slice(0, -1).join('.');

      // Check for exact brand variations
      for (const [brand, variations] of Object.entries(BRAND_VARIATIONS)) {
        if (variations.includes(hostname) || variations.includes(domainWithoutTld)) {
          brandVariationScore += 50; // High score for known typos
          detectedVariations.push({
            domain: hostname,
            brand: brand,
            type: 'known_typo',
            score: 50
          });
        }
      }

      // Check for similarity to legitimate domains
      for (const legitDomain of LEGITIMATE_DOMAINS) {
        const legitWithoutTld = legitDomain.split('.').slice(0, -1).join('.');
        const similarity = calculateSimilarity(domainWithoutTld, legitWithoutTld);
        
        if (similarity > 0.8 && similarity < 1.0) { // Similar but not exact
          const score = Math.round(similarity * 30); // Moderate score for similarity
          brandVariationScore += score;
          detectedVariations.push({
            domain: hostname,
            brand: legitDomain,
            type: 'similarity',
            score: score,
            similarity: similarity
          });
        }
      }
    } catch (e) {
      // Skip invalid URLs
    }
  }

  return { score: Math.min(brandVariationScore, 60), variations: detectedVariations };
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

// quick & cheap distance for lookalike detection (Levenshtein-lite)
function editDistance(a, b) {
  a = a.toLowerCase();
  b = b.toLowerCase();
  const dp = Array.from({ length: a.length + 1 }, () =>
    Array(b.length + 1).fill(0)
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[a.length][b.length];
}

/**
 * extractUrls
 * returns array of { raw, normalized, hasScheme }
 * - raw: the original matched fragment from text (friendly display)
 * - normalized: a URL string with http:// prefixed if no scheme present (safe for URL parsing)
 * - hasScheme: whether the original user text included an explicit http/https scheme
 */
function extractUrls(text) {
  // Improved regex to avoid false positives like "john.smith" or "user.name"
  const regex =
    /\b((?:https?:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\/[^\s]*)?|\bhttps?:\/\/\S+)/gi;
  const matches = text.match(regex) || [];
  
  return matches
    .filter(url => {
      // Filter out common false positives
      const hostname = url.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
      
      // Skip if it looks like a name (firstname.lastname pattern)
      if (/^[a-z]+\.[a-z]+$/.test(hostname) && hostname.length < 15) {
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
    .map((u) => {
      const hasScheme = /^https?:\/\//i.test(u);
      // normalize for parsing (but keep hasScheme)
      const normalized = hasScheme ? u : (u.startsWith("http://") || u.startsWith("https://") ? u : "http://" + u);
      return { raw: u, normalized, hasScheme };
    });
}

/**
 * analyzeLinks
 * Accepts array of objects from extractUrls and returns findings that include host, tld, flags
 */
function analyzeLinks(urlObjs) {
  const findings = [];
  for (const obj of urlObjs) {
    const rawToShow = obj.raw;
    try {
      const u = new URL(obj.normalized);
      const host = u.hostname;
      const parts = host.split(".");
      const tld = parts[parts.length - 1] || "";
      const isIP = /^[0-9.]+$/.test(host);
      const tooManyDots = (host.match(/\./g) || []).length >= 3;
      const hasAt = obj.raw.includes("@");

      const tldSuspicious = SUSPICIOUS_TLDS.includes(tld.toLowerCase());
      const lookalikes = BRAND_KEYWORDS.map((b) => ({
        brand: b,
        dist: editDistance(host.replace(/^www\./, ""), b),
      })).filter((x) => x.dist > 0 && x.dist <= 2);

      const flags = [];
      if (isIP) flags.push("🚨 IP Address Only - No Domain Name");
      if (tooManyDots) flags.push("🔗 Suspicious Subdomain Structure");
      if (hasAt) flags.push("⚠️ Malformed URL with @ Symbol");
      if (tldSuspicious) flags.push(`🌐 Suspicious TLD (.${tld}) - High Risk`);
      if (lookalikes.length) {
        const brandNames = lookalikes.map(l => l.brand).join(", ");
        flags.push(`🎭 Brand Impersonation Detected (${brandNames})`);
      }

      findings.push({ url: rawToShow, normalized: obj.normalized, host, tld, flags });
    } catch (_) {
      findings.push({ url: rawToShow, host: "-", tld: "-", flags: ["❌ Invalid URL Format"] });
    }
  }
  return findings;
}

// Enhanced PII Detection (matches server-side logic)
function detectPII(text) {
  let score = 0;
  const details = [];
  
  // Email detection
  const emails = text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g);
  if (emails) {
    score += emails.length * 8;
    details.push(`${emails.length} email(s) detected`);
  }
  
  // Phone detection
  const phones = text.match(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g);
  if (phones) {
    score += phones.length * 6;
    details.push(`${phones.length} phone number(s) detected`);
  }
  
  // Credit card detection
  const cards = text.match(/\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b/g);
  if (cards) {
    score += cards.length * 15;
    details.push(`${cards.length} credit card number(s) detected`);
  }
  
  // PIN detection
  const pins = text.match(/\b(?:PIN|pin|Pin)\s*(?:is|:|=)?\s*\d{3,6}\b/gi);
  if (pins) {
    score += pins.length * 12;
    details.push(`${pins.length} PIN(s) detected`);
  }
  
  // Account number detection
  const accounts = text.match(/\b[A-Za-z]{2,3}\d{4,8}\b/g);
  if (accounts) {
    score += accounts.length * 10;
    details.push(`${accounts.length} account number(s) detected`);
  }
  
  // Address detection
  const addresses = text.match(/\b\d{1,5}\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Place|Pl)\b/gi);
  if (addresses) {
    score += addresses.length * 8;
    details.push(`${addresses.length} address(es) detected`);
  }
  
  // Name detection
  const names = text.match(/\b(?:Mr|Mrs|Ms|Dr)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g);
  if (names) {
    score += names.length * 5;
    details.push(`${names.length} name(s) detected`);
  }
  
  return {
    score: Math.min(score, 40), // Cap at 40 points
    detail: details.length > 0 ? details.join(', ') : 'No PII detected'
  };
}

// Enhanced Social Engineering Detection
function detectSocialEngineering(text) {
  let score = 0;
  const details = [];
  const lc = text.toLowerCase();
  
  // Authority impersonation
  const authorityWords = ['irs', 'fbi', 'police', 'court', 'government', 'official', 'authority', 'agent', 'officer'];
  const authorityCount = authorityWords.filter(w => lc.includes(w)).length;
  if (authorityCount > 0) {
    score += authorityCount * 8;
    details.push(`${authorityCount} authority reference(s)`);
  }
  
  // Trust manipulation
  const trustWords = ['trusted', 'verified', 'secure', 'official', 'legitimate', 'certified', 'guaranteed'];
  const trustCount = trustWords.filter(w => lc.includes(w)).length;
  if (trustCount > 0) {
    score += trustCount * 5;
    details.push(`${trustCount} trust-building word(s)`);
  }
  
  // Fear tactics
  const fearWords = ['urgent', 'immediate', 'expire', 'suspend', 'close', 'terminate', 'violation', 'penalty', 'fine'];
  const fearCount = fearWords.filter(w => lc.includes(w)).length;
  if (fearCount > 0) {
    score += fearCount * 6;
    details.push(`${fearCount} fear-inducing word(s)`);
  }
  
  // Greed tactics
  const greedWords = ['free', 'prize', 'winner', 'congratulations', 'bonus', 'reward', 'cash', 'money', 'lottery'];
  const greedCount = greedWords.filter(w => lc.includes(w)).length;
  if (greedCount > 0) {
    score += greedCount * 4;
    details.push(`${greedCount} greed-inducing word(s)`);
  }
  
  // Impersonation patterns
  const impersonationPatterns = [
    /your account/i,
    /your profile/i,
    /your information/i,
    /verify your/i,
    /confirm your/i,
    /update your/i
  ];
  const impersonationCount = impersonationPatterns.filter(p => p.test(text)).length;
  if (impersonationCount > 0) {
    score += impersonationCount * 7;
    details.push(`${impersonationCount} impersonation pattern(s)`);
  }
  
  return {
    score: Math.min(score, 35), // Cap at 35 points
    detail: details.length > 0 ? details.join(', ') : 'No social engineering detected'
  };
}

// Enhanced Suspicious Patterns Detection
function detectSuspiciousPatterns(text) {
  let score = 0;
  const details = [];
  const lc = text.toLowerCase();
  
  // Suspicious grammar patterns
  const grammarPatterns = [
    /click here/i,
    /click below/i,
    /click the link/i,
    /follow this link/i,
    /visit this link/i,
    /access your account/i,
    /log into your account/i,
    /sign in to your account/i
  ];
  const grammarCount = grammarPatterns.filter(p => p.test(text)).length;
  if (grammarCount > 0) {
    score += grammarCount * 6;
    details.push(`${grammarCount} suspicious grammar pattern(s)`);
  }
  
  // Suspicious punctuation patterns
  const excessiveExclamation = (text.match(/!/g) || []).length;
  if (excessiveExclamation >= 5) {
    score += 8;
    details.push(`${excessiveExclamation} exclamation marks`);
  }
  
  const excessiveQuestion = (text.match(/\?/g) || []).length;
  if (excessiveQuestion >= 3) {
    score += 5;
    details.push(`${excessiveQuestion} question marks`);
  }
  
  // Suspicious formatting
  const allCapsLines = text.split('\n').filter(line => 
    line.trim().length >= 10 && line === line.toUpperCase()
  ).length;
  if (allCapsLines > 0) {
    score += allCapsLines * 4;
    details.push(`${allCapsLines} ALL CAPS line(s)`);
  }
  
  // Suspicious character patterns
  const suspiciousChars = (text.match(/[^\x00-\x7F]/g) || []).length;
  if (suspiciousChars > 5) {
    score += 10;
    details.push(`${suspiciousChars} non-ASCII characters`);
  }
  
  // Suspicious number patterns
  const suspiciousNumbers = text.match(/\b\d{10,}\b/g);
  if (suspiciousNumbers) {
    score += suspiciousNumbers.length * 3;
    details.push(`${suspiciousNumbers.length} suspicious number(s)`);
  }
  
  // Suspicious spacing patterns
  const excessiveSpaces = (text.match(/  +/g) || []).length;
  if (excessiveSpaces >= 3) {
    score += 4;
    details.push('excessive spacing');
  }
  
  return {
    score: Math.min(score, 30), // Cap at 30 points
    detail: details.length > 0 ? details.join(', ') : 'No suspicious patterns detected'
  };
}

function scoreHeuristics(text) {
  const lc = text.toLowerCase();
  const signals = [];
  const userProfile = getUserProfile();
  
  // Detect language and get language-specific patterns
  const detectedLanguage = detectLanguage(text);
  const languagePatterns = LANGUAGE_PATTERNS[detectedLanguage] || LANGUAGE_PATTERNS.en;
  
  // Get industry-specific patterns
  const industryPatterns = INDUSTRY_PATTERNS[userProfile.industry] || INDUSTRY_PATTERNS.general;
  
  // Combine default patterns with industry and language-specific patterns
  const combinedUrgencyWords = [...WORDS_URGENCY, ...languagePatterns.urgencyWords, ...industryPatterns.urgencyWords];
  const combinedMoneyWords = [...WORDS_MONEY, ...languagePatterns.moneyWords, ...industryPatterns.moneyWords];

  // Count matches with adaptive patterns
  const urgCount = combinedUrgencyWords.filter(w => lc.includes(w)).length;
  const credCount = WORDS_CREDS.filter(w => lc.includes(w)).length;
  const moneyCount = combinedMoneyWords.filter(w => lc.includes(w)).length;

  const lines = text.split(/\r?\n/);
  const shouty = lines.filter(l => l.trim().length >= 6 && l === l.toUpperCase()).length;
  const excls = (text.match(/!/g) || []).length;

  // Enhanced PII Detection (like server-side)
  const piiScore = detectPII(text);
  
  // Enhanced Social Engineering Patterns
  const socialEngScore = detectSocialEngineering(text);
  
  // Enhanced Suspicious Patterns
  const suspiciousScore = detectSuspiciousPatterns(text);

  const urlObjs = extractUrls(text);
  const linkFindings = analyzeLinks(urlObjs);
  
  // Detect brand variations (NEW!)
  const brandVariationAnalysis = detectBrandVariations(urlObjs);

  // Score components (normalized and safer weights)
  // Penalize only when explicit http scheme is present in the original text (hasScheme)
  const httpLinks = urlObjs.filter(u => u.hasScheme && u.normalized.startsWith("http://")).length;
  const httpLinkScore = Math.min(httpLinks * 20, 40); // smaller penalty for explicitly insecure http links

  // Adaptive scoring based on user risk tolerance
  const riskMultiplier = userProfile.riskTolerance === 'conservative' ? 1.3 : 
                        userProfile.riskTolerance === 'aggressive' ? 0.7 : 1.0;
  
  const urgencyScore = Math.min(urgCount * 12 * riskMultiplier, 36);
  const credsScore = Math.min(credCount * 18 * riskMultiplier, 36);
  const moneyScore = Math.min(moneyCount * 10 * riskMultiplier, 30);
  const brandScore = linkFindings.some(f => f.flags.some(fl => fl.toLowerCase().includes("brand"))) ? 20 : 0;
  const brandVariationScore = brandVariationAnalysis.score; // NEW: Brand variation detection
  const shoutScore = Math.min(shouty * 12, 18);
  const exclScore = Math.min(excls * 4, 12);
  const linkScore = Math.min(urlObjs.length * 5, 25);

  // suspicious TLDs in actual links (not just text)
  const suspiciousLinks = linkFindings.filter(f => f.flags.some(flag => /^Suspicious TLD/i.test(flag))).length;
  const susscore = Math.min(suspiciousLinks * 30, 60);

  let linkFlagsScore = 0;
  for (const f of linkFindings) linkFlagsScore += f.flags.length * 2;
  linkFlagsScore = Math.min(linkFlagsScore, 12);         // cap

  // Enhanced scoring with new detection methods
  const rawScore = httpLinkScore + urgencyScore + credsScore + moneyScore + brandScore + brandVariationScore + 
                   shoutScore + exclScore + linkScore + linkFlagsScore + susscore + 
                   piiScore.score + socialEngScore.score + suspiciousScore.score;

  // clamp to 0-100 and round
  const score = Math.max(0, Math.min(100, Math.round(rawScore)));

  // Determine level with improved thresholds
  let level = "Low";
  if (score >= 65) level = "High";  // Lowered threshold for better detection
  else if (score >= 30) level = "Medium";  // Lowered threshold for better detection

  // Add signals for display
  if (urgCount) signals.push({ type: "Urgency", weight: urgencyScore, detail: `Found ${urgCount} urgency cue(s) (${detectedLanguage} patterns)` });
  if (credCount) signals.push({ type: "Credentials Request", weight: credsScore, detail: `Mentions of credentials/OTP: ${credCount}` });
  if (moneyCount) signals.push({ type: "Financial Ask", weight: moneyScore, detail: `Payment-related terms: ${moneyCount} (${userProfile.industry} industry)` });
  
  // Add adaptive signals
  if (detectedLanguage !== 'en') signals.push({ type: "Language Detection", weight: 5, detail: `Detected language: ${detectedLanguage.toUpperCase()}` });
  if (userProfile.industry !== 'general') signals.push({ type: "Industry Context", weight: 3, detail: `Industry-specific patterns: ${userProfile.industry}` });
  if (userProfile.riskTolerance !== 'moderate') signals.push({ type: "Risk Profile", weight: 2, detail: `Risk tolerance: ${userProfile.riskTolerance}` });
  if (brandScore) signals.push({ type: "Brand Impersonation", weight: brandScore, detail: `Possible brand lookalike detected in links` });
  if (brandVariationScore > 0) {
    const variations = brandVariationAnalysis.variations;
    const topVariation = variations[0];
    if (topVariation) {
      signals.push({ 
        type: "Brand Typo Detection", 
        weight: brandVariationScore, 
        detail: `Suspicious domain "${topVariation.domain}" detected (${topVariation.type === 'known_typo' ? 'known typo' : 'similar to'} ${topVariation.brand})` 
      });
    }
  }
  if (shouty) signals.push({ type: "Shouting", weight: shoutScore, detail: `${shouty} line(s) in ALL CAPS` });
  if (excls >= 3) signals.push({ type: "Excessive Punctuation", weight: exclScore, detail: `${excls} exclamation marks` });
  if (urlObjs.length) signals.push({ type: "Links Present", weight: linkScore, detail: `${urlObjs.length} link(s) detected` });
  if (linkFlagsScore) signals.push({ type: "Link Flags", weight: linkFlagsScore, detail: "Suspicious link characteristics present" });
  
  // Add enhanced detection signals
  if (piiScore.score > 0) signals.push({ type: "PII Detection", weight: piiScore.score, detail: piiScore.detail });
  if (socialEngScore.score > 0) signals.push({ type: "Social Engineering", weight: socialEngScore.score, detail: socialEngScore.detail });
  if (suspiciousScore.score > 0) signals.push({ type: "Suspicious Patterns", weight: suspiciousScore.score, detail: suspiciousScore.detail });

  // return normalized values: urls array is user-facing raw matches
  return { score, level, signals, urls: urlObjs.map(u=>u.raw), linkFindings };
}


// === UI: Risk Meter & Labels ===
function setRisk(score, level, riskFill, riskLabel) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  riskFill.style.width = `${clamped}%`;
  riskLabel.textContent = `${level} (${clamped})`;
  riskLabel.className = "text-sm px-2 py-1 rounded-lg";
  // reset background classes by reassigning className above then adding one
  if (level === "High") riskLabel.classList.add("bg-red-600/30");
  else if (level === "Medium") riskLabel.classList.add("bg-amber-600/30");
  else if (level === "Low") riskLabel.classList.add("bg-green-600/30");
  else riskLabel.classList.add("bg-slate-800");
}

// === Server API Calls ===

async function analyzeWithGemini(message) {
  try {
    const res = await fetchWithBackoff('/api/analyze', {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    const data = await res.json();
    
    if (data.error) {
      console.error('Server error:', data.error);
      return null;
    }

    if (typeof data?.riskLevel === "string" && typeof data?.reasoning === "string") {
      return { 
        riskLevel: data.riskLevel, 
        reasoning: data.reasoning,
        officialWebsite: data.officialWebsite || null,
        punycodeAnalysis: data.punycodeAnalysis || [],
        domainsAnalyzed: data.domainsAnalyzed || []
      };
    }
  } catch (error) {
    console.error('Error calling analyze API:', error);
  }
  return null;
}

async function generateSafeReply(message) {
  const fallback =
    "Thanks for reaching out. I can't verify this request or the link provided, so I won't be sharing any personal information. Please contact me through an official channel I can independently verify.";

  try {
    const res = await fetchWithBackoff('/api/reply', {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    const data = await res.json();
    
    if (data.error) {
      console.error('Server error:', data.error);
      return fallback;
    }

    const reply = data?.["safe reply"];
    if (reply && typeof reply === "string") return reply;
  } catch (error) {
    console.error('Error calling reply API:', error);
  }
  return fallback;
}

// === Masking: Protect user PII before sending to AI ===
function maskSensitiveData(text) {
  let masked = String(text);

  const report = { emails: 0, phones: 0, pins: 0, accounts: 0, cards: 0, addresses: 0, names: 0 };

  // 1) Emails
  const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  masked = masked.replace(emailRegex, (m) => {
    report.emails++;
    return "[REDACTED EMAIL]";
  });

  // 2) PIN (explicit)
  const pinRegex = /\b(pin|PIN)\s*[:\-]?\s*(\d{4,6})\b/g;
  masked = masked.replace(pinRegex, (m) => {
    report.pins++;
    return "[REDACTED PIN]";
  });

  // 3) Credit-card like sequences (13-19 digits, allow spaces/dashes)
  const cardRegex = /(?<!\d)(?:\d[ \-]*){13,19}(?!\d)/g;
  masked = masked.replace(cardRegex, (m) => {
    report.cards++;
    return "[REDACTED CARD]";
  });

  // 4) Phone numbers (various formats, keep loose but practical)
  const phoneRegex = /(\+?\d{1,3}[-.\s(]*\d{2,4}[-.\s)]*\d{2,4}[-.\s]*\d{2,4})/g;
  masked = masked.replace(phoneRegex, (m) => {
    // avoid masking short digit groups only (e.g. 2-digit years)
    const digitsOnly = m.replace(/\D/g, "");
    if (digitsOnly.length < 7) return m; // probably not a phone
    report.phones++;
    return "[REDACTED PHONE]";
  });

  // 5) Account numbers (long digit sequences 8+ digits not already caught)
  const accountRegex = /(?<!\d)(\d{8,20})(?!\d)/g;
  masked = masked.replace(accountRegex, (m) => {
    report.accounts++;
    return "[REDACTED ACCOUNT]";
  });

  // 6) Addresses - Single comprehensive pattern to catch complete addresses
  // This pattern captures complete addresses including street number, name, type, apartment/suite, city, state, and ZIP
  const addressRegex = /\b\d{1,5}[A-Za-z]?\s+(?:[A-Za-z0-9#]+\s?){1,6}(?:Street|St\.|Road|Rd\.|Avenue|Ave\.|Boulevard|Blvd\.|Lane|Ln\.|Drive|Dr\.|Way|Place|Pl\.|Circle|Cir\.|Court|Ct\.|Crescent|Cres\.|Close|Cl\.|Terrace|Tce\.|Grove|Gr\.|Gardens|Gdns\.|Square|Sq\.|Heights|Hts\.|Manor|Mews|Park|Pk\.|Rise|View|Vale|Walk|Wood|Wynd)(?:\s*,\s*(?:Suite|Ste|Apt|Apartment|Unit|Floor|Fl)\s*[A-Za-z0-9#\s]*)?(?:\s*,\s*[A-Za-z\s]+,\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?)?/gi;

  masked = masked.replace(addressRegex, (m) => {
    report.addresses++;
    return "[REDACTED ADDRESS]";
  });


  // 7) "Name: John Doe" style explicit labels
  const nameLabelRegex = /\b(Name|Full Name|Your Name)\s*[:\-]\s*([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)/g;
  masked = masked.replace(nameLabelRegex, (m, p1) => {
    report.names++;
    return `${p1}: [REDACTED NAME]`;
  });

  // 8) Greetings like "Dear John" or "Hi John"
  const greetRegex = /(^|\n)(\s*(Dear|Hi|Hello|Hey)\s+)([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)/g;
  masked = masked.replace(greetRegex, (m, p1, p2) => {
    report.names++;
    return `${p1}${p2}[REDACTED NAME]`;
  });

  return { masked, report };
}

// === Rendering ===
function renderLinks(findings, riskScore = 0, linksList, linksPanel) {
  linksList.innerHTML = "";
  if (!findings.length) {
    linksPanel.classList.add("hidden");
    return;
  }
  linksPanel.classList.remove("hidden");
  for (const f of findings) {
    // Calculate link risk level based on overall risk score
    let riskLevel = "Low";
    let riskColor = "border-slate-700";
    let riskBg = "bg-slate-900";
    
    // Use the overall risk score to determine link risk
    if (riskScore >= 70) {
      riskLevel = "High";
      riskColor = "border-red-500";
      riskBg = "bg-red-900/20";
    } else if (riskScore >= 35) {
      riskLevel = "Medium";
      riskColor = "border-orange-500";
      riskBg = "bg-orange-900/20";
    } else {
      // For low risk, still check if individual link has suspicious flags
      const hasHighRiskFlags = f.flags.some(flag => 
        flag.includes("Suspicious TLD") || 
        flag.includes("Brand Impersonation") || 
        flag.includes("Invalid URL Format") ||
        flag.includes("IP Address Only")
      );
      
      if (hasHighRiskFlags) {
        riskLevel = "Medium";
        riskColor = "border-orange-500";
        riskBg = "bg-orange-900/20";
      }
    }

    const li = createEl("li", {
      className: `p-3 rounded-lg ${riskBg} border ${riskColor}`,
    });

    const top = createEl("div", {
      className: "flex items-center justify-between gap-3",
    });
    
    // Add risk indicator
    const riskIndicator = createEl("span", {
      className: riskLevel === "High" ? "px-2 py-1 rounded-full bg-red-600 text-white text-xs font-bold" :
                   riskLevel === "Medium" ? "px-2 py-1 rounded-full bg-orange-600 text-white text-xs font-bold" :
                   "px-2 py-1 rounded-full bg-green-600 text-white text-xs font-bold",
      text: `${riskLevel} RISK`
    });
    
    const urlSpan = createEl("span", { className: "truncate text-white font-medium", text: f.url });
    const open = createEl("a", {
      className: "y2k-button-secondary text-xs",
      attrs: { href: f.normalized || f.url, target: "_blank", rel: "noopener noreferrer" },
      text: riskLevel === "High" ? "⚠️ Open at own risk" : "Open (cautiously)",
    });
    
    top.appendChild(riskIndicator);
    top.appendChild(urlSpan);
    top.appendChild(open);

    const meta = createEl("div", { className: "mt-2 text-xs text-slate-300" });
    meta.textContent = `Host: ${f.host}   TLD: ${f.tld}`;

    const flags = createEl("div", { className: "mt-2 flex flex-wrap gap-2" });
    if (f.flags.length) {
      for (const flag of f.flags) {
        const chip = createEl("span", {
          className:
            "px-2 py-1 rounded-full bg-red-600/20 text-red-200 text-xs",
          text: flag,
        });
        flags.appendChild(chip);
      }
    }

    li.appendChild(top);
    li.appendChild(meta);
    li.appendChild(flags);
    linksList.appendChild(li);
  }
}

function renderAnalysisCard({ finalLevel, finalReason, heur, ai, finalScore, note }, analysisResult) {
  analysisResult.className = "y2k-result"; // reset
  if (finalLevel === "High") analysisResult.classList.add("phishing");
  else if (finalLevel === "Medium") analysisResult.classList.add("medium");
  else if (finalLevel === "Low") analysisResult.classList.add("safe");
  else analysisResult.classList.add("reply");

  const wrapper = createEl("div");

  const title = createEl("p", { className: "text-2xl font-bold mb-1" });
  title.textContent =
    finalLevel === "High" ? "🚨 HIGH RISK"
    : finalLevel === "Medium" ? "⚠️ MEDIUM RISK"
    : finalLevel === "Low" ? "✅ Looks Safe"
    : "ℹ️ Result";

  const reason = createEl("p", { className: "mt-1 text-base" });
  // Show simplified reason - AI details will be in dedicated section
  if (ai) {
    const confidence = calculateConfidence(heur, ai);
    reason.textContent = `Combined score ${finalScore}/100. AI Risk: ${ai.riskLevel}. Confidence: ${Math.round(confidence * 100)}%`;
  } else {
    const confidence = calculateConfidence(heur);
    reason.textContent = `${finalReason} Confidence: ${Math.round(confidence * 100)}%`;
  }

  // Add personalized alert if risk is detected
  if (finalLevel === "High" || finalLevel === "Medium") {
    const userProfile = getUserProfile();
    const personalizedAlert = generatePersonalizedAlert(
      document.getElementById("message-input").value, 
      finalScore, 
      finalLevel, 
      userProfile
    );
    
    const alertDiv = createEl("div", { 
      className: "mt-3 p-3 bg-red-500/10 border border-red-500/30 rounded-lg" 
    });
    
    const alertText = createEl("p", { 
      className: "text-sm text-red-300 whitespace-pre-line" 
    });
    alertText.textContent = personalizedAlert.alert;
    
    alertDiv.appendChild(alertText);
    wrapper.appendChild(alertDiv);
  }

  wrapper.appendChild(title);
  wrapper.appendChild(reason);

  const hTitle = createEl("p", {
    className: "mt-4 font-semibold",
    text: "Key Signals (local heuristics)",
  });
  wrapper.appendChild(hTitle);

  if (heur.signals.length) {
    const ul = createEl("ul", {
      className: "list-disc ml-6 space-y-1 text-sm",
    });
    for (const s of heur.signals) {
      const li = createEl("li");
      li.textContent = `${s.type}: ${s.detail}`;
      ul.appendChild(li);
    }
    wrapper.appendChild(ul);
  } else {
    wrapper.appendChild(
      createEl("p", { className: "text-sm", text: "No strong local phishing signals." })
    );
  }

  if (ai) {
    // Add AI Assessment section
    const aiSep = createEl("hr", { attrs: { role: "presentation" }, className: "mt-4 border-slate-600" });
    const aiTitle = createEl("p", {
      className: "mt-4 font-bold text-blue-400 text-3xl mb-4 leading-tight",
      text: "AI Assessment",
    });
    
    const aiReasoning = createEl("div", { className: "mt-2 text-lg text-white font-medium" });
    
    // Format AI reasoning properly
    if (ai.reasoning && (ai.reasoning.includes('•') || ai.reasoning.includes('-') || ai.reasoning.includes('*'))) {
      const lines = ai.reasoning.split('\n').filter(line => line.trim());
      const hasBullets = lines.some(line => line.trim().startsWith('•') || line.trim().startsWith('-') || line.trim().startsWith('*'));
      
      if (hasBullets) {
        const ul = createEl("ul", { className: "list-disc ml-4 space-y-1" });
        lines.forEach(line => {
          if (line.trim()) {
            const li = createEl("li", { className: "text-base text-white font-medium" });
            li.textContent = line.replace(/^[•\-\*]\s*/, '').replace(/\*\*(.*?)\*\*/g, '$1').trim();
            ul.appendChild(li);
          }
        });
        aiReasoning.appendChild(ul);
      } else {
        const textLines = ai.reasoning.split('\n').slice(0, 6);
        aiReasoning.textContent = textLines.join('\n');
      }
    } else {
      const textLines = ai.reasoning ? ai.reasoning.split('\n').slice(0, 6) : ['No AI analysis available'];
      aiReasoning.textContent = textLines.join('\n');
    }
    
    wrapper.appendChild(aiSep);
    wrapper.appendChild(aiTitle);
    wrapper.appendChild(aiReasoning);
    
    // Add Punycode analysis if available
    if (ai.punycodeAnalysis && ai.punycodeAnalysis.length > 0) {
      const punycodeSection = createEl("div", { className: "punycode-warning" });
      
      const punycodeTitle = createEl("h4", {
        className: "punycode-warning-title",
        text: "Punycode & Homograph Analysis"
      });
      
      const punycodeText = createEl("p", { className: "text-red-300 font-medium mb-4" });
      punycodeText.textContent = "🚨 Suspicious domain characteristics detected:";
      
      punycodeSection.appendChild(punycodeTitle);
      punycodeSection.appendChild(punycodeText);
      
      // Display each domain analysis
      ai.punycodeAnalysis.forEach(analysis => {
        if (analysis.warnings && analysis.warnings.length > 0) {
          const domainCard = createEl("div", { className: "punycode-domain-card" });
          
          const domainTitle = createEl("h5", { 
            className: "punycode-domain-name mb-3",
            text: analysis.domain
          });
          
          const warningsList = createEl("ul", { className: "punycode-warning-list" });
          analysis.warnings.forEach(warning => {
            const warningItem = createEl("li", { 
              className: "text-red-200",
              text: warning
            });
            warningsList.appendChild(warningItem);
          });
          
          // Show potential targets if any
          if (analysis.potentialTargets && analysis.potentialTargets.length > 0) {
            const targetsSection = createEl("div", { className: "punycode-targets" });
            
            const targetsTitle = createEl("p", { 
              className: "punycode-targets-title",
              text: "Potential Impersonation Targets:"
            });
            
            const targetsList = createEl("ul", { className: "punycode-targets-list" });
            analysis.potentialTargets.slice(0, 3).forEach(target => {
              const targetItem = createEl("li", { 
                className: "text-red-200",
                text: `${target.target} (${Math.round(target.similarity * 100)}% similar) - ${target.method}`
              });
              targetsList.appendChild(targetItem);
            });
            
            // Add official website warning
            const topTarget = analysis.potentialTargets[0];
            if (topTarget && topTarget.officialWebsite) {
              const officialWarning = createEl("div", { className: "mt-4 p-4 bg-yellow-900/30 border border-yellow-500/50 rounded-lg" });
              
              const officialTitle = createEl("h6", { 
                className: "text-yellow-300 font-bold mb-2",
                text: "⚠️ Use the Official Website Instead:"
              });
              
              const officialLink = createEl("a", {
                className: "text-yellow-200 hover:text-yellow-100 underline font-semibold break-all",
                attrs: { 
                  href: topTarget.officialWebsite, 
                  target: "_blank", 
                  rel: "noopener noreferrer" 
                },
                text: topTarget.officialWebsite
              });
              
              const scamWarning = createEl("p", { 
                className: "text-yellow-200 text-sm mt-2",
                text: "This suspicious domain might be trying to impersonate the legitimate site. Always verify URLs before entering sensitive information."
              });
              
              officialWarning.appendChild(officialTitle);
              officialWarning.appendChild(officialLink);
              officialWarning.appendChild(scamWarning);
              targetsSection.appendChild(officialWarning);
            }
            
            targetsSection.appendChild(targetsTitle);
            targetsSection.appendChild(targetsList);
            domainCard.appendChild(targetsSection);
          }
          
          domainCard.appendChild(domainTitle);
          domainCard.appendChild(warningsList);
          punycodeSection.appendChild(domainCard);
        }
      });
      
      wrapper.appendChild(punycodeSection);
    }

    // Add official website if available
    if (ai.officialWebsite) {
      const officialWebsiteSection = createEl("div", { className: "mt-6 p-6 bg-green-900/40 border-2 border-green-500/60 rounded-xl shadow-lg" });
      
      const officialTitle = createEl("h4", {
        className: "text-2xl font-bold mb-4 text-green-400 flex items-center",
      });
      
      const shieldIcon = createEl("i", { className: "fas fa-shield-check text-green-400 mr-3 text-xl" });
      officialTitle.appendChild(shieldIcon);
      officialTitle.appendChild(document.createTextNode("Official Website"));
      
      const officialText = createEl("p", { className: "text-lg mb-4 text-green-300 font-medium" });
      officialText.textContent = "Use the official website:";
      
      const officialLink = createEl("a", {
        className: "text-xl text-green-300 hover:text-green-100 underline break-all font-semibold block mb-4",
        attrs: { 
          href: ai.officialWebsite, 
          target: "_blank", 
          rel: "noopener noreferrer" 
        },
        text: ai.officialWebsite
      });
      
      const warningText = createEl("p", { className: "text-base text-green-300 font-medium bg-green-800/30 p-3 rounded-lg border border-green-400/30" });
      warningText.textContent = "⚠️ Verify the URL matches exactly before clicking";
      
      officialWebsiteSection.appendChild(officialTitle);
      officialWebsiteSection.appendChild(officialText);
      officialWebsiteSection.appendChild(officialLink);
      officialWebsiteSection.appendChild(warningText);
      
      wrapper.appendChild(officialWebsiteSection);
    }
  }

  if (note) {
    const noteEl = createEl("p", { className: "mt-4 text-xs italic", text: note });
    wrapper.appendChild(noteEl);
  }

  const tip = createEl("p", { className: "mt-4 text-xs font-semibold" });
  tip.textContent =
    finalLevel === "High" || finalLevel === "Medium"
      ? "Do not click links or share information until independently verified."
      : "Stay cautious and inspect links before clicking.";

  wrapper.appendChild(tip);

  analysisResult.innerHTML = "";
  analysisResult.appendChild(wrapper);
}

// === Pipeline ===
async function runAnalysis(messageInput, resultContainer, loadingIndicator, analysisResult, riskFill, riskLabel, linksList, linksPanel) {
  const text = messageInput.value.trim();
  if (!text) return;

  resultContainer.classList.remove("hidden");
  loadingIndicator.style.display = "flex";
  analysisResult.innerHTML = "";
  analysisResult.className = "y2k-result";

  const heur = scoreHeuristics(text);
  // Don't update risk meter yet - wait for final combined result
  renderLinks(heur.linkFindings, heur.score, linksList, linksPanel);

  let ai = null;
  try {
    ai = await analyzeWithGemini(text);
  } catch {
    // ignore; heuristics still shown
  }

  loadingIndicator.style.display = "none";

  // Calculate final combined score and level
  let finalLevel = heur.level;
  let finalScore = heur.score;
  let finalReason = `Local score ${heur.score}/100.`;
  
  if (ai) {
    const order = { Low: 0, Medium: 1, High: 2 };
    finalLevel = order[ai.riskLevel] > order[heur.level] ? ai.riskLevel : heur.level;
    
    // Calculate combined score: average of local and AI scores
    const aiScore = ai.riskLevel === 'High' ? 85 : ai.riskLevel === 'Medium' ? 50 : 15;
    finalScore = Math.round((heur.score + aiScore) / 2);
    
    // Ensure final level matches the combined score
    if (finalScore >= 65) finalLevel = "High";
    else if (finalScore >= 30) finalLevel = "Medium";
    else finalLevel = "Low";
    
    finalReason = `Combined score ${finalScore}/100 (Local: ${heur.score}, AI: ${aiScore}). ${ai.reasoning}`;
  }

  // Update risk meter with final combined result
  setRisk(finalScore, finalLevel, riskFill, riskLabel);

  // Update threat history if learning is enabled
  const userProfile = getUserProfile();
  if (userProfile.learningEnabled && finalLevel !== "Low") {
    updateThreatHistory({
      level: finalLevel,
      score: finalScore,
      signals: heur.signals,
      domains: heur.urls,
      text: text.substring(0, 100) + "..." // Store first 100 chars for context
    });
  }

  renderAnalysisCard({ finalLevel, finalReason, heur, ai, finalScore }, analysisResult);
}

// === Events ===
document.addEventListener("DOMContentLoaded", () => {
  // === DOM Refs ===
  const analyzeButton = document.getElementById("analyze-button");
  const replyButton = document.getElementById("reply-button");
  const clearButton = document.getElementById("clear-button");
  const messageInput = document.getElementById("message-input");
  const resultContainer = document.getElementById("result-container");
  const loadingIndicator = document.getElementById("loading-indicator");
  const analysisResult = document.getElementById("analysis-result");
  const riskFill = document.getElementById("risk-fill");
  const riskLabel = document.getElementById("risk-label");
  const linksPanel = document.getElementById("links-panel");
  const linksList = document.getElementById("links-list");
  const liveScanToggle = document.getElementById("live-scan-toggle");
  const charCount = document.getElementById("char-count");

  const sampleBtn = document.getElementById("sample-btn");


  const consentBtn = document.getElementById("consent-button");
  const consentModal = document.getElementById("consent-modal");
  const maskedPreview = document.getElementById("masked-preview");
  const consentCheckbox = document.getElementById("consent-checkbox");
  const sendConsentBtn = document.getElementById("send-consent-btn");
  const cancelConsent = document.getElementById("cancel-consent");
  const closeConsent = document.getElementById("close-consent-btn");

  analyzeButton.addEventListener("click", () => {
    const text = messageInput.value.trim();
    if (!text) {
      alert("Please paste a message to analyze.");
      return;
    }
    const { masked } = maskSensitiveData(text);
    maskedPreview.textContent = masked || "—";
    consentCheckbox.checked = false;
    sendConsentBtn.disabled = true;
    consentModal.showModal();
  });


  replyButton.addEventListener("click", async () => {
    const text = messageInput.value.trim();
    if (!text) return;

    resultContainer.classList.remove("hidden");
    loadingIndicator.style.display = "flex";
    analysisResult.innerHTML = "";
    analysisResult.className = "y2k-result";

    try {
      const replyText = await generateSafeReply(text);
      loadingIndicator.style.display = "none";

      analysisResult.classList.add("reply");
      const title = createEl("p", {
        className: "text-2xl font-bold mb-2",
        text: "✨ Suggested Safe Reply ✨",
      });
      const body = createEl("p", { className: "text-base text-white font-medium" });
      body.textContent = replyText;

      const copyBtn = createEl("button", {
        className: "y2k-button-secondary mt-4",
        text: "Copy",
      });
      copyBtn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(replyText);
          copyBtn.textContent = "Copied!";
        } catch {
          copyBtn.textContent = "Copy failed";
        }
        setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
      });

      analysisResult.innerHTML = "";
      analysisResult.appendChild(title);
      analysisResult.appendChild(body);
      analysisResult.appendChild(copyBtn);
      analysisResult.style.display = "block";
    } catch (e) {
      loadingIndicator.style.display = "none";
      analysisResult.classList.add("phishing");
      analysisResult.textContent = "Error generating reply.";
    }
  });

  clearButton.addEventListener("click", () => {
    messageInput.value = "";
    charCount.textContent = "0 characters";
    setRisk(0, "Unknown", riskFill, riskLabel);
    linksPanel.classList.add("hidden");
    resultContainer.classList.add("hidden");
    analysisResult.innerHTML = "";
  });

  messageInput.addEventListener("input", () => {
    const text = messageInput.value;
    charCount.textContent = `${text.length} character${text.length === 1 ? "" : "s"}`;
    if (!liveScanToggle.checked) return;

    if (!text.trim()) {
      setRisk(0, "Unknown", riskFill, riskLabel);
      linksPanel.classList.add("hidden");
      resultContainer.classList.add("hidden");
      return;
    }

    const heur = scoreHeuristics(text);
    setRisk(heur.score, heur.level, riskFill, riskLabel);
    renderLinks(heur.linkFindings, heur.score, linksList, linksPanel);

    resultContainer.classList.remove("hidden");
    loadingIndicator.style.display = "none";
    analysisResult.innerHTML = "";
    analysisResult.className = "y2k-result";
    
    renderAnalysisCard({
      finalLevel: heur.level,
      finalReason: `Real-time analysis: ${heur.score}/100 (Click Analyze for AI assessment)`,
      heur,
      ai: null,
      finalScore: heur.score,
      note: "Real-time detection active"
    }, analysisResult);
  });



  // Sample
  if (sampleBtn) {
    sampleBtn.addEventListener("click", async () => {
      const sample = `FINAL NOTICE: Your PayPal account will be SUSPENDED in 24 HOURS.
Click https://paypl.com/login to verify your password and 2FA NOW.
Failure to act will result in permanent closure and loss of funds.`;
      messageInput.value = sample;
      messageInput.dispatchEvent(new Event("input"));
    });
  }

  // --- Consent workflow: mask then send to Gemini ---
  consentBtn.addEventListener("click", () => {
    const text = messageInput.value.trim();
    if (!text) {
      alert("Please paste a message to send.");
      return;
    }
    const { masked } = maskSensitiveData(text);
    maskedPreview.textContent = masked || "—";
    consentCheckbox.checked = false;
    sendConsentBtn.disabled = true;
    consentModal.showModal();
  });

  consentCheckbox.addEventListener("change", () => {
    sendConsentBtn.disabled = !consentCheckbox.checked;
  });

  cancelConsent.addEventListener("click", (e) => {
    e.preventDefault();
    consentModal.close();
  });
  closeConsent.addEventListener("click", (e) => {
    e.preventDefault();
    consentModal.close();
  });

  sendConsentBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text) return;

    // Close modal immediately and reset form
    consentModal.close();
    consentCheckbox.checked = false;
    sendConsentBtn.disabled = true;

    const { masked, report } = maskSensitiveData(text);

    // show loading + call
    resultContainer.classList.remove("hidden");
    loadingIndicator.style.display = "flex";
    analysisResult.innerHTML = "";
    analysisResult.className = "y2k-result";

    try {
      const ai = await analyzeWithGemini(masked);
      loadingIndicator.style.display = "none";

      // build a small note about masking counts
      let note = `Masked content sent. Redactions: `;
      const parts = [];
      for (const k of Object.keys(report)) {
        if (report[k]) parts.push(`${k}: ${report[k]}`);
      }
      if (parts.length === 0) note += "none detected.";
      else note += parts.join(", ") + ".";

      // combine heuristics for display
      const heur = scoreHeuristics(text);
      let finalLevel = heur.level;
      let finalReason = `Local score ${heur.score}/100.`;
      if (ai) {
        const order = { Low: 0, Medium: 1, High: 2 };
        finalLevel = order[ai.riskLevel] > order[heur.level] ? ai.riskLevel : heur.level;
        finalReason = `Local score ${heur.score}/100. ${ai.reasoning}`;
      }

      renderAnalysisCard({ finalLevel, finalReason, heur, ai, finalScore: heur.score, note }, analysisResult);
    } catch (err) {
      loadingIndicator.style.display = "none";
      analysisResult.classList.add("phishing");
      analysisResult.textContent = "An error occurred while sending masked content to Gemini. Please try again.";
    }
  });

}); // End DOMContentLoaded