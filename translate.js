// translate.js  — DeepL wrapper (ESM)
// Krav: Node 18+ (global fetch), ENV: TRANSLATE_PROVIDER=deepl, TRANSLATE_API_KEY=...

const PROVIDER = (process.env.TRANSLATE_PROVIDER || '').toLowerCase();
const API_KEY  = process.env.TRANSLATE_API_KEY || '';
// DeepL: free-nycklar börjar ofta med "dlk_" och använder api-free.deepl.com
const DEEPL_BASE =
  (API_KEY && API_KEY.startsWith('dlk_'))
    ? 'https://api-free.deepl.com/v2/translate'
    : 'https://api.deepl.com/v2/translate';

// Enkel minnescache för att undvika dubblett-översättningar under samma processkörning
const cache = new Map();

/** Mappar typiska språkalias -> DeepL-koder */
function normalizeLang(lang) {
  if (!lang) return null;
  const l = String(lang).toLowerCase().trim();
  const map = {
    sv: 'SV', se: 'SV', 'sv-se': 'SV',
    en: 'EN', 'en-gb': 'EN-GB', 'en-us': 'EN-US'
  };
  return map[l] || l.toUpperCase();
}

/** Liten helper för www-form-urlencoded body */
function formEncode(params) {
  const usp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (Array.isArray(v)) v.forEach(x => usp.append(k, x));
    else if (v !== undefined && v !== null) usp.append(k, String(v));
  });
  return usp.toString();
}

/**
 * translateText
 * @param {string|string[]} text - sträng eller array av strängar
 * @param {string} targetLang   - t.ex. 'EN' eller 'SV'
 * @param {string} [sourceLang] - t.ex. 'SV' (valfritt, autodetect annars)
 * @returns {Promise<string|string[]>}
 */
export async function translateText(text, targetLang, sourceLang) {
  if (PROVIDER !== 'deepl') {
    throw new Error('TRANSLATE_PROVIDER är inte satt till "deepl".');
  }
  if (!API_KEY) {
    throw new Error('TRANSLATE_API_KEY saknas.');
  }

  const target = normalizeLang(targetLang);
  const source = normalizeLang(sourceLang);

  if (!text || (Array.isArray(text) && text.length === 0)) return text;
  const items = Array.isArray(text) ? text : [text];

  // Cache-nycklar
  const cacheKeys = items.map(t => `deepl:${source||'auto'}>${target}|${t}`);
  const results = new Array(items.length).fill(null);

  // 1) Plocka ur cache först
  const toTranslate = [];
  const toTranslateIdx = [];
  cacheKeys.forEach((key, i) => {
    if (cache.has(key)) {
      results[i] = cache.get(key);
    } else {
      toTranslate.push(items[i]);
      toTranslateIdx.push(i);
    }
  });

  // 2) Inget kvar att översätta? returnera direkt
  if (toTranslate.length === 0) {
    return Array.isArray(text) ? results : results[0];
  }

  // 3) Gör anrop till DeepL (batch i ett request – DeepL stödjer flera "text" fält)
  const body = {
    auth_key: API_KEY,
    target_lang: target,
    // source_lang: source (bara sätt om användaren skickat med något)
    text: toTranslate,
    // Kvalitet/stil (valfritt): preserve_formatting=1 håller radbrytningar bättre
    preserve_formatting: 1
  };
  if (source) body.source_lang = source;

  let resp;
  try {
    resp = await fetch(DEEPL_BASE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formEncode(body),
    });
  } catch (e) {
    throw new Error(`Kunde inte nå DeepL: ${e.message}`);
  }

  if (!resp.ok) {
    // Försök få mer info från DeepL
    let detail = '';
    try { detail = await resp.text(); } catch {}
    throw new Error(`DeepL HTTP ${resp.status}: ${detail || resp.statusText}`);
  }

  const data = await resp.json();
  if (!data || !Array.isArray(data.translations)) {
    throw new Error('Oväntat svar från DeepL.');
  }

  // 4) Lägg tillbaka översättningar i rätt index + cacha
  data.translations.forEach((tr, j) => {
    const idx = toTranslateIdx[j];
    const out = tr.text;
    results[idx] = out;
    cache.set(cacheKeys[idx], out);
  });

  return Array.isArray(text) ? results : results[0];
}

/**
 * Hjälpmetod: översätt bara om texten verkar vara på fel språk.
 * (Mycket enkel heuristik – bra för UI-snuttar.)
 */
export async function translateIfNeeded(text, targetLang, sourceLangGuess) {
  // Här kan du bygga in en riktig språkdetektor senare.
  // Just nu: om sourceLangGuess redan matchar targetLang → returnera text.
  const tgt = normalizeLang(targetLang);
  const src = normalizeLang(sourceLangGuess);
  if (tgt && src && tgt.split('-')[0] === src.split('-')[0]) {
    return text;
  }
  return translateText(text, targetLang, sourceLangGuess);
}