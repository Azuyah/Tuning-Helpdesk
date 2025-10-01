// scripts/build-dtc-db.mjs
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Källa: GitHub gist med generiska DTC-beskrivningar (JSON-objekt: { "P0301": "Cylinder 1 Misfire Detected", ... })
const SOURCE_URL =
  'https://gist.githubusercontent.com/wzr1337/8af2731a5ffa98f9d506537279da7a0e/raw/a273cf7ee48ba98318e04a6cd667d0de1eb28ad0/dtcmapping.json';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Mål: /public/dtc-codes.json (det som din klient redan fetchar)
const OUT_PATH = path.resolve(__dirname, '..', 'public', 'dtc-codes.json');

function normalizeCode(raw) {
  const s = String(raw || '').toUpperCase().trim();
  // Små städningar: ta bort mellanslag, punkt, bindestreck etc.
  return s.replace(/[^A-Z0-9]/g, '');
}

function detectSystem(code) {
  // Grov systemtagg baserat på prefix:
  // P = Powertrain, B = Body, C = Chassis, U = Network
  if (!code) return null;
  const ch = code[0];
  if (ch === 'P') return 'powertrain';
  if (ch === 'B') return 'body';
  if (ch === 'C') return 'chassis';
  if (ch === 'U') return 'network';
  return null;
}

(async () => {
  console.log('Hämtar DTC-källor…');

  const res = await fetch(SOURCE_URL, { headers: { 'Accept': 'application/json' }});
  if (!res.ok) {
    throw new Error(`Kunde inte hämta källa: ${res.status} ${res.statusText}`);
  }
  const data = await res.json(); // data: { "P0001": "Fuel Volume Regulator Ctrl Circuit/Open", ... }

  // Normalisera till ditt schema:
  // [{ code, short, description, system, generic }]
  const out = [];
  for (const [rawCode, desc] of Object.entries(data)) {
    const code = normalizeCode(rawCode);
    if (!code) continue;
    out.push({
      code,
      short: desc || '',
      description: desc || '',
      system: detectSystem(code),
      generic: true,               // den här källan är generiska (SAE) koder
      source: 'sae-j2012'          // enkel markör för källa
    });
  }

  // Sortera snyggt (P0001.., Bxxxx, Cxxxx, Uxxxx)
  out.sort((a, b) => a.code.localeCompare(b.code, 'en'));

  // Skriv filen
  await fs.mkdir(path.dirname(OUT_PATH), { recursive: true });
  await fs.writeFile(OUT_PATH, JSON.stringify(out, null, 2), 'utf8');

  console.log(`✅ Skrev ${out.length} koder till ${OUT_PATH}`);
})().catch(err => {
  console.error('❌ Bygget misslyckades:', err);
  process.exit(1);
});