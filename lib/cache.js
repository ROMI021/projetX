import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, '..', 'data');
const DISCOVERY_CACHE_FILE = path.join(DATA_DIR, 'discovery_cache.json');

export function loadDiscoveryCache() {
  try {
    if (fs.existsSync(DISCOVERY_CACHE_FILE)) {
      return JSON.parse(fs.readFileSync(DISCOVERY_CACHE_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Error loading discovery cache:', e);
  }
  return {};
}

export function saveDiscoveryCache(cache) {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DISCOVERY_CACHE_FILE, JSON.stringify(cache, null, 2), 'utf8');
  } catch (e) {
    console.error('Error saving discovery cache:', e);
  }
}
