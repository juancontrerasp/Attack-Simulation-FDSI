/**
 * ST-01.5 - Sistema de cache por hash MD5
 * Evita llamadas repetidas a la API para el mismo contenido analizado.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CACHE_DIR = path.join(__dirname, '..', 'cache', 'entries');

function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
}

function hashContent(content) {
  return crypto.createHash('md5').update(content).digest('hex');
}

function cachePath(hash) {
  return path.join(CACHE_DIR, `${hash}.json`);
}

/**
 * Retorna el resultado cacheado si existe, o null si no hay cache.
 */
function getCached(content) {
  ensureCacheDir();
  const hash = hashContent(content);
  const file = cachePath(hash);

  if (!fs.existsSync(file)) return null;

  try {
    const raw = fs.readFileSync(file, 'utf-8');
    const entry = JSON.parse(raw);
    return { hash, ...entry };
  } catch {
    return null;
  }
}

/**
 * Guarda el resultado del análisis en cache.
 */
function setCached(content, normalizedResult) {
  ensureCacheDir();
  const hash = hashContent(content);
  const entry = {
    cached_at: new Date().toISOString(),
    normalized: normalizedResult
  };

  try {
    fs.writeFileSync(cachePath(hash), JSON.stringify(entry, null, 2), 'utf-8');
  } catch {
    // Cache write failure is non-fatal
  }

  return hash;
}

/**
 * Elimina todas las entradas del cache.
 */
function clearCache() {
  ensureCacheDir();
  const files = fs.readdirSync(CACHE_DIR).filter(f => f.endsWith('.json'));
  files.forEach(f => fs.unlinkSync(path.join(CACHE_DIR, f)));
  return files.length;
}

module.exports = { getCached, setCached, clearCache, hashContent };
