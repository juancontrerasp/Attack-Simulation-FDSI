/**
 * ST-01.3 - Validador y normalizador de respuesta STRIDE
 */

const STRIDE_CATEGORIES = [
  'Spoofing',
  'Tampering',
  'Repudiation',
  'InformationDisclosure',
  'DenialOfService',
  'ElevationOfPrivilege'
];

const VALID_SEVERITIES = new Set(['Alta', 'Media', 'Baja']);

function parseAgentResponse(rawText) {
  // Intento 1: JSON directo
  try { return JSON.parse(rawText); } catch { /* continue */ }

  // Intento 2: bloque ```json ... ```
  const blockMatch = rawText.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (blockMatch) {
    try { return JSON.parse(blockMatch[1].trim()); } catch { /* continue */ }
  }

  // Intento 3: extraer desde { hasta el ultimo }
  const start = rawText.indexOf('{');
  const end = rawText.lastIndexOf('}');
  if (start !== -1 && end !== -1 && end > start) {
    try { return JSON.parse(rawText.slice(start, end + 1)); } catch { /* continue */ }
  }

  // Intento 4: JSON truncado — el modelo se quedo sin tokens antes de cerrar.
  // Intentar reparar agregando cierres de brackets faltantes.
  if (start !== -1) {
    const partial = rawText.slice(start);
    const repaired = repairTruncatedJSON(partial);
    if (repaired) {
      try { return JSON.parse(repaired); } catch { /* continue */ }
    }
  }

  throw new Error('No se pudo parsear la respuesta del agente como JSON valido');
}

function repairTruncatedJSON(partial) {
  // Mantener un stack del tipo de contenedor abierto para cerrarlos en orden correcto
  const stack = [];
  let inString = false;
  let escape = false;
  let lastSafePos = 0;

  for (let i = 0; i < partial.length; i++) {
    const ch = partial[i];
    if (escape) { escape = false; continue; }
    if (ch === '\\' && inString) { escape = true; continue; }
    if (ch === '"') {
      inString = !inString;
      if (!inString) lastSafePos = i + 1;
      continue;
    }
    if (inString) continue;

    lastSafePos = i + 1;
    if (ch === '{') stack.push('}');
    else if (ch === '[') stack.push(']');
    else if (ch === '}' || ch === ']') stack.pop();
  }

  if (stack.length === 0) return null;

  // Si terminamos dentro de un string: truncar al ultimo punto seguro (fuera del string)
  let repaired = inString
    ? partial.slice(0, lastSafePos).trimEnd()
    : partial.trimEnd();

  // Limpiar trailing parcial: coma suelta o clave sin valor
  repaired = repaired.replace(/,\s*$/, '').replace(/:\s*$/, ': null');

  // Cerrar en orden inverso al de apertura
  repaired += stack.reverse().join('');

  return repaired;
}

function normalizeThreat(threat, category) {
  return {
    category,
    component: threat.component || 'Componente no identificado',
    description: threat.description || 'Sin descripcion',
    evidence: threat.evidence || 'Sin evidencia directa en el codigo',
    severity: VALID_SEVERITIES.has(threat.severity) ? threat.severity : 'Media',
    mitigation: threat.mitigation || 'Revisar implementacion segun buenas practicas OWASP'
  };
}

function validateAndNormalize(rawText) {
  const parsed = parseAgentResponse(rawText);
  const threats = parsed.threats || {};
  const normalizedThreats = {};

  for (const category of STRIDE_CATEGORIES) {
    const list = Array.isArray(threats[category]) ? threats[category] : [];
    normalizedThreats[category] = list.map(item => normalizeThreat(item, category));
  }

  return {
    summary: parsed.summary || 'Analisis STRIDE completado.',
    inferred_components: Array.isArray(parsed.inferred_components) ? parsed.inferred_components : [],
    threats: normalizedThreats
  };
}

function countThreats(normalizedResponse) {
  const counts = {
    total: 0,
    Alta: 0,
    Media: 0,
    Baja: 0,
    byCategory: {}
  };

  for (const category of STRIDE_CATEGORIES) {
    const items = normalizedResponse.threats[category] || [];
    counts.byCategory[category] = items.length;
    counts.total += items.length;

    for (const threat of items) {
      counts[threat.severity] = (counts[threat.severity] || 0) + 1;
    }
  }

  return counts;
}

function validateOutputEnvelope(output) {
  if (!output || typeof output !== 'object') return false;
  if (!output.metadata || typeof output.metadata !== 'object') return false;
  if (!output.threats || typeof output.threats !== 'object') return false;

  for (const category of STRIDE_CATEGORIES) {
    if (!Array.isArray(output.threats[category])) return false;
  }

  return true;
}

module.exports = {
  STRIDE_CATEGORIES,
  validateAndNormalize,
  countThreats,
  validateOutputEnvelope
};
