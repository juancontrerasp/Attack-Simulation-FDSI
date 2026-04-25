/**
 * ST-14.1 - Validador y normalizador de respuesta de feedback de seguridad
 */

const STRIDE_CATEGORIES = [
  'Spoofing', 'Tampering', 'Repudiation',
  'InformationDisclosure', 'DenialOfService', 'ElevationOfPrivilege'
];

const VALID_SEVERITIES = new Set(['Alta', 'Media', 'Baja']);
const VALID_ARTEFACT_TYPES = new Set(['diagram', 'code', 'openapi', 'image', 'repo']);

function parseResponse(rawText) {
  try { return JSON.parse(rawText); } catch { /* continue */ }

  const blockMatch = rawText.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (blockMatch) {
    try { return JSON.parse(blockMatch[1].trim()); } catch { /* continue */ }
  }

  const start = rawText.indexOf('{');
  const end = rawText.lastIndexOf('}');
  if (start !== -1 && end !== -1 && end > start) {
    try { return JSON.parse(rawText.slice(start, end + 1)); } catch { /* continue */ }
  }

  throw new Error('No se pudo parsear la respuesta de feedback como JSON válido');
}

function normalizeWhatsGood(items) {
  if (!Array.isArray(items)) return [];
  return items.map(item => ({
    aspect: String(item.aspect || 'Control identificado'),
    why_it_matters: String(item.why_it_matters || ''),
    stride_impact: STRIDE_CATEGORIES.includes(item.stride_impact)
      ? item.stride_impact
      : 'InformationDisclosure'
  }));
}

function normalizeWhatToFix(items) {
  if (!Array.isArray(items)) return [];
  return items.map(item => ({
    issue: String(item.issue || 'Problema de seguridad'),
    stride_category: STRIDE_CATEGORIES.includes(item.stride_category)
      ? item.stride_category
      : 'InformationDisclosure',
    severity: VALID_SEVERITIES.has(item.severity) ? item.severity : 'Media',
    how_to_fix: String(item.how_to_fix || 'Revisar implementación según OWASP')
  }));
}

function normalizeWhatToAdd(items) {
  if (!Array.isArray(items)) return [];
  return items.map(item => ({
    missing_control: String(item.missing_control || 'Control de seguridad'),
    why_needed: String(item.why_needed || ''),
    stride_category: STRIDE_CATEGORIES.includes(item.stride_category)
      ? item.stride_category
      : 'InformationDisclosure',
    implementation_hint: String(item.implementation_hint || '')
  }));
}

function validateAndNormalizeFeedback(rawText) {
  const parsed = parseResponse(rawText);

  const rawScore = parsed.overall_security_score;
  const score = typeof rawScore === 'number'
    ? Math.max(0, Math.min(100, Math.round(rawScore)))
    : 0;

  const artefactType = VALID_ARTEFACT_TYPES.has(parsed.artefact_type)
    ? parsed.artefact_type
    : 'code';

  return {
    artefact_type: artefactType,
    system_summary: String(parsed.system_summary || 'Análisis de seguridad completado.'),
    whats_good:  normalizeWhatsGood(parsed.whats_good),
    what_to_fix: normalizeWhatToFix(parsed.what_to_fix),
    what_to_add: normalizeWhatToAdd(parsed.what_to_add),
    overall_security_score: score
  };
}

function validateFeedbackEnvelope(output) {
  if (!output || typeof output !== 'object') return false;
  if (!output.metadata || typeof output.metadata !== 'object') return false;
  if (!Array.isArray(output.whats_good)) return false;
  if (!Array.isArray(output.what_to_fix)) return false;
  if (!Array.isArray(output.what_to_add)) return false;
  if (typeof output.overall_security_score !== 'number') return false;
  return true;
}

module.exports = {
  validateAndNormalizeFeedback,
  validateFeedbackEnvelope
};
