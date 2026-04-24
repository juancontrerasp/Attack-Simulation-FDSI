/**
 * ST-11.2 - Motor de recomendaciones de mitigación con fallback a catálogo
 */

const fs = require('fs');
const path = require('path');

const CATALOG_PATH = path.resolve(__dirname, '../../security/controls-catalog.json');
const STRIDE_CATEGORIES = [
  'Spoofing', 'Tampering', 'Repudiation',
  'InformationDisclosure', 'DenialOfService', 'ElevationOfPrivilege'
];

// ── Catalog loader ──────────────────────────────────────────────────────────

function loadCatalog() {
  const raw = fs.readFileSync(CATALOG_PATH, 'utf-8');
  return JSON.parse(raw).controls;
}

// ── Catalog matching ────────────────────────────────────────────────────────

const KEYWORD_PATTERNS = [
  { pattern: /sql.inject|sqli|prepared.stat|query.concat/i, id: 'CTRL-T-01' },
  { pattern: /xss|cross.site.script|html.inject|script.inject/i, id: 'CTRL-T-02' },
  { pattern: /path.travers|directory.travers|file.inclus/i, id: 'CTRL-T-03' },
  { pattern: /jwt|alg.none|algorithm.none|token.forge/i, id: 'CTRL-S-01' },
  { pattern: /session.fix/i, id: 'CTRL-S-02' },
  { pattern: /weak.auth|no.auth|missing.auth(?!z)|credential/i, id: 'CTRL-S-03' },
  { pattern: /audit.log|no.log|missing.log|traza/i, id: 'CTRL-R-01' },
  { pattern: /log.inject|log.tamper|log.forge/i, id: 'CTRL-R-02' },
  { pattern: /non.repudi|digital.sign|event.sign/i, id: 'CTRL-R-03' },
  { pattern: /missing.header|security.header|x.frame|hsts|csp/i, id: 'CTRL-I-01' },
  { pattern: /error.leak|stack.trace|verbose.error|exception.detail/i, id: 'CTRL-I-02' },
  { pattern: /sensitive.data|password.in.response|secret.expos/i, id: 'CTRL-I-03' },
  { pattern: /brute.force|rate.limit|too.many.attempt/i, id: 'CTRL-D-01' },
  { pattern: /resource.exhaust|dos|denial.of.service|large.payload/i, id: 'CTRL-D-02' },
  { pattern: /connection.exhaust|pool.exhaust/i, id: 'CTRL-D-03' },
  { pattern: /weak.password|password.policy|simple.password/i, id: 'CTRL-E-01' },
  { pattern: /missing.authori|no.role.check|access.control|privilege.check/i, id: 'CTRL-E-02' },
  { pattern: /privilege.escal|idor|insecure.direct|ownership/i, id: 'CTRL-E-03' }
];

function findBestControl(threat, catalog) {
  const text = `${threat.component || ''} ${threat.description || ''} ${threat.evidence || ''}`;

  for (const { pattern, id } of KEYWORD_PATTERNS) {
    if (pattern.test(text)) {
      const ctrl = catalog.find(c => c.id === id);
      if (ctrl) return ctrl;
    }
  }

  // Fallback: first control matching the STRIDE category
  return catalog.find(c => c.stride_category === threat.category) || null;
}

function enrichFromCatalog(threat, catalog, language) {
  const ctrl = findBestControl(threat, catalog);
  if (!ctrl) {
    return {
      ...threat,
      control_standard: 'OWASP Top 10 2021',
      reference_id: 'CWE-1000',
      implementation_hint: 'Consultar OWASP Top 10 y aplicar controles de defensa en profundidad.',
      effort_estimate: 'Medium',
      source: 'catalog'
    };
  }

  const lang = language || 'Java';
  const hints = ctrl.implementation_hints;
  const hint = hints[lang] || hints['Java'] || hints['Node.js'] || hints['Python'] || '';

  return {
    ...threat,
    control_standard: ctrl.control_standard,
    reference_id: ctrl.reference_id,
    implementation_hint: hint,
    effort_estimate: ctrl.effort_estimate,
    source: 'catalog'
  };
}

// ── AI prompt builder ───────────────────────────────────────────────────────

function buildRecommendationSystemPrompt(stackProfile) {
  const lang = stackProfile.language || 'Java';
  const fw = stackProfile.framework ? ` con ${stackProfile.framework}` : '';
  const db = stackProfile.database ? `, base de datos ${stackProfile.database}` : '';
  const auth = stackProfile.auth ? `, autenticación ${stackProfile.auth}` : '';

  return `Eres un experto en seguridad de software especializado en mitigación de amenazas STRIDE.
Stack tecnológico detectado: ${lang}${fw}${db}${auth}.

Para cada amenaza recibida, proporciona:
1. control_standard: estándar aplicable exacto (ej: "OWASP A03:2021 - Injection")
2. reference_id: ID CWE o identificador OWASP exacto (ej: "CWE-89")
3. implementation_hint: código REAL en ${lang}${fw}, no pseudocódigo abstracto
4. effort_estimate: Low (config change) | Medium (refactoring) | High (architecture redesign)

Reglas obligatorias:
- Las recomendaciones DEBEN ser específicas para ${lang}${fw}, no genéricas.
- implementation_hint DEBE contener código fuente real o configuración real.
- Responde SOLO con JSON válido, sin markdown ni texto adicional.
- Mantén todos los campos originales de cada amenaza y agrega los 4 nuevos.

Formato requerido:
{
  "threats": {
    "Spoofing": [ { ...camposOriginales, "control_standard": "", "reference_id": "", "implementation_hint": "", "effort_estimate": "", "source": "ai" } ],
    "Tampering": [],
    "Repudiation": [],
    "InformationDisclosure": [],
    "DenialOfService": [],
    "ElevationOfPrivilege": []
  }
}`;
}

function buildRecommendationUserMessage(threats) {
  return `Enriquece estas amenazas STRIDE con controles de mitigación específicos:\n\n${JSON.stringify({ threats }, null, 2)}`;
}

// ── AI call ─────────────────────────────────────────────────────────────────

async function callAzureForRecommendations(systemPrompt, userMessage) {
  const { OpenAI } = require('openai');

  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_API_KEY;
  const deployment = process.env.AZURE_DEPLOYMENT_NAME || 'gpt-4o-mini';

  if (!endpoint || !apiKey) {
    throw new Error('Missing AZURE_OPENAI_ENDPOINT or AZURE_OPENAI_API_KEY');
  }

  const client = new OpenAI({
    apiKey,
    baseURL: `${endpoint.replace(/\/$/, '')}/openai/deployments/${deployment}`,
    defaultQuery: { 'api-version': '2024-02-01' },
    defaultHeaders: { 'api-key': apiKey }
  });

  const response = await client.chat.completions.create({
    model: deployment,
    max_tokens: 4000,
    temperature: 0.1,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMessage }
    ]
  });

  return response.choices[0].message.content;
}

async function callOllamaForRecommendations(systemPrompt, userMessage) {
  const model = process.env.OLLAMA_MODEL || 'llama3';
  const baseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';

  const response = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      stream: false,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userMessage }
      ]
    })
  });

  if (!response.ok) throw new Error(`Ollama error: ${response.status}`);
  const data = await response.json();
  return data.message?.content || '';
}

function parseRecommendationResponse(raw) {
  // Attempt 1: direct JSON
  try { return JSON.parse(raw); } catch { /* continue */ }

  // Attempt 2: ```json block
  const blockMatch = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (blockMatch) {
    try { return JSON.parse(blockMatch[1].trim()); } catch { /* continue */ }
  }

  // Attempt 3: extract {...}
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start !== -1 && end > start) {
    try { return JSON.parse(raw.slice(start, end + 1)); } catch { /* continue */ }
  }

  throw new Error('Could not parse AI recommendation response as JSON');
}

function validateEnrichedThreat(threat) {
  return (
    typeof threat.control_standard === 'string' && threat.control_standard.length > 0 &&
    typeof threat.reference_id === 'string' && threat.reference_id.length > 0 &&
    typeof threat.implementation_hint === 'string' && threat.implementation_hint.length > 0 &&
    ['Low', 'Medium', 'High'].includes(threat.effort_estimate)
  );
}

function mergeEnrichedThreats(originalThreats, aiThreats) {
  const merged = {};
  for (const category of STRIDE_CATEGORIES) {
    const origList = originalThreats[category] || [];
    const aiList = (aiThreats[category] || []);

    merged[category] = origList.map((orig, idx) => {
      const ai = aiList[idx];
      if (ai && validateEnrichedThreat(ai)) {
        return {
          ...orig,
          control_standard: ai.control_standard,
          reference_id: ai.reference_id,
          implementation_hint: ai.implementation_hint,
          effort_estimate: ai.effort_estimate,
          source: 'ai'
        };
      }
      return orig; // will be filled by catalog fallback later
    });
  }
  return merged;
}

// ── Main export ─────────────────────────────────────────────────────────────

async function enrichThreats(threats, stackProfile, options = {}) {
  const { verbose = false } = options;
  const devMode = process.env.DEV_MODE === 'true';
  const provider = devMode ? 'mock' : (process.env.AI_PROVIDER || 'mock');
  const catalog = loadCatalog();
  const language = stackProfile.language || 'Java';

  let aiSuccess = false;
  let enrichedThreats = threats;

  if (provider !== 'mock' && !devMode) {
    try {
      const systemPrompt = buildRecommendationSystemPrompt(stackProfile);
      const userMessage = buildRecommendationUserMessage(threats);

      if (verbose) console.log('[recommender] Llamando a IA para recomendaciones...');

      let rawResponse;
      if (provider === 'azure') {
        rawResponse = await callAzureForRecommendations(systemPrompt, userMessage);
      } else if (provider === 'ollama') {
        rawResponse = await callOllamaForRecommendations(systemPrompt, userMessage);
      }

      const parsed = parseRecommendationResponse(rawResponse);
      if (parsed && parsed.threats) {
        enrichedThreats = mergeEnrichedThreats(threats, parsed.threats);
        aiSuccess = true;
        if (verbose) console.log('[recommender] Recomendaciones de IA aplicadas correctamente.');
      }
    } catch (err) {
      if (verbose) console.warn(`[recommender] Llamada AI falló: ${err.message}. Usando catálogo offline.`);
    }
  } else if (verbose) {
    console.log('[recommender] DEV_MODE o provider=mock: usando catálogo offline directamente.');
  }

  // Apply catalog fallback for any threat missing the 4 new fields
  const finalThreats = {};
  for (const category of STRIDE_CATEGORIES) {
    finalThreats[category] = (enrichedThreats[category] || []).map(threat => {
      if (validateEnrichedThreat(threat)) return threat;
      return enrichFromCatalog(threat, catalog, language);
    });
  }

  return { enrichedThreats: finalThreats, aiSuccess };
}

module.exports = { enrichThreats };
