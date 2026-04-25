/**
 * ST-01.4 - Parser de especificaciones OpenAPI 3.x y Swagger 2.x
 * Soporta JSON nativo. Para YAML usa js-yaml si está disponible, con fallback a regex.
 */

// ─── YAML parser ─────────────────────────────────────────────────────────────

function parseYamlFallback(text) {
  // Parser YAML mínimo para estructuras planas y anidadas de OpenAPI.
  // Solo cubre los campos necesarios para el análisis STRIDE.
  const lines = text.split(/\r?\n/);
  const result = {};
  const stack = [{ obj: result, indent: -1 }];
  const arrayStack = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.trim() === '' || raw.trim().startsWith('#')) continue;

    const indent = raw.search(/\S/);
    const trimmed = raw.trim();

    // Array item
    if (trimmed.startsWith('- ')) {
      const value = trimmed.slice(2).trim();
      // Find the parent array
      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
      const top = stack[stack.length - 1].obj;
      const lastKey = stack[stack.length - 1].lastKey;
      if (lastKey && Array.isArray(top[lastKey])) {
        top[lastKey].push(value);
      }
      continue;
    }

    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;

    const key = trimmed.slice(0, colonIdx).trim();
    const valuePart = trimmed.slice(colonIdx + 1).trim();

    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const top = stack[stack.length - 1].obj;

    if (valuePart === '' || valuePart === '{}' || valuePart === '[]') {
      top[key] = valuePart === '[]' ? [] : {};
      stack.push({ obj: top[key], indent, lastKey: key });
    } else if (valuePart.startsWith('[')) {
      top[key] = valuePart.replace(/[\[\]]/g, '').split(',').map(v => v.trim()).filter(Boolean);
    } else {
      top[key] = valuePart.replace(/^['"]|['"]$/g, '');
      stack[stack.length - 1].lastKey = key;
    }
  }

  return result;
}

function parseContent(text, ext) {
  if (ext === '.json') {
    return JSON.parse(text);
  }

  // Intentar js-yaml si está disponible
  try {
    const yaml = require('js-yaml');
    return yaml.load(text);
  } catch {
    // js-yaml no instalado — usar parser mínimo
  }

  return parseYamlFallback(text);
}

// ─── Extracción de OpenAPI ────────────────────────────────────────────────────

function isOpenAPISpec(parsed) {
  return (
    (parsed && parsed.openapi && String(parsed.openapi).startsWith('3')) ||
    (parsed && parsed.swagger && String(parsed.swagger).startsWith('2'))
  );
}

function extractSecuritySchemes(parsed) {
  const schemes = [];
  const components = parsed.components || parsed.securityDefinitions || {};
  const defs = components.securitySchemes || components;

  if (typeof defs === 'object') {
    for (const [name, def] of Object.entries(defs)) {
      if (def && def.type) {
        schemes.push(`${name} (${def.type}${def.scheme ? '/' + def.scheme : ''})`);
      }
    }
  }

  return schemes;
}

function extractEndpoints(parsed) {
  const paths = parsed.paths || {};
  const endpoints = [];
  const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];

  for (const [route, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;

    for (const method of HTTP_METHODS) {
      const op = pathItem[method];
      if (!op) continue;

      const security = op.security !== undefined ? op.security : parsed.security;
      const isPublic = !security || (Array.isArray(security) && security.length === 0);

      const params = (op.parameters || []).map(p => {
        const schema = p.schema || {};
        return `${p.name}(${p.in},${schema.type || 'any'})`;
      });

      endpoints.push({
        method: method.toUpperCase(),
        route,
        summary: op.summary || op.operationId || '',
        isPublic,
        params,
        tags: op.tags || []
      });
    }
  }

  return endpoints;
}

// ─── API pública ─────────────────────────────────────────────────────────────

/**
 * Parsea un archivo de especificación OpenAPI/Swagger.
 * @param {string} filePath
 * @param {string} content
 * @returns {{ isOpenAPI: boolean, version: string, title: string, endpoints: Array, securitySchemes: string[], summary: string }}
 */
function parseOpenAPIFile(filePath, content) {
  const ext = filePath.match(/\.[^.]+$/)?.[0]?.toLowerCase() || '.json';
  let parsed;

  try {
    parsed = parseContent(content, ext);
  } catch (err) {
    return { isOpenAPI: false, error: `Error parseando archivo: ${err.message}` };
  }

  if (!isOpenAPISpec(parsed)) {
    return { isOpenAPI: false };
  }

  const info = parsed.info || {};
  const version = parsed.openapi || parsed.swagger || 'unknown';
  const endpoints = extractEndpoints(parsed);
  const securitySchemes = extractSecuritySchemes(parsed);

  const publicEndpoints = endpoints.filter(e => e.isPublic);
  const protectedEndpoints = endpoints.filter(e => !e.isPublic);

  return {
    isOpenAPI: true,
    version,
    title: info.title || 'API sin titulo',
    description: info.description || '',
    endpoints,
    securitySchemes,
    publicCount: publicEndpoints.length,
    protectedCount: protectedEndpoints.length,
    totalCount: endpoints.length
  };
}

/**
 * Construye el contexto arquitectónico desde la especificación OpenAPI.
 */
function buildOpenAPIContext(filePath, result) {
  if (!result.isOpenAPI) {
    return result.error || `El archivo ${filePath} no es una especificacion OpenAPI valida.`;
  }

  const lines = [
    `## Especificacion OpenAPI: ${result.title} (v${result.version})`,
    `Archivo: ${filePath}`,
    ''
  ];

  if (result.securitySchemes.length > 0) {
    lines.push(`Esquemas de seguridad: ${result.securitySchemes.join(', ')}`);
  } else {
    lines.push('Esquemas de seguridad: NINGUNO DEFINIDO (superficie de ataque alta)');
  }

  lines.push('');
  lines.push(`Total endpoints: ${result.totalCount} (${result.protectedCount} protegidos, ${result.publicCount} publicos)`);
  lines.push('');

  if (result.publicCount > 0) {
    lines.push('=== ENDPOINTS PUBLICOS (sin autenticacion) ===');
    result.endpoints
      .filter(e => e.isPublic)
      .slice(0, 20)
      .forEach(e => {
        const params = e.params.length > 0 ? ` | params: ${e.params.join(', ')}` : '';
        lines.push(`  ${e.method} ${e.route}${params}`);
      });
    lines.push('');
  }

  if (result.protectedCount > 0) {
    lines.push('=== ENDPOINTS PROTEGIDOS ===');
    result.endpoints
      .filter(e => !e.isPublic)
      .slice(0, 20)
      .forEach(e => {
        const params = e.params.length > 0 ? ` | params: ${e.params.join(', ')}` : '';
        lines.push(`  ${e.method} ${e.route}${params}`);
      });
  }

  return lines.join('\n');
}

module.exports = { parseOpenAPIFile, buildOpenAPIContext, isOpenAPISpec };
