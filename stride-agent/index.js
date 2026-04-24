#!/usr/bin/env node
/**
 * US-01 - Agente STRIDE sobre codigo fuente, diagramas, imagenes y specs OpenAPI
 */

const fs = require('fs');
const path = require('path');

const { readRepository, buildArchitectureContext } = require('./repo-reader');
const { analyzeArchitecture, resolveProvider } = require('./ai-provider');
const { buildCorrectionMessage } = require('./analyzer/prompt');
const {
  validateAndNormalize,
  countThreats,
  validateOutputEnvelope
} = require('./analyzer/validator');
const { getCached, setCached } = require('./cache');

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  const raw = fs.readFileSync(filePath, 'utf-8');
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const sep = trimmed.indexOf('=');
    if (sep === -1) continue;
    const key = trimmed.slice(0, sep).trim();
    let value = trimmed.slice(sep + 1).trim().replace(/^['\"]|['\"]$/g, '');
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

function parseArgs(argv) {
  const parsed = {
    repo: null,
    file: null,
    output: 'threats-output.json',
    verbose: false,
    noCache: false,
    help: false
  };

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--repo':   parsed.repo    = argv[++i]; break;
      case '--file':   parsed.file    = argv[++i]; break;
      case '--output': parsed.output  = argv[++i]; break;
      case '--verbose': parsed.verbose = true; break;
      case '--no-cache': parsed.noCache = true; break;
      case '--help': case '-h': parsed.help = true; break;
    }
  }

  // Default: si no se pasa nada, analizar directorio actual como repo
  if (!parsed.repo && !parsed.file && !parsed.help) parsed.repo = '.';

  return parsed;
}

function printHelp() {
  console.log([
    'Uso:',
    '  node analyze.js --repo <ruta>          Analiza un repositorio completo',
    '  node analyze.js --file <archivo>        Analiza un archivo individual',
    '',
    'Tipos de archivo soportados con --file:',
    '  .mmd .puml .plantuml                   Diagramas en texto (Mermaid, PlantUML)',
    '  .png .jpg .jpeg .webp                  Imagenes de arquitectura (requiere modelo vision)',
    '  .yaml .json (con campo openapi/swagger) Especificaciones OpenAPI/Swagger',
    '  Cualquier otro                          Codigo fuente',
    '',
    'Opciones:',
    '  --output <ruta>                        Archivo de salida (default: threats-output.json)',
    '  --verbose                              Muestra contexto enviado al agente',
    '  --no-cache                             Ignora cache y fuerza nueva llamada a la API',
    '  --help                                 Muestra esta ayuda'
  ].join('\n'));
}

// ─── Deteccion de tipo de archivo ────────────────────────────────────────────

function detectFileType(filePath, content) {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();

  if (['.mmd', '.puml', '.plantuml'].includes(ext)) return 'diagram';
  if (['.png', '.jpg', '.jpeg', '.webp', '.gif'].includes(ext)) return 'image';

  if (['.yaml', '.yml', '.json'].includes(ext)) {
    // Detectar OpenAPI por contenido
    try {
      const snippet = content.slice(0, 2000);
      if (/["']?openapi["']?\s*[:=]\s*["']?3\./i.test(snippet) ||
          /["']?swagger["']?\s*[:=]\s*["']?2\./i.test(snippet)) {
        return 'openapi';
      }
    } catch { /* */ }
  }

  if (ext === '.md') {
    // Markdown con bloques mermaid o C4
    if (/```mermaid/i.test(content) || /\bPerson\s*\(/i.test(content)) return 'diagram';
  }

  return 'code';
}

// ─── Construccion de contexto segun tipo ─────────────────────────────────────

async function buildContextFromFile(filePath, provider) {
  const absPath = path.resolve(filePath);
  if (!fs.existsSync(absPath)) throw new Error(`Archivo no encontrado: ${absPath}`);

  const ext = path.extname(absPath).toLowerCase();
  const isImage = ['.png', '.jpg', '.jpeg', '.webp', '.gif'].includes(ext);

  let content = '';
  if (!isImage) {
    content = fs.readFileSync(absPath, 'utf-8');
  }

  const fileType = isImage ? 'image' : detectFileType(absPath, content);

  if (fileType === 'diagram') {
    const { parseDiagramFile, buildDiagramContext } = require('./diagram-parser');
    const result = parseDiagramFile(absPath, content);
    return { context: buildDiagramContext(absPath, result), inputType: 'diagram', sourceName: path.basename(absPath) };
  }

  if (fileType === 'image') {
    const { processImageFile, buildImageContext } = require('./image-processor');
    const result = await processImageFile(absPath, provider);
    if (result.warning) console.warn(`[WARN] ${result.warning}`);
    return { context: buildImageContext(absPath, result), inputType: 'image', sourceName: path.basename(absPath) };
  }

  if (fileType === 'openapi') {
    const { parseOpenAPIFile, buildOpenAPIContext } = require('./openapi-parser');
    const result = parseOpenAPIFile(absPath, content);
    if (!result.isOpenAPI) throw new Error(`El archivo no es una especificacion OpenAPI valida: ${absPath}`);
    return { context: buildOpenAPIContext(absPath, result), inputType: 'openapi', sourceName: path.basename(absPath) };
  }

  // Codigo fuente generico
  const truncated = content.length > 10000 ? content.slice(0, 10000) + '\n... [truncado]' : content;
  const context = `## Archivo de codigo: ${path.basename(absPath)}\n\n\`\`\`${ext.slice(1)}\n${truncated}\n\`\`\``;
  return { context, inputType: 'code', sourceName: path.basename(absPath) };
}

// ─── Pipeline principal ───────────────────────────────────────────────────────

async function run() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { printHelp(); return; }

  const agentRoot = __dirname;
  const projectRoot = path.resolve(agentRoot, '..');
  loadEnvFile(path.join(projectRoot, '.env'));
  loadEnvFile(path.join(agentRoot, '.env'));

  const start = Date.now();
  const { devMode, provider } = resolveProvider();

  let contextToSend;
  let sourceName;
  let inputType;
  let repoMeta = null;

  if (args.file) {
    // ── Modo --file ────────────────────────────────────────────────────────
    const result = await buildContextFromFile(args.file, provider);
    contextToSend = result.context;
    sourceName = result.sourceName;
    inputType = result.inputType;

    if (args.verbose) {
      console.log(`Archivo: ${args.file}`);
      console.log(`Tipo detectado: ${inputType}`);
      console.log(`Contexto: ${contextToSend.length} chars`);
    }
  } else {
    // ── Modo --repo ────────────────────────────────────────────────────────
    const repoContext = readRepository(args.repo);
    const architectureContext = buildArchitectureContext(repoContext);

    repoMeta = {
      repoName: repoContext.repoName,
      repoPath: repoContext.repoPath,
      totalFiles: repoContext.totalFiles,
      totalChars: repoContext.totalChars
    };

    contextToSend = provider === 'ollama'
      ? architectureContext.slice(0, Number(process.env.OLLAMA_CONTEXT_CHARS || 6000))
      : architectureContext;

    sourceName = repoContext.repoName;
    inputType = 'repo';

    if (args.verbose) {
      console.log(`Repositorio: ${repoContext.repoName}`);
      console.log(`Archivos leidos: ${repoContext.totalFiles}`);
      console.log(`Contexto total: ${repoContext.totalChars} chars`);
      if (provider === 'ollama') {
        console.log(`Contexto enviado a Ollama: ${contextToSend.length} chars (limite OLLAMA_CONTEXT_CHARS)`);
      }
    }
  }

  // ── Cache ──────────────────────────────────────────────────────────────────
  let normalized = null;
  let cacheHit = false;
  let correctionRetries = 0;

  if (!args.noCache) {
    const cached = getCached(contextToSend);
    if (cached) {
      normalized = cached.normalized;
      cacheHit = true;
      console.log(`[cache] cache_hit: true (hash ${cached.hash})`);
    }
  }

  // ── Llamada al agente (si no hay cache) ───────────────────────────────────
  if (!normalized) {
    let rawResponse = '';
    let correctionMessage = null;
    // Ollama en CPU tarda 5+ min por llamada: correction retries son inviables.
    const maxCorrectionRetries = provider === 'ollama' ? 0 : 2;

    while (correctionRetries <= maxCorrectionRetries) {
      rawResponse = await analyzeArchitecture(contextToSend, { correctionMessage });

      try {
        normalized = validateAndNormalize(rawResponse);
        break;
      } catch (error) {
        if (correctionRetries === maxCorrectionRetries) throw error;
        correctionMessage = buildCorrectionMessage(rawResponse, error.message);
        correctionRetries += 1;
      }
    }

    if (!args.noCache) {
      setCached(contextToSend, normalized);
    }
  }

  // ── Salida ─────────────────────────────────────────────────────────────────
  const elapsedSeconds = Number(((Date.now() - start) / 1000).toFixed(2));
  const counts = countThreats(normalized);

  const output = {
    metadata: {
      generated_at: new Date().toISOString(),
      source_name: sourceName,
      input_type: inputType,
      provider,
      dev_mode: devMode,
      cache_hit: cacheHit,
      analysis_time_seconds: elapsedSeconds,
      correction_retries: correctionRetries,
      ...(repoMeta && {
        repo_name: repoMeta.repoName,
        repo_path: repoMeta.repoPath,
        total_files_analyzed: repoMeta.totalFiles,
        context_size_chars: repoMeta.totalChars
      })
    },
    summary: normalized.summary,
    inferred_components: normalized.inferred_components,
    counts,
    threats: normalized.threats
  };

  if (!validateOutputEnvelope(output)) {
    throw new Error('La salida final no cumple el envelope minimo esperado');
  }

  const outputPath = path.resolve(process.cwd(), args.output);
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2), 'utf-8');

  // Update threat registry and trend report
  try {
    const { updateFromAnalysis } = require('./threat-registry');
    const registry = updateFromAnalysis(output);
    const { addSnapshot } = require('./trend-reporter');
    addSnapshot(registry);
  } catch (err) {
    console.warn(`[registry] Warning: ${err.message}`);
  }

  console.log(`Reporte guardado en: ${outputPath}`);
  console.log(`Tiempo total: ${elapsedSeconds}s`);
  console.log(`Amenazas: ${counts.total} (Alta=${counts.Alta}, Media=${counts.Media}, Baja=${counts.Baja})`);
  if (cacheHit) console.log('cache_hit: true');
}

run().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
