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
  SYSTEM_PROMPT_FEEDBACK,
  buildFeedbackUserMessage,
  buildFeedbackCorrectionMessage
} = require('./analyzer/prompt-feedback');
const {
  validateAndNormalize,
  countThreats,
  validateOutputEnvelope
} = require('./analyzer/validator');
const {
  validateAndNormalizeFeedback,
  validateFeedbackEnvelope
} = require('./analyzer/validator-feedback');
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
    output: null,
    mode: 'stride',
    interactive: false,
    verbose: false,
    noCache: false,
    help: false
  };

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--repo':        parsed.repo        = argv[++i]; break;
      case '--file':        parsed.file        = argv[++i]; break;
      case '--output':      parsed.output      = argv[++i]; break;
      case '--mode':        parsed.mode        = argv[++i]; break;
      case '--interactive': parsed.interactive = true; break;
      case '--verbose':     parsed.verbose     = true; break;
      case '--no-cache':    parsed.noCache     = true; break;
      case '--help': case '-h': parsed.help    = true; break;
    }
  }

  // Default: si no se pasa nada, analizar directorio actual como repo
  if (!parsed.repo && !parsed.file && !parsed.help) parsed.repo = '.';

  // Default output differs by mode
  if (!parsed.output) {
    parsed.output = parsed.mode === 'feedback' ? 'design-feedback.json' : 'threats-output.json';
  }

  return parsed;
}

function printHelp() {
  console.log([
    'Uso:',
    '  node index.js --repo <ruta>            Analiza un repositorio completo',
    '  node index.js --file <archivo>         Analiza un archivo individual',
    '',
    'Modos:',
    '  --mode stride   (default) Detecta amenazas STRIDE → threats-output.json',
    '  --mode feedback           Retroalimentación de diseño seguro → design-feedback.json',
    '',
    'Tipos de archivo soportados con --file:',
    '  .mmd .puml .plantuml                   Diagramas en texto (Mermaid, PlantUML)',
    '  .png .jpg .jpeg .webp                  Imagenes de arquitectura (requiere modelo vision)',
    '  .yaml .json (con campo openapi/swagger) Especificaciones OpenAPI/Swagger',
    '  Cualquier otro                          Codigo fuente',
    '',
    'Opciones:',
    '  --output <ruta>                        Archivo de salida (default segun modo)',
    '  --interactive                          Q&A interactiva tras el análisis (solo --mode feedback)',
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

async function buildInputContext(args, provider) {
  let contextToSend, sourceName, inputType, repoMeta = null;

  if (args.file) {
    const result = await buildContextFromFile(args.file, provider);
    contextToSend = result.context;
    sourceName    = result.sourceName;
    inputType     = result.inputType;

    if (args.verbose) {
      console.log(`Archivo: ${args.file}`);
      console.log(`Tipo detectado: ${inputType}`);
      console.log(`Contexto: ${contextToSend.length} chars`);
    }
  } else {
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
    inputType  = 'repo';

    if (args.verbose) {
      console.log(`Repositorio: ${repoContext.repoName}`);
      console.log(`Archivos leidos: ${repoContext.totalFiles}`);
      console.log(`Contexto total: ${repoContext.totalChars} chars`);
    }
  }

  return { contextToSend, sourceName, inputType, repoMeta };
}

// ─── STRIDE pipeline ──────────────────────────────────────────────────────────

async function runStride(args, contextToSend, sourceName, inputType, repoMeta, provider, devMode) {
  const start = Date.now();
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

  if (!normalized) {
    let rawResponse = '';
    let correctionMessage = null;
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

    if (!args.noCache) setCached(contextToSend, normalized);
  }

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

// ─── Feedback pipeline ────────────────────────────────────────────────────────

const SCORE_COLOR = (s) => s >= 70 ? '\x1b[32m' : s >= 40 ? '\x1b[33m' : '\x1b[31m';
const SCORE_EMOJI = (s) => s >= 70 ? '🟢' : s >= 40 ? '🟡' : '🔴';
const RESET = '\x1b[0m';

function printFeedbackSummary(fb) {
  const s = fb.overall_security_score;
  const col = SCORE_COLOR(s);
  console.log('');
  console.log(`${col}Security Score: ${SCORE_EMOJI(s)} ${s}/100${RESET}`);
  console.log(`Sistema: ${fb.system_summary}`);
  console.log('');

  if (fb.whats_good.length) {
    console.log('\x1b[32m✔ Lo que está bien:\x1b[0m');
    fb.whats_good.forEach(g => console.log(`  • [${g.stride_impact}] ${g.aspect}`));
    console.log('');
  }

  if (fb.what_to_fix.length) {
    console.log('\x1b[31m✖ Lo que hay que corregir:\x1b[0m');
    fb.what_to_fix.forEach(f => console.log(`  • [${f.severity}][${f.stride_category}] ${f.issue}`));
    console.log('');
  }

  if (fb.what_to_add.length) {
    console.log('\x1b[34m+ Lo que hay que agregar:\x1b[0m');
    fb.what_to_add.forEach(a => console.log(`  • [${a.stride_category}] ${a.missing_control}`));
    console.log('');
  }
}

async function runInteractiveQA(contextToSend, inputType, provider) {
  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(resolve => rl.question(q, resolve));

  console.log('\x1b[36mModo interactivo: escribe preguntas de seguimiento (o "salir" para terminar).\x1b[0m');
  const history = [];

  while (true) {
    const question = await ask('\nPregunta> ');
    if (!question.trim() || question.trim().toLowerCase() === 'salir') break;

    history.push(question.trim());
    const historyContext = history.length > 1
      ? `Preguntas anteriores:\n${history.slice(0, -1).map((q, i) => `Q${i + 1}: ${q}`).join('\n')}\n\nPregunta actual:`
      : '';

    const userMsg = [
      historyContext,
      question.trim(),
      '\n\nContexto del artefacto analizado:',
      contextToSend.slice(0, 3000)
    ].filter(Boolean).join('\n');

    try {
      process.stdout.write('\x1b[33mAnalizando...\x1b[0m\n');
      const raw = await analyzeArchitecture(userMsg, {
        systemPrompt: SYSTEM_PROMPT_FEEDBACK,
        buildMessage: (ctx) => ctx,
        feedbackMode: true
      });
      // For Q&A we return the raw response as plain text (not JSON)
      // Try JSON first; fall back to raw
      try {
        const parsed = JSON.parse(raw);
        if (parsed.system_summary) {
          console.log(`\nRespuesta: ${parsed.system_summary}`);
        } else {
          console.log(`\nRespuesta: ${raw}`);
        }
      } catch {
        console.log(`\nRespuesta: ${raw}`);
      }
    } catch (err) {
      console.error(`\x1b[31mError en Q&A: ${err.message}\x1b[0m`);
    }
  }

  rl.close();
  console.log('\x1b[36mSesión interactiva finalizada.\x1b[0m');
}

async function runFeedback(args, contextToSend, sourceName, inputType, repoMeta, provider, devMode) {
  const start = Date.now();
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

  if (!normalized) {
    let rawResponse = '';
    let correctionMessage = null;
    const maxCorrectionRetries = provider === 'ollama' ? 0 : 2;

    while (correctionRetries <= maxCorrectionRetries) {
      rawResponse = await analyzeArchitecture(contextToSend, {
        systemPrompt: SYSTEM_PROMPT_FEEDBACK,
        buildMessage: (ctx) => buildFeedbackUserMessage(ctx, inputType),
        correctionMessage,
        feedbackMode: true
      });

      try {
        normalized = validateAndNormalizeFeedback(rawResponse);
        break;
      } catch (error) {
        if (correctionRetries === maxCorrectionRetries) throw error;
        correctionMessage = buildFeedbackCorrectionMessage(rawResponse, error.message);
        correctionRetries += 1;
      }
    }

    if (!args.noCache) setCached(contextToSend, normalized);
  }

  const elapsedSeconds = Number(((Date.now() - start) / 1000).toFixed(2));

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
    artefact_type: normalized.artefact_type,
    system_summary: normalized.system_summary,
    whats_good: normalized.whats_good,
    what_to_fix: normalized.what_to_fix,
    what_to_add: normalized.what_to_add,
    overall_security_score: normalized.overall_security_score
  };

  if (!validateFeedbackEnvelope(output)) {
    throw new Error('La salida de feedback no cumple el envelope mínimo esperado');
  }

  const outputPath = path.resolve(process.cwd(), args.output);
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2), 'utf-8');

  printFeedbackSummary(normalized);
  console.log(`Reporte guardado en: ${outputPath}`);
  console.log(`Tiempo total: ${elapsedSeconds}s`);

  // Generate HTML report
  try {
    const { generateFeedbackHTML } = require('./feedback-reporter');
    const htmlPath = outputPath.replace(/\.json$/, '.html');
    generateFeedbackHTML(output, htmlPath);
    console.log(`Reporte HTML: ${htmlPath}`);
  } catch (err) {
    console.warn(`[feedback-reporter] Warning: ${err.message}`);
  }

  // Save score for pre-commit hook
  try {
    const hookScorePath = path.resolve(process.cwd(), '.git/hooks/last-feedback-score');
    fs.writeFileSync(hookScorePath, String(normalized.overall_security_score), 'utf-8');
  } catch { /* .git may not exist in all contexts */ }

  if (args.interactive) {
    await runInteractiveQA(contextToSend, inputType, provider);
  }
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { printHelp(); return; }

  if (args.mode !== 'stride' && args.mode !== 'feedback') {
    console.error(`Modo desconocido: ${args.mode}. Usa --mode stride|feedback`);
    process.exit(1);
  }

  const agentRoot = __dirname;
  const projectRoot = path.resolve(agentRoot, '..');
  loadEnvFile(path.join(projectRoot, '.env'));
  loadEnvFile(path.join(agentRoot, '.env'));

  const { devMode, provider } = resolveProvider();
  const { contextToSend, sourceName, inputType, repoMeta } = await buildInputContext(args, provider);

  if (args.mode === 'feedback') {
    await runFeedback(args, contextToSend, sourceName, inputType, repoMeta, provider, devMode);
  } else {
    await runStride(args, contextToSend, sourceName, inputType, repoMeta, provider, devMode);
  }
}

run().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
