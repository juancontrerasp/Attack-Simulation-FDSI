#!/usr/bin/env node
/**
 * Comparador A/B de analisis STRIDE entre dos repositorios
 */

const fs = require('fs');
const path = require('path');

const { readRepository, buildArchitectureContext } = require('./repo-reader');
const { analyzeArchitecture, resolveProvider } = require('./ai-provider');
const { buildCorrectionMessage } = require('./analyzer/prompt');
const {
  STRIDE_CATEGORIES,
  validateAndNormalize,
  countThreats,
  validateOutputEnvelope
} = require('./analyzer/validator');

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  const raw = fs.readFileSync(filePath, 'utf-8');
  const lines = raw.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator === -1) continue;

    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();
    value = value.replace(/^['\"]|['\"]$/g, '');

    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function parseArgs(argv) {
  const parsed = {
    insecure: null,
    secure: null,
    output: 'threats-compare-output.json',
    verbose: false,
    assertInsecureGreater: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--insecure') {
      parsed.insecure = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === '--secure') {
      parsed.secure = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === '--output') {
      parsed.output = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === '--verbose') {
      parsed.verbose = true;
      continue;
    }
    if (arg === '--assert-insecure-greater') {
      parsed.assertInsecureGreater = true;
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }
  }

  return parsed;
}

function printHelp() {
  console.log('Uso: node compare.js --insecure <ruta-repo-inseguro> --secure <ruta-repo-seguro> [--output threats-compare-output.json] [--verbose] [--assert-insecure-greater]');
}

async function runAnalysisForRepo(repoPath, verbose = false) {
  const start = Date.now();
  const repoContext = readRepository(repoPath);
  const architectureContext = buildArchitectureContext(repoContext);

  if (verbose) {
    console.log(`\nAnalizando: ${repoContext.repoName}`);
    console.log(`Archivos leidos: ${repoContext.totalFiles}`);
    console.log(`Contexto total: ${repoContext.totalChars} chars`);
  }

  let normalized = null;
  let rawResponse = '';
  let correctionMessage = null;
  let correctionRetries = 0;
  const maxCorrectionRetries = 2;

  while (correctionRetries <= maxCorrectionRetries) {
    rawResponse = await analyzeArchitecture(architectureContext, { correctionMessage });

    try {
      normalized = validateAndNormalize(rawResponse);
      break;
    } catch (error) {
      if (correctionRetries === maxCorrectionRetries) {
        throw error;
      }
      correctionMessage = buildCorrectionMessage(rawResponse, error.message);
      correctionRetries += 1;
    }
  }

  const elapsedSeconds = Number(((Date.now() - start) / 1000).toFixed(2));
  const counts = countThreats(normalized);
  const { devMode, provider } = resolveProvider();

  const output = {
    metadata: {
      generated_at: new Date().toISOString(),
      repo_name: repoContext.repoName,
      repo_path: repoContext.repoPath,
      provider,
      dev_mode: devMode,
      total_files_analyzed: repoContext.totalFiles,
      context_size_chars: repoContext.totalChars,
      analysis_time_seconds: elapsedSeconds,
      correction_retries: correctionRetries
    },
    summary: normalized.summary,
    inferred_components: normalized.inferred_components,
    counts,
    threats: normalized.threats
  };

  if (!validateOutputEnvelope(output)) {
    throw new Error(`La salida para ${repoContext.repoName} no cumple el envelope minimo esperado`);
  }

  return output;
}

function buildComparison(insecureResult, secureResult) {
  const byCategoryDelta = {};
  for (const category of STRIDE_CATEGORIES) {
    const insecureCount = insecureResult.counts.byCategory[category] || 0;
    const secureCount = secureResult.counts.byCategory[category] || 0;
    byCategoryDelta[category] = {
      insecure: insecureCount,
      secure: secureCount,
      delta: insecureCount - secureCount
    };
  }

  const bySeverityDelta = {
    Alta: (insecureResult.counts.Alta || 0) - (secureResult.counts.Alta || 0),
    Media: (insecureResult.counts.Media || 0) - (secureResult.counts.Media || 0),
    Baja: (insecureResult.counts.Baja || 0) - (secureResult.counts.Baja || 0)
  };

  return {
    insecure_total: insecureResult.counts.total,
    secure_total: secureResult.counts.total,
    total_delta: insecureResult.counts.total - secureResult.counts.total,
    by_category: byCategoryDelta,
    by_severity_delta: bySeverityDelta,
    insecure_has_more_threats: insecureResult.counts.total > secureResult.counts.total
  };
}

async function run() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printHelp();
    return;
  }

  if (!args.insecure || !args.secure) {
    throw new Error('Debes indicar --insecure y --secure');
  }

  const agentRoot = __dirname;
  const projectRoot = path.resolve(agentRoot, '..');
  loadEnvFile(path.join(projectRoot, '.env'));
  loadEnvFile(path.join(agentRoot, '.env'));

  const overallStart = Date.now();
  const insecureResult = await runAnalysisForRepo(args.insecure, args.verbose);
  const secureResult = await runAnalysisForRepo(args.secure, args.verbose);
  const comparison = buildComparison(insecureResult, secureResult);
  const elapsedSeconds = Number(((Date.now() - overallStart) / 1000).toFixed(2));

  const finalOutput = {
    metadata: {
      generated_at: new Date().toISOString(),
      provider: insecureResult.metadata.provider,
      dev_mode: insecureResult.metadata.dev_mode,
      total_compare_time_seconds: elapsedSeconds
    },
    insecure_repo: insecureResult,
    secure_repo: secureResult,
    comparison
  };

  const outputPath = path.resolve(process.cwd(), args.output);
  fs.writeFileSync(outputPath, JSON.stringify(finalOutput, null, 2), 'utf-8');

  console.log(`Reporte A/B guardado en: ${outputPath}`);
  console.log(`Amenazas inseguro: ${comparison.insecure_total}`);
  console.log(`Amenazas seguro: ${comparison.secure_total}`);
  console.log(`Delta total (inseguro - seguro): ${comparison.total_delta}`);
  console.log(`Tiempo total comparacion: ${elapsedSeconds}s`);

  if (args.assertInsecureGreater && !comparison.insecure_has_more_threats) {
    throw new Error(
      'Criterio de aceptacion incumplido: el repositorio inseguro no tiene mas amenazas que el seguro'
    );
  }
}

run().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
