#!/usr/bin/env node
/**
 * ST-11.4 - Comando standalone: enriquece un threats-output.json existente
 *
 * Uso:
 *   node recommend.js --threats threats-output.json
 *   node recommend.js --threats threats-output.json --output threats-enriched.json
 *   node recommend.js --threats threats-output.json --in-place
 *   node recommend.js --threats threats-output.json --repo ../my-repo
 */

const fs = require('fs');
const path = require('path');

// Load .env from parent directory
function loadEnv(startDir) {
  const envPath = path.resolve(startDir, '../.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf-8').split('\n');
  for (const line of lines) {
    const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)\s*$/);
    if (!match) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!process.env[match[1]]) process.env[match[1]] = value;
  }
}

loadEnv(__dirname);

const { detectStack } = require('./stack-detector/index');
const { enrichThreats } = require('./recommender/index');

const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED    = '\x1b[31m';
const BOLD   = '\x1b[1m';
const NC     = '\x1b[0m';

function parseArgs(argv) {
  const args = { threats: null, output: null, inPlace: false, repo: null, verbose: false };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--threats':   args.threats  = argv[++i]; break;
      case '--output':    args.output   = argv[++i]; break;
      case '--in-place':  args.inPlace  = true; break;
      case '--repo':      args.repo     = argv[++i]; break;
      case '--verbose':   args.verbose  = true; break;
      default:
        console.error(`${RED}Opción desconocida: ${argv[i]}${NC}`);
        process.exit(1);
    }
  }
  return args;
}

function resolveOutputPath(args, inputPath) {
  if (args.inPlace) return path.resolve(inputPath);
  if (args.output) return path.resolve(args.output);

  const dir  = path.dirname(path.resolve(inputPath));
  const base = path.basename(inputPath, '.json');
  return path.join(dir, `${base}-enriched.json`);
}

async function run() {
  const args = parseArgs(process.argv);

  if (!args.threats) {
    console.error(`${RED}Error: --threats <archivo> es requerido.${NC}`);
    console.error(`Uso: node recommend.js --threats threats-output.json`);
    process.exit(1);
  }

  const inputPath = path.resolve(args.threats);
  if (!fs.existsSync(inputPath)) {
    console.error(`${RED}Error: No se encontró el archivo: ${inputPath}${NC}`);
    process.exit(1);
  }

  console.log(`${BOLD}[recommend] Cargando amenazas desde: ${inputPath}${NC}`);
  let report;
  try {
    report = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));
  } catch (err) {
    console.error(`${RED}Error: No se pudo parsear ${inputPath}: ${err.message}${NC}`);
    process.exit(1);
  }

  if (!report.threats) {
    console.error(`${RED}Error: El archivo no tiene campo 'threats'.${NC}`);
    process.exit(1);
  }

  // Detect stack from repo
  const repoPath = args.repo
    ? path.resolve(args.repo)
    : path.resolve(report.metadata?.repo_path || path.join(inputPath, '../../'));

  console.log(`[recommend] Detectando stack tecnológico en: ${repoPath}`);
  const stackProfile = detectStack(repoPath);
  console.log(`[recommend] Stack detectado: ${JSON.stringify(stackProfile)}`);

  const startTime = Date.now();

  const { enrichedThreats, aiSuccess } = await enrichThreats(
    report.threats,
    stackProfile,
    { verbose: args.verbose }
  );

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
  const source = aiSuccess ? 'ai' : 'catalog';

  console.log(`${GREEN}[recommend] Enriquecimiento completado en ${elapsed}s (source: ${source})${NC}`);

  // Build enriched report preserving all original fields
  const enrichedReport = {
    ...report,
    threats: enrichedThreats,
    recommendation_metadata: {
      enriched_at: new Date().toISOString(),
      source,
      stack_profile: stackProfile,
      enrichment_time_seconds: parseFloat(elapsed)
    }
  };

  const outputPath = resolveOutputPath(args, inputPath);
  fs.writeFileSync(outputPath, JSON.stringify(enrichedReport, null, 2), 'utf-8');
  console.log(`${GREEN}${BOLD}[recommend] Reporte enriquecido guardado en: ${outputPath}${NC}`);

  if (!aiSuccess) {
    console.log(`${YELLOW}[recommend] Nota: recomendaciones generadas desde catálogo offline (source: catalog).${NC}`);
  }
}

run().catch(err => {
  console.error(`${RED}Error fatal: ${err.message}${NC}`);
  process.exit(1);
});
