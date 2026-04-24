#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { loadRegistry, saveRegistry } = require('./stride-agent/threat-registry');

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m', gray: '\x1b[90m'
};

const STATUS_COLORS = {
  open: C.yellow, mitigated: C.green, accepted: C.blue, reopened: C.red
};

// Valid origin states for each action
const VALID_FROM = {
  accept: ['open', 'reopened'],
  reopen: ['accepted', 'mitigated'],
  close:  ['open', 'accepted', 'reopened']
};

const NEXT_STATUS = {
  accept: 'accepted',
  reopen: 'reopened',
  close:  'mitigated'
};

function col(status) {
  return (STATUS_COLORS[status] || '') + status + C.reset;
}

function parseArgs(argv) {
  const args = { action: null, threatId: null, by: null, reason: null, list: false, status: null, help: false };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--action':    args.action   = argv[++i]; break;
      case '--threat-id': args.threatId = argv[++i]; break;
      case '--by':        args.by       = argv[++i]; break;
      case '--reason':    args.reason   = argv[++i]; break;
      case '--list':      args.list     = true;      break;
      case '--status':    args.status   = argv[++i]; break;
      case '--help': case '-h': args.help = true;   break;
    }
  }
  return args;
}

function printHelp() {
  console.log([
    'Uso:',
    '  node threat-lifecycle.js --action <accion> --threat-id <id> --by <nombre> --reason <razon>',
    '  node threat-lifecycle.js --list [--status <estado>]',
    '',
    'Acciones:',
    '  accept   Acepta la amenaza (open|reopened → accepted)',
    '  reopen   Reabre la amenaza (accepted|mitigated → reopened)',
    '  close    Marca como mitigada manualmente (open|accepted|reopened → mitigated)',
    '',
    'Estados:',
    '  open       Detectada y sin accion',
    '  mitigated  Corregida y verificada',
    '  accepted   Aceptada con riesgo conocido',
    '  reopened   Estaba mitigada y reaparecio',
    '',
    'Opciones:',
    '  --threat-id <id>    ID de la amenaza (hash MD5 hexadecimal)',
    '  --by <nombre>       Responsable de la transicion',
    '  --reason <razon>    Justificacion (minimo 10 caracteres)',
    '  --list              Lista todas las amenazas del registry',
    '  --status <estado>   Filtra --list por estado',
    '  --help              Muestra esta ayuda'
  ].join('\n'));
}

function listThreats(args) {
  const registry = loadRegistry();
  const filtered = args.status ? registry.filter(e => e.status === args.status) : registry;

  if (filtered.length === 0) {
    console.log(C.gray + 'No hay amenazas' + (args.status ? ` en estado '${args.status}'` : '') + C.reset);
    return;
  }

  const header = `\n${C.bold}Amenazas en el registry${args.status ? ` [${args.status}]` : ''}:${C.reset} (${filtered.length})\n`;
  console.log(header);

  for (const e of filtered) {
    const c = STATUS_COLORS[e.status] || '';
    console.log(`  ${C.gray}${e.id}${C.reset}  [${c}${e.status.toUpperCase()}${C.reset}]  ${e.category} — ${C.bold}${e.component}${C.reset}  (${e.severity})`);
    console.log(`    ${C.gray}${(e.description || '').slice(0, 90)}${e.description && e.description.length > 90 ? '...' : ''}${C.reset}`);
    console.log(`    Creado: ${e.created_at.slice(0, 10)}  Actualizado: ${e.updated_at.slice(0, 10)}  Historial: ${e.history.length} entrada(s)`);
    console.log();
  }
}

function promptConfirm(question) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim().toLowerCase() !== 'n');
    });
  });
}

async function applyTransition(args) {
  if (!args.action) {
    console.error('Error: --action es requerido (accept, reopen, close)');
    process.exit(1);
  }
  if (!VALID_FROM[args.action]) {
    console.error(`Error: Accion desconocida '${args.action}'. Usa: accept, reopen, close`);
    process.exit(1);
  }
  if (!args.threatId) {
    console.error('Error: --threat-id es requerido');
    process.exit(1);
  }
  if (!args.by || !args.by.trim()) {
    console.error('Error: --by no puede estar vacio');
    process.exit(1);
  }
  if (!args.reason || args.reason.trim().length < 10) {
    console.error('Error: La razon debe tener al menos 10 caracteres');
    process.exit(1);
  }

  const registry = loadRegistry();
  const entry = registry.find(e => e.id === args.threatId);

  if (!entry) {
    console.error(`Error: Amenaza '${args.threatId}' no encontrada en el registry`);
    process.exit(1);
  }

  const validFrom = VALID_FROM[args.action];
  if (!validFrom.includes(entry.status)) {
    console.error(`Error: No se puede pasar de '${entry.status}' a '${NEXT_STATUS[args.action]}' con la accion '${args.action}'`);
    console.error(`La accion '${args.action}' solo es valida desde: ${validFrom.join(', ')}`);
    process.exit(1);
  }

  const nextStatus = NEXT_STATUS[args.action];

  console.log(`\n${C.bold}Amenaza encontrada:${C.reset}`);
  console.log(`  ID:          ${C.gray}${entry.id}${C.reset}`);
  console.log(`  Categoria:   ${entry.category}`);
  console.log(`  Componente:  ${C.bold}${entry.component}${C.reset}`);
  console.log(`  Severidad:   ${entry.severity}`);
  console.log(`  Estado:      ${col(entry.status)}`);
  console.log(`  Descripcion: ${(entry.description || '').slice(0, 100)}`);
  console.log();
  console.log(`  Transicion:  ${col(entry.status)} → ${col(nextStatus)}`);
  console.log(`  Responsable: ${args.by}`);
  console.log(`  Razon:       ${args.reason}`);
  console.log();

  const confirmed = await promptConfirm(`¿Confirmar transicion ${entry.status} → ${nextStatus}? [Y/n]: `);
  if (!confirmed) {
    console.log('Cancelado.');
    return;
  }

  const now = new Date().toISOString();
  entry.status = nextStatus;
  entry.updated_at = now;
  entry.history.push({
    status: nextStatus,
    changed_by: args.by.trim(),
    changed_at: now,
    reason: args.reason.trim()
  });

  saveRegistry(registry);
  console.log(`\n${C.green}[${now}] Transicion aplicada: [${entry.id}] → ${nextStatus}${C.reset}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || process.argv.length <= 2) {
    printHelp();
    return;
  }

  if (args.list) {
    listThreats(args);
    return;
  }

  await applyTransition(args);
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
