#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const registryPath = path.resolve(__dirname, '../security/threat-registry.json');

if (!fs.existsSync(registryPath)) {
  console.log('No threat registry found. Skipping baseline check.');
  process.exit(0);
}

const registry = JSON.parse(fs.readFileSync(registryPath, 'utf-8'));

const reopened  = registry.filter(e => e.status === 'reopened');
const open      = registry.filter(e => e.status === 'open');
const mitigated = registry.filter(e => e.status === 'mitigated');
const accepted  = registry.filter(e => e.status === 'accepted');

if (reopened.length > 0) {
  let commitHash = 'unknown';
  try {
    commitHash = execSync('git log --format=%H -1', { encoding: 'utf-8' }).trim();
  } catch { /* git may not be available in all CI environments */ }

  console.error('\nREGRESION DE SEGURIDAD DETECTADA\n');
  for (const t of reopened) {
    console.error(`  REGRESION: amenaza [${t.id}] fue mitigada y ha reaparecido. Commit que la reintrodujo: ${commitHash}.`);
    console.error(`    Categoria: ${t.category} | Componente: ${t.component}`);
    console.error(`    Descripcion: ${(t.description || '').slice(0, 120)}`);
    console.error();
  }
  console.error(`Total amenazas con regresion: ${reopened.length}`);
  process.exit(1);
}

const summary = `open=${open.length}, mitigated=${mitigated.length}, accepted=${accepted.length}, reopened=${reopened.length}`;

if (open.length > 0) {
  console.warn(`Advertencia: ${open.length} amenaza(s) en estado open sin resolver.`);
}

console.log(`Baseline check OK. Registry: ${registry.length} amenaza(s) (${summary})`);
process.exit(0);
