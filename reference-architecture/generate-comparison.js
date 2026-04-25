#!/usr/bin/env node
'use strict';

const fs = require('fs');

const [,, insecurePath, securePath, outputPath] = process.argv;

if (!insecurePath || !securePath || !outputPath) {
  console.error('Usage: node generate-comparison.js <insecure.json> <secure.json> <output.json>');
  process.exit(1);
}

const insecure = JSON.parse(fs.readFileSync(insecurePath, 'utf-8'));
const secure   = JSON.parse(fs.readFileSync(securePath,   'utf-8'));

const insecureCount = insecure.counts.total;
const secureCount   = secure.counts.total;
const ratio = secureCount > 0
  ? parseFloat((insecureCount / secureCount).toFixed(2))
  : insecureCount;

const CATEGORIES = [
  'Spoofing', 'Tampering', 'Repudiation',
  'InformationDisclosure', 'DenialOfService', 'ElevationOfPrivilege'
];

const deltaByCategory = {};
for (const cat of CATEGORIES) {
  const i = (insecure.threats[cat] || []).length;
  const s = (secure.threats[cat]   || []).length;
  deltaByCategory[cat] = { insecure: i, secure: s, delta: i - s };
}

const result = {
  generated_at: new Date().toISOString(),
  insecure_source: insecure.metadata?.source_name || 'unknown',
  secure_source:   secure.metadata?.source_name   || 'unknown',
  insecure_threat_count: insecureCount,
  secure_threat_count:   secureCount,
  differentiation_ratio: ratio,
  assessment: ratio >= 2.0
    ? `PASS: ratio ${ratio} >= 2.0 — agent correctly differentiates secure vs insecure`
    : `FAIL: ratio ${ratio} < 2.0 — insufficient differentiation`,
  insecure_by_severity: insecure.counts,
  secure_by_severity:   secure.counts,
  threats_by_category: {
    insecure: insecure.counts.byCategory || {},
    secure:   secure.counts.byCategory   || {}
  },
  delta_by_category: deltaByCategory
};

fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf-8');
console.log(`\ncomparison-result.json generated`);
console.log(`  Insecure threats: ${insecureCount}`);
console.log(`  Secure threats:   ${secureCount}`);
console.log(`  Ratio:            ${ratio}:1`);
console.log(`  Assessment:       ${result.assessment}`);

if (ratio < 2.0) {
  process.exit(1);
}
