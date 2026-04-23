const fs = require('fs');
const path = require('path');

// Colors
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const BOLD = '\x1b[1m';
const NC = '\x1b[0m';

// --- 1. Environment Handling ---
function loadEnv() {
    const envPath = path.resolve(__dirname, '../.env');
    if (!fs.existsSync(envPath)) return {};
    const content = fs.readFileSync(envPath, 'utf-8');
    const env = {};
    content.split('\n').forEach(line => {
        const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)\s*$/);
        if (match) {
            let value = match[2].trim();
            if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
                value = value.substring(1, value.length - 1);
            }
            env[match[1]] = value;
        }
    });
    return env;
}

const env = loadEnv();
const API_KEY = env.AZURE_OPENAI_API_KEY;
const ENDPOINT = env.AZURE_OPENAI_ENDPOINT;
const DEPLOYMENT = env.AZURE_DEPLOYMENT_NAME;

// --- 2. Read Diff ---
async function readStdin() {
    let data = '';
    for await (const chunk of process.stdin) {
        data += chunk;
    }
    return data;
}

// --- 3. Prompt ---
function buildPrompt(diff) {
    return `You are a high-end Security Research AI specialized in the STRIDE threat modeling framework.
Analyze the provided Git Diff and identify specifically NEW security vulnerabilities introduced by these changes.

IMPORTANT RULES:
1. Only report vulnerabilities introduced in the diff. Ignore existing issues not touched by the changes.
2. IMPORTANT: Ignore deleted lines (starting with '-'). Only analyze added or modified lines (starting with '+').
3. Be objective: Do not report standard best practices or minor improvements as "Alta" threats unless they pose a direct and significant security risk.
4. If no clear security vulnerabilities are introduced, return empty threat lists.
5. Every threat MUST have: category, component, description, evidence, severity (Alta, Media, Baja), mitigation.
6. MANDATORY: Hardcoded credentials (passwords, tokens, keys) MUST be categorized as Information Disclosure and severity Alta.
7. Using environment variables (e.g., System.getenv) for secrets is considered a secure practice in this context; do not flag it as a vulnerability.

JSON STRUCTURE:
{
  "summary": "...",
  "threats": {
    "Spoofing": [], "Tampering": [], "Repudiation": [], "InformationDisclosure": [], "DenialOfService": [], "ElevationOfPrivilege": []
  }
}

DIFF:
${diff}`;
}

// --- 4. Formatting ---
function formatReport(input) {
    const threats = [];
    for (const cat in input.threats) {
        if (Array.isArray(input.threats[cat])) {
            input.threats[cat].forEach(t => threats.push({ ...t, category: t.category || cat }));
        }
    }

    if (threats.length === 0) {
        console.log(GREEN + '✓ No se detectaron vulnerabilidades nuevas.' + NC);
        console.log(GREEN + '✓ Análisis STRIDE completado exitosamente.' + NC);
        return 0;
    }

    const highThreats = threats.filter(t => t.severity === 'Alta');
    const otherThreats = threats.filter(t => t.severity !== 'Alta');

    if (highThreats.length > 0) {
        console.log(RED + BOLD + 'PUSH BLOQUEADO: Se detectaron vulnerabilidades de severidad Alta.' + NC + '\n');
        highThreats.forEach(t => {
            console.log(RED + BOLD + '--- AMENAZA DETECTADA (CRÍTICA) ---' + NC);
            console.log(RED + 'Categoría:  ' + NC + (t.category || 'N/A'));
            console.log(RED + 'Componente: ' + NC + (t.component || 'N/A'));
            console.log(RED + 'Descripción:' + NC + (t.description || 'N/A'));
            console.log(RED + 'Evidencia:  ' + YELLOW + (t.evidence || 'N/A') + NC);
            console.log(RED + 'Mitigación: ' + GREEN + (t.mitigation || 'N/A') + NC);
            console.log(RED + '-----------------------------------' + NC + '\n');
        });
        return 1;
    } else {
        console.log(YELLOW + BOLD + 'AVISO: Se detectaron vulnerabilidades de severidad Media o Baja.' + NC + '\n');
        otherThreats.forEach(t => {
            console.log(YELLOW + BOLD + '--- ADVERTENCIA DE SEGURIDAD ---' + NC);
            console.log(YELLOW + 'Categoría:  ' + NC + (t.category || 'N/A'));
            console.log(YELLOW + 'Componente: ' + NC + (t.component || 'N/A'));
            console.log(YELLOW + 'Descripción:' + NC + (t.description || 'N/A'));
            console.log(YELLOW + 'Severidad:  ' + NC + (t.severity || 'N/A'));
            console.log(YELLOW + '--------------------------------' + NC + '\n');
        });
        return 0;
    }
}

// --- Main ---
async function run() {
    const diff = await readStdin();
    if (!diff.trim()) return;

    if (!API_KEY || !ENDPOINT || !DEPLOYMENT) {
        console.log(YELLOW + "Advertencia: Configuración de IA incompleta en .env. Omitiendo análisis." + NC);
        process.exit(0);
    }

    const url = `${ENDPOINT.replace(/\/$/, '')}/openai/deployments/${DEPLOYMENT}/chat/completions?api-version=2024-02-15-preview`;

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'api-key': API_KEY },
            body: JSON.stringify({
                messages: [
                    { role: "system", content: "You are a security analysis agent that outputs only JSON." },
                    { role: "user", content: buildPrompt(diff) }
                ],
                temperature: 0,
                response_format: { type: "json_object" }
            })
        });

        if (!response.ok) throw new Error(`API Error: ${response.status}`);

        const result = await response.json();
        const content = JSON.parse(result.choices[0].message.content);
        
        const exitCode = formatReport(content);
        process.exit(exitCode);

    } catch (error) {
        console.error(YELLOW + "Error en análisis: " + error.message + NC);
        process.exit(0);
    }
}

run();
