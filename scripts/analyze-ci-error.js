const fs = require('fs');
const path = require('path');

const LOG_FILE = 'extracted-errors.txt';
const OUTPUT_FILE = 'ai-analysis.md';

// --- 1. Environment Handling ---
// In GitHub Actions, these come from process.env (passed from secrets)
const API_KEY = process.env.AZURE_OPENAI_API_KEY;
const ENDPOINT = process.env.AZURE_OPENAI_ENDPOINT;
const DEPLOYMENT = process.env.AZURE_DEPLOYMENT_NAME;

// --- 2. Prompt ---
function buildPrompt(log) {
    return `You are a high-end CI/CD Expert and Security Researcher.
Analyze the provided GitHub Actions error log and explain what went wrong.

STRUCTURE YOUR RESPONSE IN MARKDOWN AS FOLLOWS:

### 🤖 Análisis del Agente STRIDE
<!-- STRIDE-ERROR-ANALYZER -->

#### ❌ Error Detectado
[Brief description of the specific error found in the log]

#### 🔍 Causa Probable
[Technical explanation of why this happened]

#### 🛠️ Pasos de Corrección
1. [Numbered list of concrete steps to fix the issue]
2. [If applicable, include the specific command to run locally]

---
*Este análisis fue generado automáticamente por el Agente STRIDE.*

LOG CONTENT:
${log}`;
}

// --- Main ---
async function run() {
    console.log("🤖 Iniciando análisis de IA para el error de CI...");

    if (!fs.existsSync(LOG_FILE)) {
        console.error(`❌ Error: ${LOG_FILE} no encontrado.`);
        process.exit(1);
    }

    const logContent = fs.readFileSync(LOG_FILE, 'utf-8');
    if (!logContent.trim()) {
        console.log("⚠️  Log vacío. Nada que analizar.");
        process.exit(0);
    }

    if (!API_KEY || !ENDPOINT || !DEPLOYMENT) {
        console.error("❌ Error: Faltan credenciales de Azure OpenAI en el entorno.");
        process.exit(1);
    }

    const url = `${ENDPOINT.replace(/\/$/, '')}/openai/deployments/${DEPLOYMENT}/chat/completions?api-version=2024-02-15-preview`;

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'api-key': API_KEY },
            body: JSON.stringify({
                messages: [
                    { role: "system", content: "You are a CI/CD troubleshooting expert. Respond in Spanish." },
                    { role: "user", content: buildPrompt(logContent) }
                ],
                temperature: 0
            })
        });

        if (!response.ok) throw new Error(`API Error: ${response.status}`);

        const result = await response.json();
        const analysis = result.choices[0].message.content;
        
        fs.writeFileSync(OUTPUT_FILE, analysis);
        console.log(`✅ Análisis generado exitosamente en ${OUTPUT_FILE}`);

    } catch (error) {
        console.error(`❌ Error en el análisis de IA: ${error.message}`);
        process.exit(1);
    }
}

run();
