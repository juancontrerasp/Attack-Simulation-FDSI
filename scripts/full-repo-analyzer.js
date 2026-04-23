const fs = require('fs');
const path = require('path');

// Colors
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
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

// --- 2. Scan Repository ---
function getSourceFiles(dir, files_ = []) {
    const files = fs.readdirSync(dir);
    for (const i in files) {
        const name = dir + '/' + files[i];
        if (fs.statSync(name).isDirectory()) {
            if (files[i] === 'node_modules' || files[i] === '.git' || files[i] === 'out') continue;
            getSourceFiles(name, files_);
        } else {
            if (name.match(/\.(java|js|ts|py)$/) && fs.statSync(name).size <= 51200) {
                files_.push(name);
            }
        }
    }
    return files_;
}

// --- 3. Prompt ---
function buildPrompt(filesData) {
    let context = "";
    filesData.forEach(f => {
        context += `\n--- FILE: ${f.name} ---\n${f.content}\n`;
    });

    return `You are a high-end Security Research AI specialized in the STRIDE threat modeling framework.
Analyze the provided repository source code and identify security vulnerabilities according to the STRIDE framework.

IMPORTANT RULES:
1. Be objective and professional.
2. Every threat MUST have: category, component, description, evidence, severity (Alta, Media, Baja), mitigation.
3. Categorize threats into: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
4. IMPORTANT: Using environment variables (e.g., process.env or similar) for secrets is considered a secure practice in this context; do not flag it as a vulnerability.
5. MANDATORY: Only report vulnerabilities that pose a direct and significant security risk.

JSON STRUCTURE:
{
  "summary": "Full repository security analysis summary.",
  "threats": {
    "Spoofing": [], "Tampering": [], "Repudiation": [], "InformationDisclosure": [], "DenialOfService": [], "ElevationOfPrivilege": []
  }
}

SOURCE CODE:
${context}`;
}

// --- Main ---
async function run() {
    console.log(BOLD + "🔍 Escaneando repositorio..." + NC);
    const files = getSourceFiles(path.resolve(__dirname, '..'));
    const filesData = files.map(f => ({
        name: path.relative(path.resolve(__dirname, '..'), f),
        content: fs.readFileSync(f, 'utf-8')
    }));

    if (!API_KEY || !ENDPOINT || !DEPLOYMENT) {
        console.log(YELLOW + "❌ Error: Configuración de IA incompleta en .env." + NC);
        process.exit(1);
    }

    console.log(BOLD + `🤖 Analizando ${filesData.length} archivos con Azure OpenAI...` + NC);

    const url = `${ENDPOINT.replace(/\/$/, '')}/openai/deployments/${DEPLOYMENT}/chat/completions?api-version=2024-02-15-preview`;

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'api-key': API_KEY },
            body: JSON.stringify({
                messages: [
                    { role: "system", content: "You are a security analysis agent that outputs only JSON." },
                    { role: "user", content: buildPrompt(filesData) }
                ],
                temperature: 0,
                response_format: { type: "json_object" }
            })
        });

        if (!response.ok) throw new Error(`API Error: ${response.status}`);

        const result = await response.json();
        const content = result.choices[0].message.content;
        
        fs.writeFileSync('threats-output.json', content);
        console.log(GREEN + "✅ Análisis completado. Resultados guardados en threats-output.json" + NC);

    } catch (error) {
        console.error(RED + "❌ Error en análisis: " + error.message + NC);
        process.exit(1);
    }
}

run();
