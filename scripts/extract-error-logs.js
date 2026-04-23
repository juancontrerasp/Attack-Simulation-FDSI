const fs = require('fs');
const path = require('path');

const LOGS_DIR = process.argv[2] || './logs';
const OUTPUT_FILE = 'extracted-errors.txt';

const KEYWORDS = [
    'ERROR', 
    'FAILED', 
    'Exception', 
    'error:', 
    'Build failed', 
    'Process completed with exit code'
];

function extractFromDir(dir) {
    let result = "";
    const files = fs.readdirSync(dir);
    
    // Sort files to process steps in order
    files.sort().forEach(file => {
        const filePath = path.join(dir, file);
        if (fs.statSync(filePath).isDirectory()) {
            result += extractFromDir(filePath);
        } else if (file.endsWith('.txt')) {
            const content = fs.readFileSync(filePath, 'utf-8');
            const lines = content.split('\n');
            
            let foundError = false;
            let stepErrors = [];
            
            lines.forEach((line, index) => {
                const hasKeyword = KEYWORDS.some(k => line.includes(k));
                if (hasKeyword) {
                    foundError = true;
                    // Grab context around the error (3 lines before, 2 lines after)
                    const start = Math.max(0, index - 3);
                    const end = Math.min(lines.length - 1, index + 2);
                    stepErrors.push(`...`);
                    stepErrors.push(...lines.slice(start, end + 1));
                }
            });

            if (foundError) {
                result += `\n--- STEP LOG: ${file} ---\n`;
                // If the file is small, just take the last 100 lines too
                if (lines.length < 100) {
                    result += lines.join('\n');
                } else {
                    result += stepErrors.join('\n');
                    result += `\n... (last 50 lines) ...\n`;
                    result += lines.slice(-50).join('\n');
                }
            }
        }
    });
    
    return result;
}

function run() {
    console.log(`🔍 Procesando logs en ${LOGS_DIR}...`);
    if (!fs.existsSync(LOGS_DIR)) {
        console.error(`❌ Error: El directorio ${LOGS_DIR} no existe.`);
        process.exit(1);
    }

    let extracted = extractFromDir(LOGS_DIR);
    
    // Final truncation to ~4000 tokens (approx 16000 characters)
    if (extracted.length > 16000) {
        console.log("⚠️  Truncando logs para ajustarse al contexto de la IA...");
        extracted = "... [Truncated] ...\n" + extracted.slice(-16000);
    }

    fs.writeFileSync(OUTPUT_FILE, extracted);
    console.log(`✅ Logs extraídos en ${OUTPUT_FILE} (${extracted.length} caracteres).`);
}

run();
