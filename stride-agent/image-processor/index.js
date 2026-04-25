/**
 * ST-01.3 - Procesador de imagenes de arquitectura
 * Convierte imágenes a base64 y las envía al modelo de vision para descripcion arquitectonica.
 * Soporta Azure GPT-4o y Ollama (modelos vision como llava o llama3.2-vision).
 */

const fs = require('fs');
const path = require('path');

const MAX_IMAGE_BYTES = 4 * 1024 * 1024; // 4MB

const MIME_TYPES = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif'
};

const VISION_PROMPT = `Analyze this architecture diagram and provide a structured description for security threat modeling.
Identify and describe:
1. System components and their roles (servers, databases, APIs, clients, services)
2. Data flows and communication paths between components
3. Trust boundaries and network zones (internet-facing, internal, DMZ)
4. Authentication/authorization mechanisms visible
5. Any missing security controls or exposed interfaces

Be specific about component names and data flow directions.`;

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return MIME_TYPES[ext] || 'image/png';
}

async function analyzeWithAzure(base64Image, mimeType) {
  const { OpenAI } = require('openai');

  const visionDeployment = process.env.AZURE_VISION_DEPLOYMENT_NAME || process.env.AZURE_DEPLOYMENT_NAME || 'gpt-4o';
  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_API_KEY;

  if (!endpoint || !apiKey || apiKey === 'tu-api-key-aqui') {
    throw new Error('Azure no configurado. Define AZURE_OPENAI_ENDPOINT y AZURE_OPENAI_API_KEY en .env');
  }

  const client = new OpenAI({
    apiKey,
    baseURL: `${endpoint.replace(/\/$/, '')}/openai/deployments/${visionDeployment}`,
    defaultQuery: { 'api-version': '2024-02-15-preview' },
    defaultHeaders: { 'api-key': apiKey }
  });

  const response = await client.chat.completions.create({
    model: visionDeployment,
    max_tokens: 1000,
    messages: [
      {
        role: 'user',
        content: [
          { type: 'text', text: VISION_PROMPT },
          { type: 'image_url', image_url: { url: `data:${mimeType};base64,${base64Image}` } }
        ]
      }
    ]
  });

  return response.choices[0]?.message?.content || '';
}

async function analyzeWithOllama(base64Image, mimeType) {
  const baseUrl = (process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434').replace(/\/$/, '');
  const model = process.env.OLLAMA_VISION_MODEL || process.env.OLLAMA_MODEL || 'llava:7b';
  const timeoutMs = Number(process.env.OLLAMA_TIMEOUT_MS || 300000);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  console.log(`[image-processor] Analizando imagen con ${model}...`);

  let response;
  try {
    response = await fetch(`${baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        stream: false,
        messages: [
          {
            role: 'user',
            content: VISION_PROMPT,
            images: [base64Image]
          }
        ],
        options: { temperature: 0.1, num_predict: 800 }
      }),
      signal: controller.signal
    });
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') throw new Error(`Timeout procesando imagen con Ollama`);
    throw new Error(`No se pudo conectar a Ollama: ${error.message}`);
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    const body = await response.text();
    // Si el modelo no soporta vision, retornar advertencia
    if (response.status === 400 && body.includes('does not support')) {
      return null;
    }
    throw new Error(`Ollama respondio ${response.status}: ${body}`);
  }

  const data = await response.json();
  return data?.message?.content || null;
}

/**
 * Procesa una imagen de arquitectura y retorna una descripcion textual.
 * @param {string} filePath  Ruta a la imagen
 * @param {string} provider  'azure' | 'ollama' | 'mock'
 * @returns {{ description: string, warning?: string }}
 */
async function processImageFile(filePath, provider) {
  const stats = fs.statSync(filePath);
  if (stats.size > MAX_IMAGE_BYTES) {
    throw new Error(`Imagen demasiado grande: ${(stats.size / 1024 / 1024).toFixed(1)}MB (maximo 4MB)`);
  }

  const mimeType = getMimeType(filePath);
  const base64Image = fs.readFileSync(filePath).toString('base64');

  if (provider === 'mock') {
    return {
      description: [
        'Diagrama de arquitectura con los siguientes componentes identificados:',
        '- Cliente web (browser) conectado a API Gateway',
        '- API Gateway que enruta peticiones a microservicios internos',
        '- Servicio de autenticacion con base de datos de usuarios',
        '- Servicio principal de aplicacion con base de datos relacional',
        '- Sin evidencia visible de WAF o TLS entre componentes internos',
        '',
        'Flujos de datos observados:',
        'Cliente → API Gateway (HTTPS), API Gateway → Auth Service (HTTP interno)',
        'API Gateway → App Service (HTTP interno), App Service → Database (TCP)'
      ].join('\n')
    };
  }

  if (provider === 'azure') {
    const description = await analyzeWithAzure(base64Image, mimeType);
    return { description };
  }

  if (provider === 'ollama') {
    const description = await analyzeWithOllama(base64Image, mimeType);
    if (!description) {
      return {
        description: `Imagen de arquitectura: ${path.basename(filePath)} (${mimeType}, ${(stats.size / 1024).toFixed(0)}KB).\nEl modelo Ollama configurado no soporta vision. Configura OLLAMA_VISION_MODEL=llava:7b o usa Azure para analisis de imagenes.`,
        warning: 'El modelo Ollama no soporta vision. Instala llava: ollama pull llava:7b'
      };
    }
    return { description };
  }

  throw new Error(`Proveedor no soportado para imagenes: ${provider}`);
}

/**
 * Construye el contexto arquitectonico desde la descripcion de la imagen.
 */
function buildImageContext(filePath, result) {
  const lines = [
    `## Imagen de arquitectura: ${path.basename(filePath)}`,
    ''
  ];

  if (result.warning) {
    lines.push(`[ADVERTENCIA] ${result.warning}`);
    lines.push('');
  }

  lines.push('### Descripcion del diagrama');
  lines.push(result.description);

  return lines.join('\n');
}

module.exports = { processImageFile, buildImageContext };
