/**
 * Proveedor Azure AI - Produccion
 */

const OpenAI = require('openai');

let client = null;

function getClient() {
  if (client) return client;

  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_API_KEY;
  const deployment = process.env.AZURE_DEPLOYMENT_NAME || 'gpt-4o-mini';

  if (!endpoint || !apiKey) {
    throw new Error(
      'Faltan variables de entorno: AZURE_OPENAI_ENDPOINT y AZURE_OPENAI_API_KEY.\n' +
      'Copia .env.example a .env y completa los valores.'
    );
  }

  client = new OpenAI({
    apiKey,
    baseURL: `${endpoint.replace(/\/$/, '')}/openai/deployments/${deployment}`,
    defaultQuery: { 'api-version': '2024-02-01' },
    defaultHeaders: { 'api-key': apiKey }
  });

  return client;
}

async function analyze(systemPrompt, userMessage) {
  const aiClient = getClient();
  const deployment = process.env.AZURE_DEPLOYMENT_NAME || 'gpt-4o-mini';

  const response = await aiClient.chat.completions.create({
    model: deployment,
    max_tokens: 1400,
    temperature: 0.2,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMessage }
    ]
  });

  return response.choices[0].message.content;
}

module.exports = { analyze };
