/**
 * Capa de abstraccion de proveedores de IA
 */

const { SYSTEM_PROMPT, buildUserMessage } = require('../analyzer/prompt');

async function withRetry(fn, maxRetries = 2) {
  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      // No reintentar si fue un timeout genuino — un reintento con el mismo timeout tampoco pasara
      const isTimeout = /timeout/i.test(error.message);
      if (attempt === maxRetries || isTimeout) throw error;
      const waitMs = Math.pow(2, attempt) * 1000;
      console.log(`[retry] Intento ${attempt + 1} fallido. Reintentando en ${waitMs}ms...`);
      await new Promise(resolve => setTimeout(resolve, waitMs));
    }
  }
  throw new Error('Fallo inesperado en withRetry');
}

function resolveProvider() {
  const devMode = process.env.DEV_MODE === 'true';
  const provider = devMode ? 'mock' : 'azure';
  return { devMode, provider };
}

async function analyzeArchitecture(architectureContext, options = {}) {
  const { correctionMessage, systemPrompt: customSystemPrompt, buildMessage: customBuilder, feedbackMode } = options;
  const { devMode, provider } = resolveProvider();

  if (provider === 'mock' || devMode) {
    const mock = require('./mock');
    return feedbackMode ? mock.analyzeFeedback() : mock.analyze();
  }

  const activeSystemPrompt = customSystemPrompt || SYSTEM_PROMPT;
  const buildMsg = customBuilder || buildUserMessage;
  const userMessage = correctionMessage || buildMsg(architectureContext);

  const azure = require('./azure');
  return withRetry(() => azure.analyze(activeSystemPrompt, userMessage));
}

module.exports = {
  analyzeArchitecture,
  resolveProvider
};
