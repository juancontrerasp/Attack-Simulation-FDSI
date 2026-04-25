/**
 * Proveedor Ollama - Local
 * Usa streaming para evitar timeouts HTTP en modelos lentos.
 * Elimina tokens <think>...</think> de modelos Qwen3 antes de retornar.
 */

async function analyze(systemPrompt, userMessage) {
  const baseUrl = (process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434').replace(/\/$/, '');
  const model = process.env.OLLAMA_MODEL || 'llama3.1:8b';
  const timeoutMs = Number(process.env.OLLAMA_TIMEOUT_MS || 300000);
  const numCtx = Number(process.env.OLLAMA_NUM_CTX || 8192);
  const numPredict = Number(process.env.OLLAMA_NUM_PREDICT || 2048);

  // Qwen3 usa razonamiento interno (<think>...</think>) que puede romper el JSON.
  // /no_think desactiva ese modo y reduce drasticamente el tiempo de respuesta.
  const isQwen3 = /qwen3/i.test(model);
  // Modelos locales tienen presupuesto de tokens limitado: pedir respuestas breves
  // garantiza que el JSON cierre correctamente antes del limite num_predict.
  const BREVITY_NOTE = '\n\nCRITICAL: You have a strict token budget. Be extremely concise: ' +
    'max 12 words per field, 1-2 threats per STRIDE category. ' +
    'The JSON MUST be syntactically complete and valid — close every bracket before running out of tokens.';
  let effectiveSystemPrompt = systemPrompt + BREVITY_NOTE;
  if (isQwen3) effectiveSystemPrompt += '\n/no_think';

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  process.stdout.write(`[Ollama] Analizando con ${model} (timeout ${timeoutMs / 1000}s)... `);

  let response;
  try {
    response = await fetch(`${baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        stream: true,
        messages: [
          { role: 'system', content: effectiveSystemPrompt },
          { role: 'user', content: userMessage }
        ],
        options: {
          temperature: 0.2,
          num_ctx: numCtx,
          num_predict: numPredict
        }
      }),
      signal: controller.signal
    });
  } catch (error) {
    process.stdout.write('\n');
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error(
        `Timeout al llamar Ollama despues de ${timeoutMs}ms. ` +
        `Aumenta OLLAMA_TIMEOUT_MS en .env o reduce el tamano del repo.`
      );
    }
    throw new Error(`No se pudo conectar a Ollama en ${baseUrl}: ${error.message}`);
  }

  if (!response.ok) {
    process.stdout.write('\n');
    clearTimeout(timeoutId);
    const body = await response.text();
    throw new Error(`Ollama respondio ${response.status}: ${body}`);
  }

  let fullContent = '';
  let tokenCount = 0;

  try {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      let chunk;
      try {
        chunk = await reader.read();
      } catch (error) {
        if (error.name === 'AbortError') {
          throw new Error(
            `Timeout al llamar Ollama despues de ${timeoutMs}ms. ` +
            `Aumenta OLLAMA_TIMEOUT_MS en .env o reduce el tamano del repo.`
          );
        }
        throw error;
      }

      if (chunk.done) break;

      buffer += decoder.decode(chunk.value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        let parsed;
        try {
          parsed = JSON.parse(line);
        } catch {
          continue;
        }
        const token = parsed?.message?.content || '';
        fullContent += token;
        tokenCount += 1;
        if (tokenCount % 80 === 0) process.stdout.write('.');
        if (parsed.done) break;
      }
    }
  } catch (error) {
    process.stdout.write('\n');
    throw error;
  } finally {
    clearTimeout(timeoutId);
    process.stdout.write('\n');
  }

  if (!fullContent) {
    throw new Error('Respuesta invalida de Ollama: sin contenido en el stream');
  }

  // Eliminar bloques de razonamiento interno de Qwen3 (y cualquier modelo que los use)
  const cleaned = fullContent.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
  return cleaned || fullContent.trim();
}

module.exports = { analyze };
