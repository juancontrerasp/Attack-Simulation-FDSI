# ST-10.2 — Node 18 slim, npm ci determinista, usuario no-root
FROM node:18-slim
WORKDIR /app

# Instalar dependencias primero para aprovechar la caché de capas
COPY package.json package-lock.json ./
RUN npm ci --only=production

# Copiar todos los módulos del agente
COPY index.js analyze.js compare.js ./
COPY analyzer/ ./analyzer/
COPY ai-provider/ ./ai-provider/
COPY diagram-parser/ ./diagram-parser/
COPY openapi-parser/ ./openapi-parser/
COPY image-processor/ ./image-processor/
COPY cache/ ./cache/
COPY repo-reader/ ./repo-reader/
COPY stack-detector/ ./stack-detector/
COPY recommender/ ./recommender/
COPY threat-registry/ ./threat-registry/
COPY trend-reporter/ ./trend-reporter/
COPY feedback-reporter/ ./feedback-reporter/

# Dar ownership a node antes de cambiar de usuario
RUN mkdir -p /app/cache /app/output && chown -R node:node /app

# Usuario no-root: reduce superficie de ataque en producción
USER node

# /app/cache persiste el caché MD5 entre ejecuciones (reduce costo de Azure AI)
# /app/output almacena los reportes generados
VOLUME ["/app/cache", "/app/output"]

ENTRYPOINT ["node", "index.js"]
CMD []
