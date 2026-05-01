# Docker — Guía de uso del sistema STRIDE-Agent

## Arquitectura de contenedores

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Host                              │
│                                                                 │
│  ┌──────────────────────────┐   ┌──────────────────────────┐   │
│  │      stride-agent        │   │      attack-engine       │   │
│  │  (node:18-slim)          │   │  (openjdk:11-jre-slim)   │   │
│  │                          │   │                          │   │
│  │  index.js                │   │  AttackEngine.java       │   │
│  │  ├─ diagram-parser/      │   │  ├─ attacks/             │   │
│  │  ├─ openapi-parser/      │   │  ├─ config/              │   │
│  │  ├─ image-processor/     │   │  ├─ model/               │   │
│  │  ├─ ai-provider/         │   │  └─ util/                │   │
│  │  ├─ threat-registry/     │   │                          │   │
│  │  └─ trend-reporter/      │   │  Lee: /app/config/       │   │
│  │                          │   │  Escribe: /app/output/   │   │
│  │  Lee .env (credenciales) │   │                          │   │
│  └──────────┬───────────────┘   └──────────┬───────────────┘   │
│             │                              │                   │
│             │         stride-network       │                   │
│             └──────────────────────────────┘                   │
│                                                                 │
│  ┌───────────────────────┐  ┌───────────────────────────────┐  │
│  │   volumen stride-cache │  │    volumen stride-output      │  │
│  │   (caché MD5 agente)   │  │  (reportes JSON compartidos)  │  │
│  └───────────────────────┘  └───────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │   .env  (montado solo en stride-agent, nunca en imagen)   │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Inicio rápido

```bash
# 1. Clonar y configurar
git clone <repo-url>
cd Attack-Simulation-FDSI
cp .env.example .env
# Completar .env con credenciales reales (AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY)

# 2. Construir imágenes
docker build -t attack-engine ./attack-engine
docker build -t stride-agent ./stride-agent

# 3. Levantar el sistema
docker-compose up
```

## Tabla de comandos frecuentes

| # | Comando | Descripción |
|---|---------|-------------|
| 1 | `docker build -t attack-engine ./attack-engine` | Compila imagen Java con multi-stage build |
| 2 | `docker build -t stride-agent ./stride-agent` | Construye imagen Node.js con todos los parsers |
| 3 | `docker-compose up` | Levanta ambos servicios con credenciales del .env |
| 4 | `docker-compose up stride-agent` | Levanta solo el agente STRIDE (sin motor de ataques) |
| 5 | `docker-compose exec stride-agent node index.js --repo /app --output /app/output/threats.json` | Analiza el repositorio completo desde el contenedor |
| 6 | `docker-compose exec stride-agent node index.js --file /app/reference-architecture/secure-architecture.mmd --mode feedback --no-cache` | Analiza un diagrama Mermaid en modo feedback |
| 7 | `docker-compose exec stride-agent node index.js --file /app/reference-architecture/secure-api.yaml` | Analiza una especificación OpenAPI |
| 8 | `docker-compose down` | Detiene los servicios y preserva los volúmenes |
| 9 | `docker-compose -f docker-compose.yml -f docker-compose.ci.yml up --abort-on-container-exit` | Ejecuta el pipeline de CI con DEV_MODE=true |
| 10 | `docker images \| grep -E 'stride-agent\|attack-engine'` | Verifica tamaño de las imágenes construidas |

## Configuración de credenciales

Las credenciales de Azure **nunca** se hardcodean en los Dockerfiles. Se cargan exclusivamente desde el archivo `.env` a través del campo `env_file` en `docker-compose.yml`.

```bash
# Verificar que las credenciales no están expuestas en la imagen
docker inspect stride-agent  # no debe mostrar AZURE_OPENAI_API_KEY con valor real
```

Flujo de configuración:
1. `.env.example` vive en el repositorio (sin valores reales)
2. `.env` se crea localmente por cada desarrollador y está en `.gitignore`
3. `docker-compose.yml` referencia `env_file: .env`
4. El contenedor recibe las variables en tiempo de ejecución, no en la imagen

## Uso desde otro repositorio (inyección del agente)

Para usar el agente STRIDE sobre un proyecto externo que tiene diagramas y documentación:

```bash
# Opción A: montar el proyecto externo como volumen
docker run --rm \
  --env-file /ruta/a/.env \
  -v /ruta/a/mi-proyecto:/workspace:ro \
  -v stride-cache:/app/cache \
  stride-agent node index.js --file /workspace/docs/arquitectura.mmd --mode feedback --no-cache

# Opción B: copiar archivos de diseño al output del contenedor
docker-compose exec stride-agent node index.js \
  --file /app/reference-architecture/secure-architecture.mmd \
  --mode feedback \
  --no-cache \
  --output /app/output/feedback.json
```

Para integrar el hook pre-push en un repositorio externo:
```bash
# Copiar stride-agent/ y ejecutar:
bash scripts/install-hooks.sh
# El hook .git-hooks/pre-push se instala en .git/hooks/pre-push
# A partir de ese momento, cada git push analiza .mmd, .yaml (OpenAPI) y .md automáticamente
```

## Persistencia del caché

El volumen `stride-cache` es crítico para reducir el consumo de créditos de Azure. Sin él, cada ejecución regenera el análisis completo consumiendo tokens innecesariamente.

```bash
# La segunda ejecución sobre el mismo artefacto muestra cache_hit:true en logs
docker-compose exec stride-agent node index.js --file /app/reference-architecture/secure-architecture.mmd
# Logs: [cache] cache_hit: true (hash abc123...)

# Para forzar regeneración (por ejemplo al cambiar el artefacto):
docker-compose exec stride-agent node index.js --file /app/reference-architecture/secure-architecture.mmd --no-cache
```

## Troubleshooting — 5 problemas comunes

### 1. Modo feedback falla con error de caché

**Síntoma:**
```
Error: La salida de feedback no cumple el envelope mínimo esperado
Exit code: 1
```

**Causa:** Una ejecución previa en modo `stride` guardó su resultado en caché. Al correr `--mode feedback`, el agente recupera ese caché (de formato diferente) y falla la validación del envelope.

**Solución:** Usar siempre `--no-cache` en modo feedback:
```bash
docker-compose exec stride-agent node index.js \
  --file /app/reference-architecture/secure-architecture.mmd \
  --mode feedback \
  --no-cache
```

---

### 2. La imagen stride-agent supera los 300 MB

**Síntoma:** `docker images` muestra más de 300 MB para `stride-agent`.

**Causa:** Las dependencias de desarrollo fueron incluidas (`npm install` en lugar de `npm ci --only=production`), o `node_modules` se copió accidentalmente sin `.dockerignore`.

**Solución:** Verificar que `stride-agent/.dockerignore` contiene `node_modules` y que el Dockerfile usa `npm ci --only=production`. Reconstruir limpiamente:
```bash
docker rmi stride-agent
docker build --no-cache -t stride-agent ./stride-agent
docker images | grep stride-agent
```

---

### 3. Credenciales de Azure no llegan al contenedor

**Síntoma:**
```
Error: AZURE_OPENAI_ENDPOINT no configurado
```

**Causa:** El archivo `.env` no existe o tiene errores de formato (comillas extra, espacios alrededor del `=`).

**Solución:**
```bash
# Verificar que .env existe y tiene el formato correcto
cat .env | grep AZURE_OPENAI_ENDPOINT
# Debe ser: AZURE_OPENAI_ENDPOINT=https://...  (sin comillas, sin espacios)

# Verificar que las variables llegan al contenedor
docker-compose exec stride-agent env | grep AZURE
```

---

### 4. El volumen stride-cache no persiste entre reinicios

**Síntoma:** Cada `docker-compose up` regenera el análisis completo (los logs nunca muestran `cache_hit: true`).

**Causa:** Se usó `docker-compose down -v` que elimina los volúmenes nombrados, o el volumen no está montado correctamente.

**Solución:**
```bash
# Usar down SIN el flag -v para preservar volúmenes
docker-compose down        # correcto: preserva stride-cache y stride-output
docker-compose down -v     # incorrecto: elimina todos los volúmenes

# Verificar que el volumen existe
docker volume ls | grep stride-cache
```

---

### 5. attack-engine no puede conectar con el sistema objetivo

**Síntoma:**
```
Connection refused: http://localhost:8080
```

**Causa:** El contenedor `attack-engine` intenta conectar a `localhost`, que dentro del contenedor es el propio contenedor, no el host.

**Solución:** Usar el nombre del servicio en la red interna `stride-network`, o usar `host.docker.internal` para apuntar al host:
```bash
# En docker-compose.yml, agregar variable TARGET_URL para attack-engine:
docker-compose run attack-engine java -cp out:lib/snakeyaml-2.2.jar AttackEngine \
  --target http://host.docker.internal:8080

# O pasar TARGET_URL en .env:
TARGET_URL=http://host.docker.internal:8080
```

---

## Limpieza de volúmenes

```bash
# Detener servicios preservando datos
docker-compose down

# Detener servicios Y eliminar volúmenes (requiere reconstruir caché)
docker-compose down -v

# Eliminar solo el caché del agente (mantiene los reportes)
docker volume rm attack-simulation-fdsi_stride-cache

# Eliminar solo los reportes generados
docker volume rm attack-simulation-fdsi_stride-output

# Limpiar todo: imágenes, contenedores, volúmenes y redes del proyecto
docker-compose down -v --rmi all
```

> **Nota:** El prefijo del volumen (`attack-simulation-fdsi_`) corresponde al nombre del directorio del proyecto. Verificar con `docker volume ls` antes de eliminar.
