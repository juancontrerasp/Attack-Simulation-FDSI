#!/bin/bash

# run-full-analysis.sh
# Orchestrates AI static analysis and Java dynamic validation.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Defaults
SKIP_DYNAMIC=false
TARGET_OVERRIDE=""

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

# --- 1. Dependency Check ---
log "${BOLD}Fase 0: Verificación de dependencias${NC}"
if ! command -v node &>/dev/null; then
    echo -e "${RED}Error: node no está instalado.${NC}"
    exit 1
fi
if ! command -v java &>/dev/null; then
    echo -e "${RED}Error: java no está instalado.${NC}"
    exit 1
fi

# --- 2. Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-dynamic) SKIP_DYNAMIC=true; shift ;;
        --target) TARGET_OVERRIDE="$2"; shift 2 ;;
        *) echo "Opción desconocida: $1"; exit 1 ;;
    esac
done

# --- 3. AI Static Analysis ---
log "${BOLD}Fase 1: Análisis estático de IA (STRIDE)${NC}"
node scripts/full-repo-analyzer.js
if [ $? -ne 0 ]; then
    echo -e "${RED}Error en el análisis estático.${NC}"
    exit 1
fi

# --- 4. Health Check & Dynamic Analysis ---
if [ "$SKIP_DYNAMIC" = "true" ]; then
    log "${YELLOW}Fase 2: Omitiendo validación dinámica (--skip-dynamic)${NC}"
    rm -f results.json # Ensure old results don't interfere
else
    log "${BOLD}Fase 2: Validación dinámica (Motor Java)${NC}"
    
    # Determine target URL
    TARGET_URL=$(grep "target_url" config/attack-config.yaml | cut -d'"' -f2)
    [ -n "$TARGET_OVERRIDE" ] && TARGET_URL="$TARGET_OVERRIDE"

    log "Realizando health check a: $TARGET_URL"
    HEALTHY=false
    for i in {1..3}; do
        if curl -s --max-time 5 "$TARGET_URL" > /dev/null; then
            HEALTHY=true
            break
        fi
        log "${YELLOW}Reintento $i: El sistema no responde...${NC}"
        sleep 2
    done

    if [ "$HEALTHY" = "true" ]; then
        log "${GREEN}Sistema disponible. Iniciando pruebas dinámicas...${NC}"
        
        # Select attacks based on AI findings
        ATTACKS=$(node -e "
            const threats = JSON.parse(require('fs').readFileSync('threats-output.json')).threats;
            const map = JSON.parse(require('fs').readFileSync('config/stride-attacks-map.json'));
            const selected = new Set();
            for (const cat in threats) {
                if (threats[cat].length > 0 && map[cat]) {
                    map[cat].forEach(a => selected.add(a));
                }
            }
            console.log(Array.from(selected).join(','));
        ")
        
        if [ -z "$ATTACKS" ]; then
            log "No se detectaron amenazas que requieran validación dinámica."
            rm -f results.json
        else
            log "Ejecutando ataques: $ATTACKS"
            ./launch_attack.sh --attacks "$ATTACKS" ${TARGET_OVERRIDE:+"--target $TARGET_OVERRIDE"}
        fi
    else
        log "${RED}Error: El sistema objetivo no está disponible tras 3 reintentos.${NC}"
        rm -f results.json
    fi
fi

# --- 5. Merge Results ---
log "${BOLD}Fase 3: Consolidación de reporte final${NC}"
node scripts/combine-results.js

log "${GREEN}${BOLD}Pipeline completado exitosamente.${NC}"
log "Reporte consolidado disponible en: ${BOLD}combined-report.json${NC}"
