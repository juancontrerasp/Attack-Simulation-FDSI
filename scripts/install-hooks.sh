#!/bin/bash

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Instalando hooks de Git...${NC}"

# Check if running from repo root
if [ ! -d ".git" ]; then
    echo -e "${RED}Error: Este script debe ejecutarse desde la raíz del repositorio (donde se encuentra la carpeta .git).${NC}"
    exit 1
fi

# Ensure .git/hooks directory exists
mkdir -p .git/hooks

# Path to the source hook and destination
HOOK_SOURCE=".git-hooks/pre-push"
HOOK_DEST=".git/hooks/pre-push"

if [ -f "$HOOK_SOURCE" ]; then
    # Copy the hook file
    cp "$HOOK_SOURCE" "$HOOK_DEST"
    
    # Set execution permissions (Linux/Mac/WSL)
    chmod +x "$HOOK_DEST"
    
    echo -e "${GREEN}¡Éxito! El hook pre-push ha sido instalado en $HOOK_DEST${NC}"
else
    echo -e "${RED}Error: No se encontró el archivo de origen en $HOOK_SOURCE${NC}"
    exit 1
fi
