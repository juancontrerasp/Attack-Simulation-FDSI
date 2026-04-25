#!/bin/bash
# Attack Simulation Launcher
# Usage: ./launch_attack.sh [OPTIONS]
#
# Options:
#   --config <path>      Path to YAML config file (default: config/attack-config.yaml)
#   --target <url>       Override target_url from config (e.g. http://192.168.1.1:9090)
#   --attacks <list>     Comma-separated attack names to run (e.g. SqlInjection,XSS)
#
# Examples:
#   ./launch_attack.sh
#   ./launch_attack.sh --config config/attack-config-ci.yaml
#   ./launch_attack.sh --target http://192.168.1.100:9090
#   ./launch_attack.sh --attacks SqlInjection,BruteForce,XSS

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
CONFIG_ARG=""
TARGET_ARG=""
ATTACKS_ARG=""

# Valid attack names for bash-side validation
VALID_ATTACKS=("SqlInjection" "BruteForce" "SessionFixation" "JwtToken" "XSS"
               "PathTraversal" "InfoLeak" "InsecureHeaders" "CORS" "WeakPassword")

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG_ARG="$2"; shift 2 ;;
        --target)
            TARGET_ARG="$2"; shift 2 ;;
        --attacks)
            ATTACKS_ARG="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "🛡️  Attack Simulation Tool"
echo "========================="

# ── Validate --attacks names before invoking Java ─────────────────────────────
if [[ -n "$ATTACKS_ARG" ]]; then
    IFS=',' read -ra REQUESTED <<< "$ATTACKS_ARG"
    for name in "${REQUESTED[@]}"; do
        valid=false
        for v in "${VALID_ATTACKS[@]}"; do
            if [[ "$name" == "$v" ]]; then valid=true; break; fi
        done
        if [[ "$valid" == "false" ]]; then
            echo "❌ Error: nombre de ataque invalido: '$name'"
            echo "   Valores validos: ${VALID_ATTACKS[*]}"
            exit 1
        fi
    done
fi

# ── Check directory ────────────────────────────────────────────────────────────
if [[ ! -d "attack-engine" ]]; then
    echo "❌ Error: attack-engine directory not found"
    echo "   Run this script from the Attack-Simulation-FDSI root directory"
    exit 1
fi

# ── SnakeYAML dependency ──────────────────────────────────────────────────────
LIB_DIR="attack-engine/lib"
SNAKE_JAR_NAME="snakeyaml-2.2.jar"
SNAKE_JAR="$LIB_DIR/$SNAKE_JAR_NAME"
SNAKE_URL="https://repo1.maven.org/maven2/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar"

mkdir -p "$LIB_DIR"

if [[ ! -f "$SNAKE_JAR" ]]; then
    echo "📦 Descargando SnakeYAML $SNAKE_JAR_NAME ..."
    if command -v curl &>/dev/null; then
        curl -fsSL -o "$SNAKE_JAR" "$SNAKE_URL"
    elif command -v wget &>/dev/null; then
        wget -q -O "$SNAKE_JAR" "$SNAKE_URL"
    else
        echo "❌ Error: se necesita curl o wget para descargar SnakeYAML."
        echo "   Descargalo manualmente desde:"
        echo "   $SNAKE_URL"
        echo "   y guardalo en $SNAKE_JAR"
        exit 1
    fi
    echo "✅ SnakeYAML descargado"
fi

# ── Classpath separator (Windows vs Unix) ─────────────────────────────────────
OS=$(uname -s 2>/dev/null || echo "unknown")
case "$OS" in
    MINGW*|CYGWIN*|MSYS*) CP_SEP=";" ;;
    *)                     CP_SEP=":" ;;
esac

SNAKE_CP="attack-engine/lib/$SNAKE_JAR_NAME"

# ── Compile if needed ──────────────────────────────────────────────────────────
NEEDS_COMPILE=false
if [[ ! -d "out" ]] || [[ ! -f "out/AttackEngine.class" ]]; then
    NEEDS_COMPILE=true
fi

# Recompile if any source file is newer than AttackEngine.class
if [[ "$NEEDS_COMPILE" == "false" ]]; then
    while IFS= read -r -d '' src; do
        if [[ "$src" -nt "out/AttackEngine.class" ]]; then
            NEEDS_COMPILE=true
            break
        fi
    done < <(find attack-engine -name "*.java" -print0 2>/dev/null)
fi

if [[ "$NEEDS_COMPILE" == "true" ]]; then
    echo "🔨 Compilando motor de ataques..."
    mkdir -p out
    (
        cd attack-engine
        javac -cp "lib/$SNAKE_JAR_NAME" -d ../out \
            AttackEngine.java \
            attacks/*.java \
            model/*.java \
            util/*.java \
            config/*.java
    )
    if [[ $? -ne 0 ]]; then
        echo "❌ Error de compilacion"
        exit 1
    fi
    echo "✅ Compilacion exitosa"
    echo ""
fi

# ── Build Java arguments ───────────────────────────────────────────────────────
JAVA_ARGS=()

if [[ -n "$CONFIG_ARG" ]]; then
    JAVA_ARGS+=("--config" "$CONFIG_ARG")
    echo "📋 Config: $CONFIG_ARG"
else
    JAVA_ARGS+=("--config" "config/attack-config.yaml")
fi

if [[ -n "$TARGET_ARG" ]]; then
    JAVA_ARGS+=("--target" "$TARGET_ARG")
    echo "🎯 Target override: $TARGET_ARG"
fi

if [[ -n "$ATTACKS_ARG" ]]; then
    JAVA_ARGS+=("--attacks" "$ATTACKS_ARG")
    echo "⚔️  Attacks: $ATTACKS_ARG"
fi

echo ""

# ── Run ────────────────────────────────────────────────────────────────────────
echo "🚀 Iniciando simulacion de ataques..."
echo ""
java -cp "out${CP_SEP}${SNAKE_CP}" AttackEngine "${JAVA_ARGS[@]}"

# ── Post-run ───────────────────────────────────────────────────────────────────
if [[ -f "results.json" ]]; then
    echo ""
    echo "✅ Simulacion completada!"
    echo ""

    if [[ -f "create-standalone-dashboard.py" ]]; then
        echo "📊 Generando dashboard standalone..."
        python3 create-standalone-dashboard.py
        echo ""
    fi

    echo "📊 Resultados guardados en:"
    echo "   - results.json          (resultados detallados con STRIDE)"
    echo "   - dashboard-standalone.html  (abre directamente en el navegador) ⭐"
    echo ""

    # Quick summary using vulnerable count
    VULN_COUNT=$(grep -c '"vulnerable":true' results.json 2>/dev/null || echo "0")
    if [[ "$VULN_COUNT" -gt 0 ]]; then
        echo "⚠️  Advertencia: $VULN_COUNT vulnerabilidades detectadas"
    else
        echo "✅ No se detectaron vulnerabilidades"
    fi
else
    echo "❌ Error: results.json no fue generado"
    exit 1
fi
