# Demo 5 Minutos (Windows / PowerShell)

## Objetivo
Mostrar, en 5 minutos, las capacidades principales del repo:
- Analisis estatico STRIDE por IA.
- Simulacion de ataques dinamicos con Java.
- Consolidacion y metricas para reporte.
- Gate de seguridad por baseline (incluyendo caso de falla).
- Pipeline Windows nativo con scripts `.ps1`.

## Pre-demo (1-2 min antes)
Ejecuta el preflight para validar comandos:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demo-preflight.ps1
```

Artefacto generado:
- `demo-preflight-report.json`

## Guion de 5 minutos

### Min 0:00 - 0:30 | Contexto rapido
Explica que el proyecto combina:
- Motor de ataques Java (`attack-engine`).
- Agente STRIDE IA (`stride-agent`).
- Reportes para evidencia (`combined-report.json`, `metrics-report.html`).

### Min 0:30 - 1:30 | Analisis estatico IA
```powershell
npm run stride:analyze
```

Muestra archivo generado:
- `threats-output.json`

### Min 1:30 - 2:30 | Validacion dinamica (ataque puntual)
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\launch_attack.ps1 -Attacks SqlInjection -Target http://localhost:8080
```

Muestra archivos:
- `results.json`
- `dashboard-standalone.html`

### Min 2:30 - 3:20 | Consolidacion de hallazgos
```powershell
node scripts/combine-results.js
```

Muestra archivo:
- `combined-report.json`

### Min 3:20 - 4:10 | Metricas para paper/evidencia
```powershell
node compare.js
```

Muestra archivos:
- `metrics-report.json`
- `metrics-report.html`
- `docs/results-table.tex`

### Min 4:10 - 5:00 | Pipeline completo y gate de seguridad
Demo estable (siempre util para presentacion):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipDynamic -SkipRecommendations -SkipBaseline
```

Luego muestra el gate real (puede fallar si hay regresiones `reopened`):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipDynamic -SkipRecommendations
```

Mensaje clave de valor:
- Si falla baseline, el pipeline bloquea por regresion de seguridad.
- Si se omite baseline solo para demo, el resto del flujo queda demostrado de punta a punta.

## Comandos de respaldo (por si algo tarda)
Si recomendaciones tardan mucho, usa:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipRecommendations -SkipDynamic -SkipBaseline
```

Si el target no responde:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\launch_attack.ps1 -Attacks SqlInjection -Target http://localhost:8080
```
(igual te genera `results.json` y dashboard en este entorno)

## Artefactos a enseñar al final
- `threats-output.json`
- `results.json`
- `combined-report.json`
- `dashboard-standalone.html`
- `metrics-report.html`
- `security/threat-registry.json`
