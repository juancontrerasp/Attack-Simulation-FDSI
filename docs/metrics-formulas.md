# Métricas de Comparación: Manual vs Automatizado

Documentación de las fórmulas y definiciones usadas en `compare.js` para evaluar la calidad del análisis STRIDE automatizado frente al manual.

---

## 1. Definiciones Fundamentales

### Verdadero Positivo (TP – True Positive)

Una amenaza que fue identificada **tanto** en el análisis manual **como** en el análisis automatizado.  
El automatizado "acertó": detectó una amenaza que el experto humano también encontró.

### Falso Positivo (FP – False Positive)

Una amenaza que el análisis automatizado **reportó** pero el análisis manual **no encontró**.  
El automatizado "inventó" una amenaza que el experto no consideró real o relevante.

### Falso Negativo (FN – False Negative)

Una amenaza que el análisis manual **encontró** pero el análisis automatizado **no detectó**.  
El automatizado "se perdió" una amenaza real.

### Verdadero Negativo (TN – True Negative)

Una amenaza que **ninguno** de los análisis identificó (no aplicable directamente aquí, ya que solo trabajamos con amenazas reportadas).

---

## 2. Fórmulas

### Precision (Precisión)

Mide qué proporción de las amenazas reportadas por el automatizado son realmente válidas (confirmadas por el análisis manual).

```
Precision = TP / (TP + FP)
```

- **Rango**: 0.0 – 1.0 (0% – 100%)
- **Alta precisión** → pocas falsas alarmas
- **Baja precisión** → muchas amenazas reportadas que no son reales

> Si el denominador es 0 (no se detectó ninguna amenaza), Precision = 0.

---

### Recall (Cobertura / Sensibilidad)

Mide qué proporción de las amenazas reales (del análisis manual) fueron detectadas por el automatizado.

```
Recall = TP / (TP + FN)
```

- **Rango**: 0.0 – 1.0 (0% – 100%)
- **Alto recall** → pocas amenazas perdidas
- **Bajo recall** → el automatizado perdió muchas amenazas reales

> Si el denominador es 0 (no hay amenazas manuales), Recall = 0.

---

### F1 Score

Media armónica de Precision y Recall. Balancea ambas métricas en un único número.

```
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

- **Rango**: 0.0 – 1.0 (0% – 100%)
- **F1 alto** → buen balance entre no perderse amenazas y no generar falsas alarmas
- Penaliza fuertemente si cualquiera de las dos métricas es baja

> Si Precision + Recall = 0, F1 = 0 (evita división por cero).

---

### Cobertura STRIDE (STRIDE Coverage)

Mide qué porcentaje de las 6 categorías STRIDE están representadas en el análisis automatizado.

```
STRIDE Coverage (%) = (Categorías cubiertas / 6) × 100
```

Las 6 categorías STRIDE son:
1. **S**poofing
2. **T**ampering
3. **R**epudiation
4. **I**nformation Disclosure
5. **D**enial of Service
6. **E**levation of Privilege

Una categoría se considera "cubierta" si el análisis automatizado detectó **al menos una** amenaza en esa categoría.

---

## 3. Normalización de Amenazas

Para comparar amenazas entre análisis manual y automatizado, se construye una **clave normalizada**:

```
key = normalize(category) | normalize(component) | normalize(severity)
```

- Todo en minúsculas y sin espacios extras
- Aliases de categorías unificados (p.ej. `"Information Disclosure"` → `"InformationDisclosure"`)

Dos amenazas son consideradas **iguales** si sus claves normalizadas coinciden.

---

## 4. Ejemplo Sencillo

Supongamos:

**Análisis manual** (ground truth):
| # | Categoría | Componente | Severidad |
|---|-----------|------------|-----------|
| 1 | Spoofing | CORS Attack | Alta |
| 2 | Tampering | SQL Injection | Alta |
| 3 | InformationDisclosure | Info Leak | Media |

**Análisis automatizado**:
| # | Categoría | Componente | Severidad |
|---|-----------|------------|-----------|
| A | Spoofing | CORS Attack | Alta |
| B | Tampering | SQL Injection | Alta |
| C | Tampering | XSS Attack | Alta |

**Clasificación**:
- `1` y `A` coinciden → **TP**
- `2` y `B` coinciden → **TP**
- `3` no tiene par en automatizado → **FN**
- `C` no tiene par en manual → **FP**

**Cálculo**:
```
TP = 2, FP = 1, FN = 1

Precision = 2 / (2+1) = 0.667  →  66.7%
Recall    = 2 / (2+1) = 0.667  →  66.7%
F1        = 2 × (0.667 × 0.667) / (0.667 + 0.667) = 0.667  →  66.7%

STRIDE Coverage = 2/6 × 100 = 33.3%
  (Solo Spoofing y Tampering tienen al menos 1 amenaza automatizada)
```

---

## 5. Interpretación de Resultados

| Métrica | Excelente | Aceptable | Mejorar |
|---------|-----------|-----------|---------|
| Precision | ≥ 75% | 50–74% | < 50% |
| Recall | ≥ 75% | 50–74% | < 50% |
| F1 Score | ≥ 75% | 50–74% | < 50% |
| STRIDE Coverage | 100% | 67–83% | < 67% |

---

## 6. Métricas adicionales del paper (US-08)

### Cobertura Total (Total Coverage)

Mide qué proporción **cuantitativa** de amenazas produce el agente con respecto al análisis manual.
A diferencia de Recall (que requiere matching individual), esta métrica compara solo los conteos.

```text
Cobertura Total (%) = |amenazas_agente| / |amenazas_manuales_inseguro| × 100
```

- Puede superar 100% si el agente detecta más amenazas que el equipo manual.
- Complementaria al Recall: informa sobre la _cantidad_ relativa, no solo el solapamiento.

---

### Tasa de Falsos Positivos (False Positive Rate)

Porcentaje de las amenazas del agente que **no fueron identificadas manualmente**.

```text
FP Rate (%) = FP / |amenazas_agente| × 100
```

Equivale a `1 - Precision` expresado como porcentaje del total automatizado (no del total manual).

---

### Ratio de Velocidad (Speedup Ratio)

Cuántas veces más rápido es el análisis automatizado frente al manual.

```text
Speedup = tiempo_manual (s) / tiempo_automatizado (s)
```

- Un ratio ≥ 10 es el umbral mínimo requerido por US-08.
- Los tiempos se extraen del campo `analysisTimeSeconds` en los metadatos de cada JSON.

---

### Ratio de Diferenciación (Differentiation Ratio)

Mide la capacidad de los dos enfoques para **distinguir** sistemas inseguros de seguros,
en función de la diferencia en la cantidad de amenazas detectadas.

```text
Diferenciación = |amenazas_inseguro| / |amenazas_seguro|
```

- Un ratio ≥ 1.4 indica que el análisis detecta al menos un 40% más de amenazas en el sistema inseguro.
- Se calcula tanto para el análisis manual como para el automatizado (cuando están disponibles).

---

### Análisis por Formato de Entrada

Compara la cobertura del agente cuando el **mismo sistema** se proporciona en distintos formatos:

| Formato | Archivo esperado |
|---------|-----------------|
| Código fuente (Java) | `threats-output-code.json` |
| Diagrama Mermaid | `threats-output-mermaid.json` |
| Imagen del diagrama | `threats-output-image.json` |

Para cada formato se calculan Recall, Precision, F1, Cobertura total y Cobertura STRIDE.
Esto evidencia la ventaja del enfoque _formato-agnóstico_.

---

## 7. Referencias

- STRIDE: [Microsoft STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- Precision/Recall: [Wikipedia – Precision and recall](https://en.wikipedia.org/wiki/Precision_and_recall)
- F1 Score: [Wikipedia – F-score](https://en.wikipedia.org/wiki/F-score)
