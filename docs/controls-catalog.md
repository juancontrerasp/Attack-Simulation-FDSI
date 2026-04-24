# Security Controls Catalog

Catálogo de controles de seguridad mapeados a categorías STRIDE.  
Archivo fuente: [`/security/controls-catalog.json`](../security/controls-catalog.json)

Cada control incluye: estándar de referencia (OWASP/CWE/NIST), estimación de esfuerzo y ejemplos de implementación en Java, Node.js y Python.

---

## Categoría: Spoofing

| ID | Amenaza | Control | Estándar | Referencia | Esfuerzo |
|----|---------|---------|----------|------------|----------|
| CTRL-S-01 | JwtAlgNone | JWT Algorithm Pinning | OWASP A07:2021 - Identification and Authentication Failures | CWE-345 | Medium |
| CTRL-S-02 | SessionFixation | Session Regeneration on Authentication | OWASP A07:2021 - Identification and Authentication Failures | CWE-384 | Low |
| CTRL-S-03 | WeakAuth | Multi-Factor Authentication and Account Lockout | OWASP A07:2021 - Identification and Authentication Failures | CWE-287 | Medium |

**Descripción de controles:**

- **JWT Algorithm Pinning** — Fijar el algoritmo esperado en `verify()` impide ataques `alg=none` donde el atacante forja tokens sin firma válida.
- **Session Regeneration** — Regenerar el ID de sesión tras autenticar previene que un atacante fije una sesión conocida antes del login.
- **Account Lockout** — Combinar rate-limiting con bloqueo temporal tras N intentos fallidos mitiga ataques de fuerza bruta sobre credenciales.

---

## Categoría: Tampering

| ID | Amenaza | Control | Estándar | Referencia | Esfuerzo |
|----|---------|---------|----------|------------|----------|
| CTRL-T-01 | SqlInjection | Parameterized Queries / Prepared Statements | OWASP A03:2021 - Injection | CWE-89 | High |
| CTRL-T-02 | XSS | Output Encoding and Content Security Policy | OWASP A03:2021 - Injection | CWE-79 | Medium |
| CTRL-T-03 | PathTraversal | Canonical Path Validation | OWASP A01:2021 - Broken Access Control | CWE-22 | Medium |

**Descripción de controles:**

- **Parameterized Queries** — Separar el código SQL de los datos de usuario mediante `PreparedStatement` / `pool.execute()` elimina la superficie de inyección SQL. Refactoring alto porque requiere revisar cada query del codebase.
- **Output Encoding + CSP** — Escapar datos antes de renderizarlos en HTML y añadir Content-Security-Policy bloquea XSS reflejado, almacenado y basado en DOM.
- **Canonical Path Validation** — Resolver la ruta a su forma canónica y verificar que está dentro del directorio base autorizado previene path traversal y lectura arbitraria de archivos.

---

## Categoría: Repudiation

| ID | Amenaza | Control | Estándar | Referencia | Esfuerzo |
|----|---------|---------|----------|------------|----------|
| CTRL-R-01 | MissingAuditLog | Structured Audit Logging with Actor Context | NIST SP 800-53 AU-2 | CWE-778 | Medium |
| CTRL-R-02 | TamperedLogs | Log Injection Prevention | OWASP A09:2021 - Security Logging and Monitoring Failures | CWE-117 | Low |
| CTRL-R-03 | NoNonRepudiation | Cryptographic Event Signing | NIST SP 800-53 AU-10 | CWE-345 | High |

**Descripción de controles:**

- **Structured Audit Logging** — Registrar actor, acción, recurso y timestamp en formato JSON estructurado permite trazabilidad forense completa y cumple NIST AU-2.
- **Log Injection Prevention** — Sanear la entrada del usuario antes de escribirla en logs (eliminar `\r\n`) previene que un atacante forje entradas de log o inyecte comandos de control.
- **Cryptographic Event Signing** — Firmar eventos críticos con ECDSA garantiza que no pueden ser repudiados ni modificados retroactivamente (no-repudiation).

---

## Categoría: Information Disclosure

| ID | Amenaza | Control | Estándar | Referencia | Esfuerzo |
|----|---------|---------|----------|------------|----------|
| CTRL-I-01 | MissingHeaders | HTTP Security Headers Enforcement | OWASP A05:2021 - Security Misconfiguration | CWE-693 | Low |
| CTRL-I-02 | ErrorLeakage | Generic Error Responses | OWASP A05:2021 - Security Misconfiguration | CWE-209 | Low |
| CTRL-I-03 | SensitiveDataExposure | Sensitive Field Filtering in API Responses | OWASP A02:2021 - Cryptographic Failures | CWE-312 | Medium |

**Descripción de controles:**

- **HTTP Security Headers** — Añadir `X-Frame-Options: DENY`, `HSTS`, `X-Content-Type-Options` y `CSP` con una línea de configuración (`helmet`, Spring Security headers) cierra vectores de clickjacking, sniffing y cross-origin.
- **Generic Error Responses** — Devolver `"Internal server error"` genérico en producción impide que stacktraces, versiones de frameworks o rutas internas lleguen al atacante.
- **Sensitive Field Filtering** — Excluir campos como `password`, `resetToken` o `ssn` de las respuestas API con `@JsonIgnore` / DTO / serializer `write_only` evita exposición accidental de datos sensibles.

---

## Categoría: Denial of Service

| ID | Amenaza | Control | Estándar | Referencia | Esfuerzo |
|----|---------|---------|----------|------------|----------|
| CTRL-D-01 | BruteForce | Rate Limiting on Authentication Endpoints | OWASP A07:2021 - Identification and Authentication Failures | CWE-307 | Medium |
| CTRL-D-02 | ResourceExhaustion | Request Size Limits and Timeouts | NIST SP 800-53 SC-5 | CWE-400 | Low |
| CTRL-D-03 | ConnectionExhaustion | Connection Pool and Circuit Breaker Configuration | NIST SP 800-53 SC-5 | CWE-770 | Medium |

**Descripción de controles:**

- **Rate Limiting** — Limitar a 5 intentos por 15 minutos en `/login` (Bucket4j / express-rate-limit / django-ratelimit) previene fuerza bruta automatizada sin afectar usuarios legítimos.
- **Request Size Limits** — Configurar un tamaño máximo de body (2MB) y timeout de conexión (30s) bloquea ataques de agotamiento de recursos por payload gigante o conexiones lentas.
- **Connection Pool Limits** — Configurar `pool_size`, `max_overflow` y `connection_timeout` en HikariCP/mysql2/SQLAlchemy previene que ráfagas de tráfico agoten los descriptores de conexión.

---

## Categoría: Elevation of Privilege

| ID | Amenaza | Control | Estándar | Referencia | Esfuerzo |
|----|---------|---------|----------|------------|----------|
| CTRL-E-01 | WeakPassword | Password Complexity and Hashing Policy | OWASP A07:2021 - Identification and Authentication Failures | CWE-521 | Medium |
| CTRL-E-02 | MissingAuthz | Role-Based Access Control Enforcement | OWASP A01:2021 - Broken Access Control | CWE-285 | Medium |
| CTRL-E-03 | PrivilegeEscalation | Object-Level Ownership Verification (IDOR Prevention) | OWASP A01:2021 - Broken Access Control | CWE-269 | High |

**Descripción de controles:**

- **Password Complexity** — Exigir mínimo 12 caracteres con mayúscula, número y símbolo especial, y hashear con BCrypt cost 12 (passay / bcrypt / Django validators) neutraliza ataques de diccionario y rainbow tables.
- **RBAC Enforcement** — Verificar el rol del usuario en cada endpoint sensible con `@PreAuthorize` / middleware JWT / `@permission_required` impide acceso no autorizado por escalada horizontal.
- **IDOR Prevention** — Filtrar siempre los recursos por `userId == currentUser.id` a nivel de query previene acceso cross-tenant donde un usuario autenticado accede a recursos de otro usuario.

---

## Uso programático

```bash
# Enriquecer un reporte existente con el catálogo
node stride-agent/recommend.js --threats threats-output.json

# Enriquecer in-place (sobreescribe el original)
node stride-agent/recommend.js --threats threats-output.json --in-place

# Especificar repo para detección de stack
node stride-agent/recommend.js --threats threats-output.json --repo ./mi-proyecto
```

## Añadir controles al catálogo

El catálogo `/security/controls-catalog.json` es un archivo JSON versionado, editable sin código.  
Para añadir un control nuevo, agrega un objeto al array `controls` siguiendo la estructura:

```json
{
  "id": "CTRL-X-04",
  "stride_category": "Tampering",
  "threat_pattern": "MiAmenaza",
  "control_name": "Nombre del Control",
  "control_standard": "OWASP A03:2021 - Injection",
  "reference_id": "CWE-XX",
  "effort_estimate": "Low|Medium|High",
  "implementation_hints": {
    "Java": "// código Java real",
    "Node.js": "// código Node.js real",
    "Python": "# código Python real"
  }
}
```
