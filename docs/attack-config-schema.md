# Attack Config YAML Schema

Schema reference for `config/attack-config.yaml` and its variants.

## Full Schema

```yaml
target_url: <string>           # REQUIRED
endpoints:                     # optional
  login: <string>              # optional, default: /login
  register: <string>           # optional, default: /register
  auth_me: <string>            # optional, default: /api/auth/me
timeout_ms: <integer>          # optional, default: 5000
max_passwords: <integer>       # optional, default: 100
passwords_file: <string>       # optional, default: passwords.txt
enabled_attacks: [<string>]    # optional, default: all attacks
```

## Field Reference

### `target_url` — string, REQUIRED

Base URL of the target system. Must be a well-formed HTTP or HTTPS URL.

| Detail | Value |
|---|---|
| Type | `string` |
| Required | Yes |
| Format | Must start with `http://` or `https://` |
| Example | `http://localhost:8080` |
| Example | `https://staging.myapp.com` |

**Error if missing:** `Error de configuracion: target_url es requerido`  
**Error if invalid:** `Error de configuracion: target_url debe ser una URL HTTP/HTTPS valida`

---

### `endpoints` — object, optional

Override endpoint paths when the target application uses non-standard routes.
All sub-fields are optional and fall back to their defaults if omitted.

| Sub-field | Type | Default | Description |
|---|---|---|---|
| `login` | string | `/login` | POST endpoint for authentication |
| `register` | string | `/register` | POST endpoint for user registration |
| `auth_me` | string | `/api/auth/me` | GET endpoint requiring a Bearer JWT token |

---

### `timeout_ms` — integer, optional

Maximum time in milliseconds to wait for each individual HTTP request (both
connection and response). Applied to every request across all attacks.

| Detail | Value |
|---|---|
| Type | `integer` |
| Default | `5000` |
| Min | `1` (positive integer) |
| Recommended for local | `5000` |
| Recommended for remote | `10000` |
| Recommended for CI | `2000` |

**Error if invalid:** `Error de configuracion: timeout_ms debe ser un entero positivo`

---

### `max_passwords` — integer, optional

Maximum number of passwords to test in the `BruteForce` attack.
Passwords are read from `passwords_file` up to this limit.

| Detail | Value |
|---|---|
| Type | `integer` |
| Default | `100` |
| Min | `1` |
| Max | `1000` |

**Error if out of range:** `Error de configuracion: max_passwords debe estar entre 1 y 1000`

---

### `passwords_file` — string, optional

Path to a plain-text file containing one password per line, used by the
`BruteForce` attack. Path is relative to the directory where `launch_attack.sh`
is executed (project root).

| Detail | Value |
|---|---|
| Type | `string` |
| Default | `passwords.txt` |
| Format | Relative or absolute path |
| Example | `passwords.txt` |
| Example | `attack-engine/wordlists/rockyou-top1000.txt` |

---

### `enabled_attacks` — list of strings, optional

Explicit list of attacks to execute. If omitted, all 10 attacks run.
Unknown names produce a warning but do not cause an error.

| Detail | Value |
|---|---|
| Type | `list<string>` |
| Default | All 10 attacks |
| Valid values | See table below |

| Value | Attack | STRIDE Category |
|---|---|---|
| `SqlInjection` | SQL Injection | Tampering |
| `BruteForce` | Brute Force | DenialOfService |
| `SessionFixation` | Session Fixation | Spoofing |
| `JwtToken` | JWT Token Security | Spoofing |
| `XSS` | Cross-Site Scripting | Tampering |
| `PathTraversal` | Path Traversal | InformationDisclosure |
| `InfoLeak` | Information Leakage | InformationDisclosure |
| `InsecureHeaders` | Insecure HTTP Headers | InformationDisclosure |
| `CORS` | CORS Misconfiguration | Spoofing |
| `WeakPassword` | Weak Password Policy | ElevationOfPrivilege |

## Unknown Fields

Any field not listed above produces a **warning** on stderr but does not stop
execution. This ensures forward compatibility when new fields are added.

## Validation Error Messages

| Condition | Message |
|---|---|
| `target_url` missing | `Error de configuracion: target_url es requerido` |
| `target_url` not HTTP/HTTPS | `Error de configuracion: target_url debe ser una URL HTTP/HTTPS valida` |
| `timeout_ms` not a positive integer | `Error de configuracion: timeout_ms debe ser un entero positivo` |
| `max_passwords` outside 1-1000 | `Error de configuracion: max_passwords debe estar entre 1 y 1000` |
| `timeout_ms` / `max_passwords` not an integer | `Error de configuracion: <field> debe ser un numero entero` |
