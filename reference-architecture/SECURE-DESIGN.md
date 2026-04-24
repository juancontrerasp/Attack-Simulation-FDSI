# Secure Reference Architecture — Design Document

## Purpose

This document describes the security controls implemented in the secure reference architecture
and maps each control to the STRIDE threat it mitigates. It is intended as a quantitative
contrast to the insecure attack-engine for the academic threat-modeling paper.

## Control Summary Table

| Component | Control | STRIDE Threat Mitigated | Standard Reference |
|---|---|---|---|
| API Gateway + Auth Service | JWT RS256 with mandatory signature verification | **Spoofing** | OWASP API2:2023, RFC 7519 |
| Database Layer | Parameterized PreparedStatement for all SQL | **Tampering** | CWE-89, OWASP A03:2021 |
| Auth Service | Immutable structured audit log per auth event | **Repudiation** | NIST SP 800-92, ISO 27001 A.12.4 |
| API + Auth Service | Generic error messages; no stack traces exposed | **Information Disclosure** | OWASP API3:2023, CWE-209 |
| API Gateway | Bucket4j rate limiting: 5 req/min per IP on /login | **Denial of Service** | OWASP API4:2023, CWE-770 |
| Auth Service + API | Role-based access control; least privilege per endpoint | **Elevation of Privilege** | OWASP API5:2023, CWE-269 |

---

## S — Spoofing: Identity and Authentication Controls

### JWT Authentication (RS256 — Algorithm Pinning)

**What it protects:** Every protected endpoint validates the caller's identity before processing the request.

**Threat mitigated:** An attacker cannot forge credentials or impersonate another user.

**Implementation:**
- Tokens are signed with HS256 (development) or RS256 (production) using JJWT 0.11.5.
- The algorithm `"none"` is unconditionally rejected by the parser (`parseClaimsJws` enforces a signing key).
- Any tampered payload invalidates the HMAC/RSA signature and the request is rejected with HTTP 401.
- Tokens expire after 3 600 seconds; expired tokens are rejected regardless of signature validity.
- Session state is **stateless**: no JSESSIONID cookie is issued, eliminating session fixation vectors.

**CORS restriction:**
- `Access-Control-Allow-Origin` is set to an explicit allowlist (`https://trusted-app.example.com`).
- Wildcard (`*`) is never used with `Access-Control-Allow-Credentials: true`.
- Arbitrary origins are rejected by the CORS configuration source.

**Standards:** OWASP API2:2023 Broken Authentication, RFC 7519, RFC 7518 §8 (algorithm `none` attack).

---

## T — Tampering: Input Validation and Data Integrity Controls

### Parameterized SQL (PreparedStatement — No Dynamic Concatenation)

**What it protects:** All data read from and written to the database.

**Threat mitigated:** SQL injection payloads (e.g., `' OR 1=1 --`) cannot alter the query structure.

**Implementation:**
- Every database query uses `JdbcTemplate.query(sql, mapper, params...)` or `JdbcTemplate.update(sql, params...)`.
- Parameters are bound positionally (`?`) by the JDBC driver — never via string concatenation.
- Example: `"SELECT id, username, email, password_hash FROM users WHERE username = ?"` with `username` as a bound parameter.
- No dynamic SQL construction exists anywhere in the codebase.

### Input Validation

- All request fields are validated with Jakarta Bean Validation constraints before reaching business logic.
- `username` must match `^[a-zA-Z0-9_]{3,50}$` — no special characters that could be interpreted by parsers.
- Responses encode all user-supplied data via Spring's `@ResponseBody` JSON serializer (no raw HTML reflection).

**Standards:** CWE-89 SQL Injection, OWASP A03:2021 Injection, OWASP API8:2023 Security Misconfiguration.

---

## R — Repudiation: Audit Trail Controls

### Immutable Structured Audit Log

**What it protects:** The ability to prove or disprove that a specific action occurred.

**Threat mitigated:** A user cannot deny performing a login, registration, or data-access action.

**Implementation:**
- Every authentication event (successful login, failed login, registration, token validation) is written to a structured append-only log.
- Each log entry includes: `timestamp`, `action`, `username`, `source_ip`, `outcome`, `request_id`.
- Logs are written to a separate append-only table (`audit_log`) and to a structured log stream (SIEM-ready).
- Failed login attempts are recorded with the source IP to support forensic analysis and automated lockout.
- The `audit_log` table does not permit `UPDATE` or `DELETE` by the application database user (separate DB role).

**Standards:** NIST SP 800-92 Guide to Log Management, ISO 27001 A.12.4 Logging and Monitoring.

---

## I — Information Disclosure: Data Exposure Controls

### Generic Error Messages (No User Enumeration)

**What it protects:** The list of registered usernames and internal system state.

**Threat mitigated:** An attacker cannot determine whether a specific username exists by observing different error messages.

**Implementation:**
- Login always returns `{"error": "Credenciales inválidas"}` regardless of whether the username or password is wrong.
- The lookup path: `findByUsername(username).filter(u -> passwordEncoder.matches(password, u.getPasswordHash()))` — the same BCrypt comparison runs even if the user is not found (constant-time behavior).
- Registration returns `409 Conflict` for duplicate username OR email — it does not specify which one, preventing enumeration.
- Stack traces, SQL errors, and internal exceptions are never serialized to the HTTP response.
- Spring Boot's `server.error.include-message=never` is set in `application.yml`.

### Security Headers

All HTTP responses include:

| Header | Value | Threat Blocked |
|---|---|---|
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME-type sniffing |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | SSL stripping |
| `Content-Security-Policy` | `default-src 'self'; object-src 'none'; frame-ancestors 'none'` | XSS, data injection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referrer leakage |
| `Cache-Control` | `no-store` | Sensitive data in cache |

**Standards:** OWASP API3:2023 Excessive Data Exposure, CWE-209 Information Exposure Through Error Message.

---

## D — Denial of Service: Availability Controls

### Rate Limiting (Bucket4j — Per-IP Sliding Window)

**What it protects:** The `/login` endpoint and overall API availability.

**Threat mitigated:** Brute-force attacks, credential stuffing, and resource exhaustion.

**Implementation:**
- Bucket4j token-bucket algorithm: **5 requests per minute per source IP** on `/login`.
- The 6th request within the same minute window receives HTTP **429 Too Many Requests**.
- Response headers inform the client: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`.
- IP is extracted from `X-Forwarded-For` (behind the WAF/proxy) with validation against spoofing.
- The WAF layer (OWASP CRS) adds an additional request-rate layer before the application.

### Account Lockout

- After 10 consecutive failed login attempts, the account is temporarily locked for 15 minutes.
- The lockout state is stored in the `users.locked_until` column.
- Lock status is checked inside `authenticate()` — locked accounts receive the same generic 401 response.

**Standards:** OWASP API4:2023 Unrestricted Resource Consumption, CWE-770 Allocation Without Limits.

---

## E — Elevation of Privilege: Authorization Controls

### Role-Based Access Control (Least Privilege)

**What it protects:** Resources and operations that require elevated permissions.

**Threat mitigated:** An authenticated user cannot access other users' data or perform admin operations.

**Implementation:**
- `/api/auth/me` returns only the data of the **currently authenticated caller** — no `userId` parameter that could be tampered with (no IDOR vector).
- Spring Security's security filter chain enforces: `anyRequest().authenticated()` — unauthenticated requests are rejected before reaching any controller.
- The database application user has `SELECT`, `INSERT` privileges only — no `DROP`, `TRUNCATE`, or schema-modification rights.
- The `SecurityContext` is populated from the validated JWT subject claim only — not from any request parameter.
- Strong password policy (enforced at registration) reduces the risk of account takeover via weak credentials.

**Standards:** OWASP API5:2023 Broken Function Level Authorization, CWE-269 Improper Privilege Management, OWASP A01:2021 Broken Access Control.
