# STRIDE to Attack Mapping

This document defines the mapping between each attack implemented in the Java engine
and its corresponding STRIDE threat category, with justification for each assignment.

## Mapping Table

| Attack Class | Attack Name | STRIDE Category | `stride_category` JSON value |
|---|---|---|---|
| `SqlInjectionAttack` | SQL Injection | Tampering | `Tampering` |
| `BruteForceAttack` | Brute Force | Denial of Service | `DenialOfService` |
| `SessionFixationAttack` | Session Fixation | Spoofing | `Spoofing` |
| `JwtTokenAttack` | JWT Token Security | Spoofing | `Spoofing` |
| `XssAttack` | Cross-Site Scripting (XSS) | Tampering | `Tampering` |
| `PathTraversalAttack` | Path Traversal | Information Disclosure | `InformationDisclosure` |
| `InfoLeakAttack` | Information Leakage | Information Disclosure | `InformationDisclosure` |
| `InsecureHeadersAttack` | Insecure HTTP Headers | Information Disclosure | `InformationDisclosure` |
| `CorsAttack` | CORS Misconfiguration | Spoofing | `Spoofing` |
| `WeakPasswordAttack` | Weak Password Policy | Elevation of Privilege | `ElevationOfPrivilege` |

## Justification

### SqlInjection → Tampering

SQL injection allows an attacker to **modify the intended query** executed against the database.
The attacker alters data flow and logic by injecting unauthorized SQL fragments.
STRIDE definition: *Tampering involves the malicious modification of data.*
SQL injection directly manipulates the data layer, fitting Tampering precisely.

### BruteForce → DenialOfService

A brute-force attack sends a large volume of authentication requests to exhaust server resources
or account lockout mechanisms. Even when no password is cracked, the flood of requests can
**degrade or deny service** to legitimate users.
STRIDE definition: *Denial of Service involves degrading or preventing access to a resource.*

### SessionFixation → Spoofing

Session fixation and related cookie vulnerabilities (missing `Secure`/`HttpOnly` flags) allow an
attacker to **impersonate a legitimate user** by hijacking or stealing their session identifier.
The attacker presents a known session token to gain an identity they do not own.
STRIDE definition: *Spoofing involves pretending to be something or someone other than yourself.*

### JwtToken → Spoofing

Weak JWT validation (accepting tampered payloads or the `none` algorithm) lets an attacker
**forge an identity token** and impersonate any user, including administrators.
STRIDE definition: *Spoofing involves illegitimately claiming an identity.*

### XSS → Tampering

Cross-Site Scripting injects malicious scripts into content **served by a trusted application**,
modifying what legitimate users see and interact with. The attack tampers with the integrity
of the response delivered by the server.
STRIDE definition: *Tampering involves modification of data — in this case, HTML/JS content.*

### PathTraversal → InformationDisclosure

Path traversal reads files outside the application's intended scope (`/etc/passwd`,
`windows/system32/config/sam`, etc.), **exposing confidential system information**.
STRIDE definition: *Information Disclosure involves exposing information to unauthorized parties.*

### InfoLeak → InformationDisclosure

Differing error responses for valid vs. invalid usernames allow an attacker to **enumerate
existing accounts**, leaking information about users in the system.
STRIDE definition: *Information Disclosure — any response that reveals data not meant to be public.*

### InsecureHeaders → InformationDisclosure

Missing security headers (`Content-Security-Policy`, `X-Frame-Options`, etc.) **expose the
application's capabilities and weaknesses** to attackers who probe HTTP responses.
Additionally, absent headers reduce the browser's ability to protect users, indirectly
disclosing exploitable attack surface.
STRIDE definition: *Information Disclosure — revealing implementation details that aid attackers.*

### CORS → Spoofing

A permissive CORS policy (wildcard origins, reflected origins, `null` origin) allows an
attacker's page to **impersonate a legitimate cross-origin request** on behalf of an
authenticated user, effectively spoofing the origin of requests.
STRIDE definition: *Spoofing — making a request appear to originate from a trusted source.*

### WeakPassword → ElevationOfPrivilege

Accepting weak passwords during registration means that attackers can **easily obtain
legitimate credentials** and gain access to user accounts, potentially including
accounts with elevated roles.
STRIDE definition: *Elevation of Privilege — gaining capabilities without proper authorization.*

## STRIDE Categories Reference

| Category | Abbreviation | Description |
|---|---|---|
| Spoofing | S | Illegitimately assuming the identity of another user or process |
| Tampering | T | Malicious modification of data in storage or transit |
| Repudiation | R | Claiming not to have performed an action that was actually performed |
| Information Disclosure | I | Exposing information to parties not authorized to see it |
| Denial of Service | D | Preventing legitimate users from accessing a service |
| Elevation of Privilege | E | Gaining capabilities not properly authorized |
