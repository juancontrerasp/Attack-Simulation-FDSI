# 🛡️ Attack-Simulation-FDSI

[![AI-Powered](https://img.shields.io/badge/AI--Powered-STRIDE-blueviolet?style=for-the-badge&logo=openai)](https://openai.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Java](https://img.shields.io/badge/Java-17+-orange?style=for-the-badge&logo=java)](https://www.oracle.com/java/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green?style=for-the-badge&logo=node.js)](https://nodejs.org/)
[![Windows Ready](https://img.shields.io/badge/Windows-PowerShell%20ready-0078D4?style=for-the-badge&logo=powershell)](https://learn.microsoft.com/en-us/powershell/)

**Attack-Simulation-FDSI** is a security testing and threat-modeling ecosystem that combines a Java attack engine with an AI-driven STRIDE analysis layer. It is designed to accompany the software lifecycle from architecture and design, through implementation and testing, all the way to continuous regression enforcement in CI/CD.

The repository provides three connected capabilities:

1. A **dynamic attack engine** that simulates common web application attacks.
2. A **continuous STRIDE agent** that reads code, diagrams, OpenAPI specs, and images.
3. A **metrics and reporting layer** that compares automated analysis with manual ground truth.

---

## Contents

- [What this repository solves](#what-this-repository-solves)
- [Security value](#security-value)
- [Architecture](#architecture)
- [Threat modeling flow](#threat-modeling-flow)
- [Technologies](#technologies)
- [Repository structure](#repository-structure)
- [Core components](#core-components)
- [Controls and threat mapping](#controls-and-threat-mapping)
- [Outputs and artifacts](#outputs-and-artifacts)
- [Commands](#commands)
- [Windows demo flow](#windows-demo-flow)
- [Documentation map](#documentation-map)
- [Troubleshooting](#troubleshooting)
- [License and scope](#license-and-scope)

---

## What this repository solves

Traditional threat modeling is often manual, point-in-time, and detached from development. This repo addresses that gap by:

- Inferring architecture directly from source code and design artifacts.
- Mapping findings to STRIDE categories with evidence.
- Running dynamic checks against a live target.
- Persisting threat state across runs to detect reopened regressions.
- Generating paper-ready metrics and comparison tables.

In practice, the repo turns threat modeling into a **continuous security control** instead of a one-off diagram exercise.

---

## Security value

This project contributes to security in four ways:

### 1. It models threats continuously
The STRIDE agent does not rely on a single diagram. It can analyze:

- Java, JavaScript, TypeScript, and Python code
- Mermaid and PlantUML diagrams
- OpenAPI / Swagger specifications
- Markdown documentation
- Architecture images

That means the threat model can move with the implementation instead of becoming stale after the first design review.

### 2. It enforces security gates
The repository keeps a persistent threat registry in [security/threat-registry.json](security/threat-registry.json). If a previously mitigated threat appears again, the baseline gate can fail the pipeline.

### 3. It connects static and dynamic validation
Static STRIDE analysis is complemented by Java-based attack simulations, so findings are not only inferred but also validated on a live target when possible.

### 4. It produces evidence for reporting and research
The repo generates JSON, HTML, LaTeX, dashboards, and comparison tables that can be used in papers, demos, and audits.

---

## Architecture

The repository is organized around four layers:

| Layer | Purpose | Main artifacts |
|---|---|---|
| Input layer | Collect code, diagrams, APIs, and images | `attack-engine/`, `reference-architecture/`, docs |
| Analysis layer | Build STRIDE context and infer threats | `stride-agent/` |
| Validation layer | Run attacks and confirm findings | `launch_attack.ps1`, `run-full-analysis.ps1`, Unix compatibility scripts |
| Reporting layer | Consolidate, compare, and publish results | `combined-report.json`, `metrics-report.html`, dashboards |

### End-to-end flow

```text
Artifact(s) from repo
   -> STRIDE agent infers architecture and threats
   -> Recommendations engine links controls to threats
   -> Threat lifecycle registry stores status across runs
   -> Java attack engine validates selected threats dynamically
   -> Combined report merges static + dynamic evidence
   -> Metrics compare manual vs automated analysis
   -> Dashboard / HTML / LaTeX outputs for demo and paper
```

---

## Threat modeling flow

The project models threats across the software lifecycle:

| SDLC stage | What the repo does | Example outputs |
|---|---|---|
| Design | Reads Mermaid, OpenAPI, Markdown, and architecture images | `secure-architecture.mmd`, `secure-api.yaml` |
| Implementation | Analyzes code structure and identifies risky patterns | `threats-output.json` |
| Testing | Runs dynamic attack scenarios against a live target | `results.json` |
| Continuous delivery | Tracks open, mitigated, and reopened threats | `security/threat-registry.json` |
| Validation | Compares manual and automated results | `metrics-report.json`, `metrics-report.html` |

This is the central idea of the repo: **security is not a separate phase, it is a continuous loop**.

---

## Technologies

| Technology | Role |
|---|---|
| Java 17+ | Attack engine and secure reference application |
| Node.js 18+ | STRIDE analysis, comparison, recommendation engine |
| PowerShell | Windows-native demo and pipeline commands |
| Bash | Linux/macOS execution scripts |
| Azure OpenAI | Production STRIDE analysis provider |
| Ollama | Local/offline analysis provider |
| Python 3 | Dashboard generation helper |
| Mermaid / OpenAPI | Design artifacts that can be analyzed directly |
| LaTeX | Paper-ready comparison tables |
| Chart.js | Embedded dashboard visualizations |

---

## Repository structure

```text
Attack-Simulation-FDSI/
├── attack-engine/               # Java attack simulation engine
├── stride-agent/                # STRIDE analyzer, parsers, cache, providers
├── reference-architecture/      # Secure reference app + docs + comparison assets
├── docs/                        # Metrics, mappings, schemas, control catalog
├── security/                    # Threat registry, baseline, trend tracking
├── threat-models/               # Manual baseline analyses for comparison
├── scripts/                     # Report consolidation and helper scripts
├── dashboard.html               # Interactive dashboard template
├── dashboard-standalone.html    # Offline dashboard generated from results
├── launch_attack.ps1            # Windows attack launcher
├── run-full-analysis.ps1        # Windows full pipeline
├── demo-preflight.ps1           # Demo readiness check
├── launch_attack.sh             # Unix/macOS compatibility attack launcher
└── run-full-analysis.sh         # Unix/macOS compatibility full pipeline
```

---

## Core components

### Attack engine

The Java engine in [attack-engine/AttackEngine.java](attack-engine/AttackEngine.java) runs 10 attack classes:

| Attack class | STRIDE category | Purpose |
|---|---|---|
| `SqlInjectionAttack` | Tampering | Detect SQL injection exposure |
| `XssAttack` | Tampering | Detect reflected XSS |
| `BruteForceAttack` | DenialOfService | Detect login abuse / rate-limit gaps |
| `SessionFixationAttack` | Spoofing | Detect session fixation risks |
| `JwtTokenAttack` | Spoofing | Detect weak JWT validation |
| `PathTraversalAttack` | InformationDisclosure | Detect file path exposure |
| `InfoLeakAttack` | InformationDisclosure | Detect user enumeration / leakage |
| `InsecureHeadersAttack` | InformationDisclosure | Detect missing security headers |
| `CorsAttack` | Spoofing | Detect CORS misconfiguration |
| `WeakPasswordAttack` | ElevationOfPrivilege | Detect weak credential policy |

The mapping is documented in [docs/stride-to-attacks-mapping.md](docs/stride-to-attacks-mapping.md).

### STRIDE agent

The Node.js agent in [stride-agent/index.js](stride-agent/index.js) orchestrates analysis and outputs `threats-output.json`.

It includes:

- [stride-agent/repo-reader/index.js](stride-agent/repo-reader/index.js)
- [stride-agent/diagram-parser/index.js](stride-agent/diagram-parser/index.js)
- [stride-agent/openapi-parser/index.js](stride-agent/openapi-parser/index.js)
- [stride-agent/image-processor/index.js](stride-agent/image-processor/index.js)
- [stride-agent/analyzer/prompt.js](stride-agent/analyzer/prompt.js)
- [stride-agent/analyzer/validator.js](stride-agent/analyzer/validator.js)
- [stride-agent/cache/index.js](stride-agent/cache/index.js)
- [stride-agent/ai-provider/azure.js](stride-agent/ai-provider/azure.js)
- [stride-agent/ai-provider/ollama.js](stride-agent/ai-provider/ollama.js)

### Recommendation engine

The catalog in [docs/controls-catalog.md](docs/controls-catalog.md) links STRIDE findings to concrete controls, standards, and implementation hints.

### Reporting and metrics

The comparison pipeline produces:

- [combined-report.json](combined-report.json)
- [metrics-report.json](metrics-report.json)
- [metrics-report.html](metrics-report.html)
- [docs/results-table.tex](docs/results-table.tex)
- [docs/results-table-final.tex](docs/results-table-final.tex)

---

## Controls and threat mapping

### STRIDE control summary

| STRIDE category | Main control focus | Reference |
|---|---|---|
| Spoofing | JWT pinning, session regeneration, MFA / lockout | [docs/controls-catalog.md](docs/controls-catalog.md) |
| Tampering | Prepared statements, output encoding, canonical paths | [docs/controls-catalog.md](docs/controls-catalog.md) |
| Repudiation | Structured audit logging and event signing | [docs/controls-catalog.md](docs/controls-catalog.md) |
| Information Disclosure | Security headers, generic errors, sensitive field filtering | [docs/controls-catalog.md](docs/controls-catalog.md) |
| Denial of Service | Rate limiting, request size limits, circuit breakers | [docs/controls-catalog.md](docs/controls-catalog.md) |
| Elevation of Privilege | RBAC, ownership checks, strong password policy | [docs/controls-catalog.md](docs/controls-catalog.md) |

### Secure reference architecture

The secure benchmark lives in `reference-architecture/` and is documented in:

- [reference-architecture/SECURE-DESIGN.md](reference-architecture/SECURE-DESIGN.md)
- [reference-architecture/secure-architecture.mmd](reference-architecture/secure-architecture.mmd)
- [reference-architecture/secure-api.yaml](reference-architecture/secure-api.yaml)

That architecture is intentionally designed to mitigate the same STRIDE threats the attack engine can detect:

| Control | Mitigates |
|---|---|
| JWT RS256 with signature verification | Spoofing |
| Prepared statements | Tampering |
| Immutable audit logs | Repudiation |
| Generic error messages | Information Disclosure |
| Bucket4j rate limiting | Denial of Service |
| RBAC and least privilege | Elevation of Privilege |

---

## Outputs and artifacts

Running the repo produces several artifacts:

| Artifact | Purpose |
|---|---|
| `threats-output.json` | Static STRIDE analysis output |
| `results.json` | Dynamic attack engine results |
| `combined-report.json` | Merged static + dynamic report |
| `dashboard-standalone.html` | Offline dashboard |
| `metrics-report.json` | Quantitative comparison output |
| `metrics-report.html` | Interactive comparison report |
| `security/threat-registry.json` | Persistent lifecycle registry |
| `security/trend-report.json` | Historical trend data |
| `demo-preflight-report.json` | Demo readiness summary |

---

## Commands

### Static analysis

```bash
npm run stride:analyze
```

### Dynamic simulation

Unix / Linux / macOS:

```bash
./launch_attack.sh
```

Windows equivalent:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\launch_attack.ps1 -Attacks SqlInjection -Target http://localhost:8080
```

### Consolidate reports

```bash
node scripts/combine-results.js
```

### Generate metrics and paper tables

```bash
node compare.js
```

### Full pipeline

Unix / Linux / macOS:

```bash
./run-full-analysis.sh
```

Windows / PowerShell demo-safe mode:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipDynamic -SkipRecommendations -SkipBaseline
```

Windows security gate mode:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipDynamic -SkipRecommendations
```

### Demo readiness check

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demo-preflight.ps1
```

---

## Windows demo flow

If you are presenting on Windows, use this order:

1. Validate environment:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\demo-preflight.ps1
   ```
2. Show static STRIDE analysis:
   ```powershell
   npm run stride:analyze
   ```
   Open `threats-output.json`.
3. Show a live attack simulation:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\launch_attack.ps1 -Attacks SqlInjection -Target http://localhost:8080
   ```
   Open `results.json` and `dashboard-standalone.html`.
4. Merge results:
   ```powershell
   node scripts/combine-results.js
   ```
   Open `combined-report.json`.
5. Show comparison metrics:
   ```powershell
   node compare.js
   ```
   Open `metrics-report.html`, `metrics-report.json`, and `docs/results-table.tex`.
6. Show the end-to-end pipeline:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipDynamic -SkipRecommendations -SkipBaseline
   ```
   Open `security/threat-registry.json` and `security/trend-report.json`.
7. Optionally show the security gate failure:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipDynamic -SkipRecommendations
   ```

If you want URL-based viewing, start the local server with `python serve_dashboard.py` and open `http://localhost:8000/dashboard.html`.

### What to show on screen

- `threats-output.json`
- `results.json`
- `combined-report.json`
- `dashboard-standalone.html`
- `metrics-report.html`
- `security/threat-registry.json`
- `security/trend-report.json`

---

## Security lifecycle and continuous delivery

This repository does not just detect issues once. It tracks threat state over time:

- **open**: threat detected and unresolved
- **mitigated**: threat not found in the latest analysis
- **reopened**: previously mitigated threat found again
- **accepted**: threat formally acknowledged and baselined

That lifecycle is what lets the repo accompany the project from design to development and continuously through delivery.

The model is intentionally continuous:

| Phase | How the repo helps |
|---|---|
| Design | Analyze Mermaid, OpenAPI, Markdown, and architecture images |
| Development | Analyze source code and detect risky patterns |
| Validation | Run Java attack simulations and confirm findings |
| Delivery | Fail the baseline when a reopened threat appears |
| Maintenance | Keep trend reports and control catalogs updated |

---

## Documentation map

These are the documentation files that actually exist in the repo:

- [docs/attack-config-schema.md](docs/attack-config-schema.md)
- [docs/combined-report-schema.json](docs/combined-report-schema.json)
- [docs/controls-catalog.md](docs/controls-catalog.md)
- [docs/design-feedback-schema.json](docs/design-feedback-schema.json)
- [docs/metrics-formulas.md](docs/metrics-formulas.md)
- [docs/results-table.tex](docs/results-table.tex)
- [docs/results-table-final.tex](docs/results-table-final.tex)
- [docs/stride-to-attacks-mapping.md](docs/stride-to-attacks-mapping.md)
- [docs/threats-output-schema.json](docs/threats-output-schema.json)
- [reference-architecture/SECURE-DESIGN.md](reference-architecture/SECURE-DESIGN.md)
- [reference-architecture/secure-architecture.mmd](reference-architecture/secure-architecture.mmd)
- [reference-architecture/secure-api.yaml](reference-architecture/secure-api.yaml)
- [DEMO_5MIN_WINDOWS.md](DEMO_5MIN_WINDOWS.md)

The old broken links to missing files have been removed.

---

## Troubleshooting

### `run-full-analysis.sh` does not work on Windows

Use the PowerShell version instead:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1
```

### The target is not available

The demo pipeline can still run in safe mode, but dynamic validation may report that the system is unavailable.

### Baseline check fails

That is expected when a threat reappears in [security/threat-registry.json](security/threat-registry.json). It is a security gate, not a bug.

### Azure OpenAI is not configured

Copy `.env.example` to `.env` and fill in the Azure values, or set `DEV_MODE=true` for offline/mock analysis.

---

## License and scope

This tool is intended for **educational and authorized security testing only**. Always ensure you have explicit permission before running simulations against any target system.

License: MIT.
