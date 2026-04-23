# 🛡️ Attack-Simulation-FDSI

[![AI-Powered](https://img.shields.io/badge/AI--Powered-STRIDE-blueviolet?style=for-the-badge&logo=openai)](https://openai.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Java](https://img.shields.io/badge/Java-17+-orange?style=for-the-badge&logo=java)](https://www.oracle.com/java/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green?style=for-the-badge&logo=node.js)](https://nodejs.org/)

**Attack-Simulation-FDSI** is a state-of-the-art security testing ecosystem designed to simulate, detect, and analyze vulnerabilities in modern web applications. It combines a powerful Java-based attack engine with an AI-driven "Shift-Left" security layer using the **STRIDE** threat modeling framework.

---

## 🚀 Key Pillars

### 1. ⚡ Dynamic Attack Engine
A comprehensive suite of **10 specialized security tests** that simulate real-world attack vectors:
*   **Injection**: SQL Injection & Cross-Site Scripting (XSS).
*   **Authentication**: Brute Force & Session Fixation.
*   **Configuration**: CORS validation, HTTP Headers, and Path Traversal.
*   **Data Integrity**: JWT validation & Information Leakage.

### 2. 🤖 AI Security Agent
Automated security analysis integrated directly into your development workflow. 
*   **Git Pre-push Hook**: Analyzes your code diffs *before* they leave your machine.
*   **STRIDE Framework**: Powered by Azure OpenAI (GPT-4o), the agent identifies threats across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
*   **Shift-Left Enforcement**: Blocks pushes containing **High-severity** vulnerabilities.

### 3. 📊 Interactive Dashboards
Visualize security posture with zero configuration:
*   **Standalone Dashboard**: Portable HTML report with embedded results.
*   **Real-time Insights**: Breakdown of threats by category and severity.

---

## 🛠️ Installation & Setup

### Prerequisites
*   **Java 17+** (for the Attack Engine)
*   **Node.js 18+** (for the AI Security Agent)
*   **Git**

### 1. Security Hook Installation (Recommended)
Set up the AI Security Agent to protect your repository:
```bash
sh scripts/install-hooks.sh
```

### 2. AI Configuration
Configure your AI provider in the `.env` file:
```env
AI_PROVIDER=azure
AZURE_OPENAI_ENDPOINT=https://your-endpoint.openai.azure.com/
AZURE_OPENAI_API_KEY=your-api-key
AZURE_DEPLOYMENT_NAME=gpt-4o-mini
```

---

## 📖 Usage Guide

### Running Attack Simulations
To execute the full suite of security tests against your target:
```bash
./launch_attack.sh
```

### Accessing the Dashboard
Results are generated in the root directory:
*   **Recommended**: Open `dashboard-standalone.html` in any browser.
*   **Web Server**: Run `./launch_dashboard.sh` to serve `dashboard.html`.

### The AI Security Workflow
The AI Agent works automatically behind the scenes. When you run `git push`:
1.  **Capture**: It identifies code changes in `.java`, `.js`, `.ts`, and `.py` files.
2.  **Analyze**: Diffs are sent to the AI Agent for STRIDE modeling.
3.  **Result**: 
    *   ✅ **Green**: No new vulnerabilities. Push continues.
    *   ⚠️ **Yellow**: Medium/Low threats found. Push allowed with warnings.
    *   ❌ **Red**: High-severity threat detected. **Push BLOCKED**.

> [!TIP]
> Use `DEV_MODE=true git push` or `git push --no-verify` to bypass the security check during rapid development.

---

## 📁 Project Structure

```text
├── attack-engine/          # Core Java simulation engine
├── diff-analyzer/          # Node.js AI analysis module
├── .git-hooks/             # Git hook templates
├── scripts/                # Installation and automation scripts
├── docs/                   # Detailed documentation and schemas
└── dashboard-standalone.html # Portable results viewer
```

---

## 🔍 Documentation Links

*   [**Quick Start Guide**](QUICKSTART.md) - Deep dive into setup.
*   [**STRIDE Mapping**](docs/stride-to-attacks-mapping.md) - How threats map to simulations.
*   [**Attack Details**](ATTACKS_INFO.md) - Technical explanation of each simulation.
*   [**CI/CD Integration**](GITHUB_ACTIONS_INTEGRATION.md) - Running in GitHub Actions.

---

## 🛡️ Security
This tool is for **educational and testing purposes only**. Always ensure you have explicit permission before running security simulations against any target system.