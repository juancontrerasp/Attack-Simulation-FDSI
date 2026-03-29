# Attack-Simulation-FDSI

Security attack simulation tool for testing web application vulnerabilities.

## Quick Start

```bash
# Run attack simulation
./launch_attack.sh

# View results
# Option 1: Open dashboard-standalone.html in browser (recommended)
# Option 2: ./launch_dashboard.sh (starts web server)
```

## Features

- **10 Comprehensive Security Tests:**
  - SQL Injection testing
  - Brute force attack simulation
  - Cross-Site Scripting (XSS) detection
  - JWT token security validation
  - Session fixation testing
  - Path traversal detection
  - CORS policy validation
  - HTTP security headers check
  - Weak password policy testing
  - Information leakage detection
- Interactive dashboard with results
- JSON output for automation
- Self-contained dashboard (no CORS issues)

## Documentation

- [Quick Start Guide](QUICKSTART.md)
- [Attack Details](ATTACKS_INFO.md)
- [Dashboard Guide](DASHBOARD_README.md)
- [GitHub Actions Integration](GITHUB_ACTIONS_INTEGRATION.md)

## Dashboard Options

After running attacks, you get two dashboard versions:

1. **dashboard-standalone.html** ⭐ (Recommended)
   - Self-contained with embedded data
   - Open directly in browser
   - No web server needed
   - Perfect for viewing GitHub Actions results

2. **dashboard.html** (Original)
   - Requires web server to load data
   - Use `./launch_dashboard.sh`
   - Good for live development

## GitHub Actions Integration

See [AWS_Login_Service-TDSE](https://github.com/juancontrerasp/AWS_Login_Service-TDSE) for a complete example of automated threat modeling in CI/CD pipelines.