# ARCADA — AI Runtime & Trust Evaluator

**Zero-trust security auditor for AI systems, LLM infrastructure, agent frameworks, and supply-chain attacks.**

ARCADA runs 27 specialized security scanners across your codebase, then uses DeepSeek Chat (V3) to synthesize findings into a prioritized report with severity scores, attacker-perspective impact analysis, and actionable remediations. Basic scans use 5 fast scanners for quick results, while deep scans run all 27 scanners for comprehensive analysis.

---

## Features

- **27 scanner modules** with two scan modes:
  - **Basic scan**: 5 fast scanners for quick results (dependency, secrets, code_exec, ai_risks, network)
  - **Deep scan**: All 27 scanners including AST analysis, taint tracking, sandboxing, and dependency source scanning
- **AI-powered reasoning** via DeepSeek Chat (V3) — not just pattern matching; understands compound risks and context
- **Four interfaces**: Web UI, CLI (`arcada audit`), REST API (`POST /audit`), Python SDK
- **Three output formats**: terminal (Rich), JSON, Markdown, SARIF (for IDE/CI integration)
- **CI/CD ready**: `--fail-on critical` exits with code 1 for pipeline gates

---

## Installation

### From source

```bash
git clone https://github.com/ladebw/ARCADA
cd arcada
pip install -e ".[dev]"
```

### Requirements

- Python 3.11+
- A DeepSeek API key

---

## Quick Start

```bash
# Set your API key
export DEEPSEEK_API_KEY=sk-...

# Audit a requirements.txt
arcada audit requirements.txt

# Audit an entire project directory
arcada audit ./my-project/

# Audit with full details
arcada audit app.py --verbose

# Output as Markdown report
arcada audit ./repo --format markdown --output report.md

# CI gate: fail if any high/critical findings
arcada audit requirements.txt --fail-on high
```

---

## CLI Reference

```
arcada audit TARGET [OPTIONS]

TARGET:
  File path      arcada audit requirements.txt
  Directory      arcada audit ./project/
  URL            arcada audit https://raw.githubusercontent.com/.../requirements.txt
  Inline code    arcada audit "import os; os.system('whoami')"

Options:
  -t, --type       Target type: auto|code|dependencies|docker|config|url
  -f, --format     Output format: terminal|json|markdown|sarif
  -o, --output     Write report to file
  -s, --scanners   Comma-separated scanner names (default: all)
  -v, --verbose    Show full finding details in terminal
  --fail-on        Exit code 1 if findings at this severity found (CI use)
  --no-banner      Suppress the ARCADA banner

arcada serve          Start the REST API server
arcada list-scanners  Show all available scanners
```

---

## REST API

Start the server:

```bash
arcada serve --port 8000
# or
uvicorn arcada.api:app --port 8000
```

### POST /audit

```bash
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-arcada-api-key" \
  -d '{
    "target": "requests\nflask\nopenai\nlangchain",
    "target_type": "dependencies",
    "output_format": "json"
  }'
```

**Request body:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | required | Path, URL, or inline content |
| `target_type` | string | `"auto"` | `auto\|code\|dependencies\|docker\|config\|url` |
| `scanners` | list | `[]` (all) | Scanner names to run |
| `output_format` | string | `"json"` | `json\|markdown\|sarif` |

**Response:** Full audit report (see Report Format below).

### GET /health

```json
{"status": "ok", "service": "arcada", "version": "0.1.0"}
```

---

## Python SDK

```python
import asyncio
from arcada.models import AuditRequest
from arcada.orchestrator import Orchestrator
from arcada.report import format_report

async def main():
    orchestrator = Orchestrator()

    report = await orchestrator.audit(AuditRequest(
        target="./my-project/",
        target_type="auto",
        output_format="json",
    ))

    print(f"Risk score: {report.summary.risk_score}/100")
    print(f"Maturity: {report.summary.security_maturity}")

    for finding in report.findings:
        print(f"[{finding.severity}] {finding.title}")
        print(f"  Fix: {finding.fix}")

    # Save as Markdown
    with open("report.md", "w") as f:
        f.write(format_report(report, "markdown"))

asyncio.run(main())
```

---

## Web Interface

ARCADA includes a modern web interface for easy scanning:

1. **Start the server**:
   ```bash
   arcada serve --port 8000
   ```

2. **Open in browser**: http://localhost:8000

3. **Features**:
   - **Basic scan**: Fast 5-scanner analysis (uncheck "Deep scan")
   - **Deep scan**: Comprehensive 27-scanner analysis (check "Deep scan")
   - **Real-time logs**: See scan progress in terminal-style output
   - **Interactive reports**: Click to expand findings, filter by severity
   - **Export options**: Download reports as JSON or PDF

4. **Usage**:
   - Enter a GitHub URL (e.g., `https://github.com/user/repo`)
   - Choose scan type: Basic (fast) or Deep (comprehensive)
   - Click "SCAN" to start analysis
   - View results with severity scores and remediation steps

---

## Scanner Modules

ARCADA includes 27 specialized security scanners. Basic scans run 5 fast scanners (marked with ⚡), while deep scans run all scanners.

### Basic Scan Scanners (5 fast scanners)

| Scanner | What it detects |
|---------|----------------|
| `dependency` ⚡ | CVEs, unpinned deps, typosquatting, AI/LLM packages |
| `secrets` ⚡ | API keys (OpenAI, Anthropic, AWS, GCP...), tokens, private keys, unsafe logging |
| `code_exec` ⚡ | eval/exec, shell injection, pickle, unsafe YAML, template injection, path traversal |
| `ai_risks` ⚡ | Prompt injection, uncontrolled tokens, LLM output exec, RAG injection, model DoS |
| `network` ⚡ | Suspicious endpoints, telemetry sinks, SSL bypass, dynamic URLs, DNS exfil |

### Advanced Scanners (included in deep scans)

| Scanner | What it detects |
|---------|----------------|
| `supply_chain` | Install-time hooks, dynamic imports, CI secret leakage, base64 payloads |
| `agent_risks` | Dangerous tools, MCP risks, infinite loops, missing human-in-the-loop |
| `runtime` | Root execution, privileged containers, Docker socket mounts, exposed DB ports |
| `abuse` | Missing rate limits, no auth, missing per-user quotas, replay attacks |
| `trust_model` | JWT 'none' algo, CORS wildcard, SQL injection, spoofed headers, debug mode |
| `js_ast` | JavaScript AST analysis for obfuscated code, malicious patterns |
| `go_risks` | Go-specific risks: unsafe pointers, cgo issues, race conditions |
| `taint_analysis` | Data flow taint tracking from sources to sensitive sinks |
| `binary` | Binary file analysis, embedded resources, suspicious imports |
| `cicd` | CI/CD pipeline misconfigurations, insecure workflows |
| `crossfile_taint` | Cross-file taint analysis for multi-file vulnerabilities |
| `sandbox` | Sandbox escape detection, isolation bypass attempts |
| `crypto_risks` | Weak cryptography, deprecated algorithms, key management issues |
| `homoglyph` | Homoglyph attacks, lookalike domain/path detection |
| `llm_exfil` | LLM exfiltration techniques, prompt leaking, model stealing |
| `sca` | Software Composition Analysis for dependency vulnerabilities |
| `obfuscation` | Code obfuscation detection, packed malware, anti-analysis |
| `reachability` | Attack surface analysis, reachable code paths |
| `threat_intel` | Threat intelligence integration, known malicious patterns |
| `behavior` | Behavioral analysis, runtime behavior prediction |
| `heuristic_detector` | Heuristic detection of novel attack patterns |
| `model_security` | ML model security: model poisoning, evasion attacks |

---

## Report Format

```json
{
  "target": "./my-project/",
  "target_type": "directory",
  "arcada_version": "0.1.0",
  "findings": [
    {
      "title": "Hardcoded secret: OpenAI API Key",
      "description": "An OpenAI API key was found in source code...",
      "severity": "critical",
      "impact": "Attacker gains full access to your OpenAI account...",
      "evidence": "Line 12: OPENAI_KEY = 'sk-...'",
      "fix": "Remove from code. Rotate the key. Use environment variables.",
      "scanner": "secrets",
      "location": "config.py"
    }
  ],
  "summary": {
    "risk_score": 87,
    "security_maturity": "Unsafe",
    "top_risks": ["..."],
    "immediate_actions": ["..."],
    "total_findings": 23,
    "critical_count": 4,
    "high_count": 11,
    "medium_count": 6,
    "low_count": 2
  }
}
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MODEL_PROVIDER` | No | AI provider: deepseek, openai, anthropic (default: deepseek) |
| `API_KEY` | Yes | API key for your chosen AI provider |
| `BASE_URL` | No | API endpoint (defaults per provider) |
| `DEEPSEEK_MAX_TOKENS` | No | Max tokens for AI response (default: 8192) |
| `ARCADA_API_KEY` | No | Protects the REST API (leave empty to disable) |
| `CORS_ORIGINS` | No | Comma-separated allowed CORS origins |

### AI Provider Configuration

ARCADA supports multiple AI providers for the reasoning engine. Configure in `.env`:

**DeepSeek (default)**
```bash
MODEL_PROVIDER=deepseek
API_KEY=sk-your-deepseek-key
BASE_URL=https://api.deepseek.com/v1
```

**OpenAI**
```bash
MODEL_PROVIDER=openai
API_KEY=sk-your-openai-key
BASE_URL=https://api.openai.com/v1
```

**Claude (Anthropic)**
```bash
MODEL_PROVIDER=anthropic
API_KEY=sk-ant-your-anthropic-key
BASE_URL=https://api.anthropic.com
```

### Code: Provider Switching

Edit `arcada/reasoning.py` to switch providers:

```python
# Line 29-30: Change model and URL based on provider
PROVIDER = os.environ.get("MODEL_PROVIDER", "deepseek")

if PROVIDER == "openai":
    DEEPSEEK_API_URL = f"{os.environ.get('BASE_URL', 'https://api.openai.com/v1')}/chat/completions"
    DEEPSEEK_MODEL = "gpt-4o"
elif PROVIDER == "anthropic":
    DEEPSEEK_API_URL = f"{os.environ.get('BASE_URL', 'https://api.anthropic.com')}/v1/messages"
    DEEPSEEK_MODEL = "claude-sonnet-4-20250514"
else:
    # DeepSeek (default)
    DEEPSEEK_API_URL = f"{os.environ.get('BASE_URL', 'https://api.deepseek.com')}/v1/chat/completions"
    DEEPSEEK_MODEL = "deepseek-chat"
```

> **Tip**: Set `DEEPSEEK_MAX_TOKENS=16000` for large repositories with many findings.

### Threat Intelligence (Optional - DISABLED by default)

To enable threat intelligence features:

```bash
# Enable threat intel
export ARCADA_THREAT_INTEL_ENABLED=true

# Optional: VirusTotal API key for hash reputation checking
# Get free API key at https://www.virustotal.com/gui/join-free
export VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

**Note**: Threat intel features are disabled by default to avoid external API dependencies.
Enable them for enhanced malware detection by setting the above environment variables.

Copy `.env.example` to `.env` and fill in your values.

---

## Running Tests

```bash
pytest tests/ -v
```

Tests cover all 27 scanner modules with real malicious code patterns.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: ARCADA Security Audit
  env:
    DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
  run: |
    pip install arcada
    arcada audit requirements.txt --fail-on high --format json --output arcada-report.json

- name: Upload ARCADA Report
  uses: actions/upload-artifact@v4
  with:
    name: arcada-security-report
    path: arcada-report.json
```

### SARIF upload to GitHub Security tab

```yaml
- name: ARCADA SARIF Audit
  run: arcada audit ./src --format sarif --output arcada.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: arcada.sarif
```

---

## Contributing

ARCADA needs your help. Build a better security scanner for AI-powered applications.

### Why Contribute?

AI security is a growing field with real stakes. Every vulnerability caught protects real applications and real users.

### Where to Contribute

- **New detection modules** — Add scanners for new attack vectors
- **Crawling improvements** — Better repo cloning, file discovery
- **Auth / access control checks** — Detect misconfigured auth in AI apps
- **Performance optimization** — Faster scans, lower memory usage
- **Reporting improvements** — Better JSON, SARIF, integration with security tools

### Quick Start

```bash
# 1. Fork the repo on GitHub

# 2. Clone your fork
git clone https://github.com/ladebw/ARCADA
cd arcada

# 3. Install in development mode
pip install -e ".[dev]"

# 4. Create a feature branch
git checkout -b scanner/my-new-scanner

# 5. Run tests
pytest tests/ -v

# 6. Add your scanner to arcada/scanners/
#    Follow existing scanner patterns in arcada/scanners/base.py

# 7. Submit a PR
```

### Scanner Development

Each scanner inherits from `BaseScanner` and implements the `scan()` method:

```python
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity

class MyScanner(BaseScanner):
    name = "my_scanner"
    
    async def scan(self) -> list[ScannerResult]:
        # Use self.grep(), self.grep_lines(), self.grep_context()
        # Add findings with self.add_finding()
        return self.findings
```

Run specific scanner tests:
```bash
pytest tests/test_scanners.py -v
pytest tests/test_new_scanners.py -v
```

### Code Style

- Use type hints
- Add docstrings to new methods
- Keep scanners focused and modular

---

## License

MIT
