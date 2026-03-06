# clawsan

**Security scanner for OpenClaw / Claude AI agent installations**

[![CI](https://github.com/tttturtle-russ/clawsan/actions/workflows/ci.yml/badge.svg)](https://github.com/tttturtle-russ/clawsan/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/tttturtle-russ/clawsan)](https://goreportcard.com/report/github.com/tttturtle-russ/clawsan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/tttturtle-russ/clawsan)](https://github.com/tttturtle-russ/clawsan/releases/latest)

clawsan audits your OpenClaw installation against **33 security signals** mapped to the [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and CWE. It gives you a security score, grade, and actionable remediation — plus SARIF output for GitHub's Security tab.

```
 ██████╗██╗      █████╗ ██╗    ██╗███████╗ █████╗ ███╗   ██╗
██╔════╝██║     ██╔══██╗██║    ██║██╔════╝██╔══██╗████╗  ██║
██║     ██║     ███████║██║ █╗ ██║███████╗███████║██╔██╗ ██║
██║     ██║     ██╔══██║██║███╗██║╚════██║██╔══██║██║╚██╗██║
╚██████╗███████╗██║  ██║╚███╔███╔╝███████║██║  ██║██║ ╚████║
 ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝

  OpenClaw Security Scanner v1.0.0
  Scanning: ~/.openclaw/
  Started:  2025-01-01T00:00:00Z
──────────────────────────────────────────────────────────────────────
...
──────────────────────────────────────────────────────────────────────

  Security Score: 72/100  Grade: C

  Checks run:  33
  Duration:    142ms

  Findings by severity:
  CRITICAL   1  █
  HIGH       3  ███
  MEDIUM     4  ████
  LOW        2  ██
```

---

## Installation

**Go (any platform):**
```bash
go install github.com/tttturtle-russ/clawsan@latest
```

**Pre-built binaries** — download from [Releases](https://github.com/tttturtle-russ/clawsan/releases/latest) (Linux, macOS, Windows — amd64 + arm64).

**Build from source:**
```bash
git clone https://github.com/tttturtle-russ/clawsan
cd clawsan
make install
```

---

## Quick Start

```bash
# Scan default OpenClaw location (~/.openclaw/)
clawsan scan

# Scan a specific path
clawsan scan /path/to/openclaw

# CI mode: only report HIGH and above, exit 1 if found
clawsan scan --min-severity HIGH --quiet

# Export SARIF for GitHub Security tab
clawsan scan --output results.sarif

# Export JSON for custom tooling
clawsan scan --output results.json

# Print version
clawsan --version
```

---

## CLI Reference

```
clawsan scan [path] [flags]

Flags:
  --path string          path to OpenClaw installation (default ~/.openclaw/)
  --min-severity string  minimum severity to report and trigger exit 1 (default "LOW")
                         values: LOW | MEDIUM | HIGH | CRITICAL
  --quiet                suppress all output except errors (useful in CI)
  --no-color             disable ANSI color output
  --json                 print JSON to stdout
  --output FILE          write output to file (.sarif or .json extension)

Exit codes:
  0   clean — no findings at or above --min-severity
  1   findings detected at or above --min-severity
  2   scanner error (path not found, parse failure, etc.)
```

---

## GitHub Actions Integration

### Basic CI

```yaml
- name: Scan OpenClaw installation
  run: |
    go install github.com/tttturtle-russ/clawsan@latest
    clawsan scan --min-severity HIGH --quiet
```

### Upload to GitHub Security tab (SARIF)

```yaml
permissions:
  security-events: write

- name: Run clawsan
  run: clawsan scan --output results.sarif || true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

Findings appear directly in the **Security → Code scanning** tab with severity, OWASP tag, and remediation guidance.

---

## Security Checks (33 signals)

### Supply Chain — `SUPPLY_CHAIN-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| SUPPLY_CHAIN-001 | HIGH | Missing Skill Hash | LLM03:2025 | CWE-494 |
| SUPPLY_CHAIN-002 | CRITICAL | Malicious Skill Reputation | LLM03:2025 | CWE-829 |
| SUPPLY_CHAIN-002B | HIGH | Unverified Skill Reputation | LLM03:2025 | CWE-829 |
| SUPPLY_CHAIN-003 | MEDIUM | Unofficial Skill Source | LLM03:2025 | CWE-494 |
| SUPPLY_CHAIN-004 | MEDIUM | Dangerous Skill Name Pattern | LLM03:2025 | CWE-829 |
| SUPPLY_CHAIN-005 | HIGH | Skill Hash Mismatch | LLM03:2025 | CWE-494 |
| SUPPLY_CHAIN-006 | HIGH | Skill Metadata Tampering | LLM03:2025 | CWE-494 |
| SUPPLY_CHAIN-006B | MEDIUM | Skill Metadata Inconsistency | LLM03:2025 | CWE-494 |

### Configuration — `CONFIG-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| CONFIG-001 | HIGH | Global Permission Skip | LLM06:2025 | CWE-269 |
| CONFIG-002 | MEDIUM | Open DM Policy | LLM06:2025 | CWE-284 |
| CONFIG-003 | HIGH | Broad Workspace Access | LLM06:2025 | CWE-732 |
| CONFIG-004 | HIGH | Plaintext API Key | LLM02:2025 | CWE-312 |
| CONFIG-005 | MEDIUM | Public Network Binding | LLM06:2025 | CWE-284 |
| CONFIG-006 | HIGH | Gateway Auth Disabled | LLM06:2025 | CWE-306 |
| CONFIG-007 | HIGH | Tunnel Auth Disabled | LLM06:2025 | CWE-306 |

### Discovery — `DISCOVERY-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| DISCOVERY-001 | CRITICAL | AGENTS.md Prompt Injection | LLM01:2025 | CWE-74 |
| DISCOVERY-002 | HIGH | Dangerous Tool Definition | LLM06:2025 | CWE-78 |
| DISCOVERY-003 | HIGH | Shadow Background Task | LLM01:2025 | CWE-913 |
| DISCOVERY-004 | HIGH | Tool Description Poisoning | LLM01:2025 | CWE-74 |
| DISCOVERY-005 | MEDIUM | Homoglyph Tool Name | LLM01:2025 | CWE-116 |
| DISCOVERY-006 | HIGH | Sensitive Path Tool Access | LLM02:2025 | CWE-22 |

### Runtime — `RUNTIME-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| RUNTIME-001 | HIGH | Forbidden Zone Access | LLM06:2025 | CWE-732 |
| RUNTIME-002 | HIGH | High-Risk Mobile Permission | LLM06:2025 | CWE-269 |
| RUNTIME-003 | HIGH | Browser Debug Port Exposed | LLM06:2025 | CWE-489 |
| RUNTIME-004 | HIGH | Unauthenticated Webhook | LLM06:2025 | CWE-306 |
| RUNTIME-005 | HIGH | Wildcard User Allowlist | LLM06:2025 | CWE-284 |
| RUNTIME-006 | MEDIUM | Excessive Session Sharing | LLM06:2025 | CWE-664 |

### Skill Content — `SKILL_CONTENT-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| SKILL_CONTENT-001 | CRITICAL | Prompt Injection in Skill | LLM01:2025 | CWE-74 |
| SKILL_CONTENT-002 | HIGH | Skill Exfiltration Pattern | LLM02:2025 | CWE-200 |
| SKILL_CONTENT-003 through 023 | MEDIUM–CRITICAL | Various skill content signals | LLM01–LLM06 | Various |

### Skill Identity — `SKILL_IDENTITY-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| SKILL_IDENTITY-001 | HIGH | Impersonation Pattern | LLM01:2025 | CWE-290 |
| SKILL_IDENTITY-002 through 007 | MEDIUM–HIGH | Identity and trust signals | LLM01–LLM04 | Various |

### Skill Composite — `SKILL_COMPOSITE-*`

Cross-skill signals that detect dangerous combinations across installed skills.

---

## Scoring

| Score | Grade | Meaning |
|---|---|---|
| 90–100 | **A** | Excellent — no significant findings |
| 75–89 | **B** | Good — minor issues present |
| 60–74 | **C** | Fair — medium risks detected |
| 40–59 | **D** | Poor — high risks detected |
| 0–39 | **F** | Critical — immediate action required |

**Deductions:** CRITICAL −25 · HIGH −10 · MEDIUM −5 · LOW −1

---

## Output Formats

| Format | Flag | Use case |
|---|---|---|
| Terminal (colored) | default | Interactive use |
| JSON | `--json` or `--output file.json` | Custom tooling, SIEM ingestion |
| SARIF 2.1.0 | `--output file.sarif` | GitHub Security tab, VS Code |

The SARIF output includes `security-severity` numeric scores (9.8 / 7.5 / 5.0 / 2.0) for GitHub Advanced Security triaging.

---

## Development

```bash
# Run tests
make test

# Build with version injection
make build

# Lint
make lint

# Coverage report
make coverage
```

Tests that hit the real `https://clawhub.ai` endpoint are tagged as integration tests and run as part of the standard suite.

---

## Architecture

```
clawsan/
├── cmd/            CLI (cobra): scan subcommand, flags, version
├── internal/
│   ├── api/        ClawHub HTTP client (real endpoint, no mocks)
│   ├── detectors/  7 detector packages × 33 signals
│   ├── output/     terminal (color), JSON, SARIF 2.1.0
│   ├── parser/     config.json / workspace / MCP tool / skill file parsers
│   ├── scoring/    score + grade calculation
│   └── types/      Finding, ScanResult, OWASP/CWE constants
└── main.go
```

Each detector is independently testable and returns `[]types.Finding`. The orchestrator in `internal/scanner` wires them together and assembles the `ScanResult`.

---

## Contributing

1. Fork and branch from `main`
2. `go test ./...` must pass
3. New signals need: ID, Title, Description, Remediation, Severity, OWASP, CWE
4. Open a PR — CI runs tests, vet, and a self-scan SARIF upload

---

## License

[MIT](LICENSE) © 2025 tttturtle-russ
