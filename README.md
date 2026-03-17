# clawsan

**Security scanner for OpenClaw / Claude AI agent installations**

[![CI](https://github.com/tttturtle-russ/clawsan/actions/workflows/ci.yml/badge.svg)](https://github.com/tttturtle-russ/clawsan/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/tttturtle-russ/clawsan)](https://goreportcard.com/report/github.com/tttturtle-russ/clawsan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/tttturtle-russ/clawsan)](https://github.com/tttturtle-russ/clawsan/releases/latest)

clawsan audits your OpenClaw installation against **56 security signals** mapped to the [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and CWE. It gives you a security score, grade, and actionable remediation — plus SARIF output for GitHub's Security tab.

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

  Checks run:  56
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

## Security Checks (56 signals)

### Access Control — `AC-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| AC-001 | HIGH | Channel has DM policy set to 'open' | LLM06:2025 | CWE-284: Improper Access Control |
| AC-002 | HIGH | Channel has group policy set to 'open' | LLM06:2025 | CWE-284: Improper Access Control |
| AC-003 | HIGH | Channel allowFrom contains wildcard '*' | LLM06:2025 | CWE-284: Improper Access Control |
| AC-003B | HIGH | Channel allowlist contains wildcard '*' | LLM06:2025 | CWE-284: Improper Access Control |
| AC-004 | HIGH | Execution sandbox is disabled or weakened | LLM06:2025 | CWE-693: Protection Mechanism Failure |
| AC-005 | CRITICAL | ACP auto-approval is set to 'all' (GHSA-7jx5) | LLM06:2025 | CWE-306: Missing Authentication for Critical Function |
| AC-006 | MEDIUM | Session DM scope is global across multiple channels | LLM01:2025 | CWE-668: Exposure of Resource to Wrong Sphere |

### Configuration — `CONFIG-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| CONFIG-001 | CRITICAL | Control UI device authentication is disabled | LLM06:2025 | CWE-306: Missing Authentication for Critical Function |
| CONFIG-002 | CRITICAL | Host header origin fallback is enabled (DNS rebinding risk) | LLM06:2025 | CWE-346: Origin Validation Error |
| CONFIG-003 | HIGH | Agent workspace is set to an overly broad path | LLM06:2025 | CWE-732: Incorrect Permission Assignment for Critical Resource |
| CONFIG-004 | HIGH | Gateway auth token is stored as plaintext in config | LLM02:2025 | CWE-312: Cleartext Storage of Sensitive Information |
| CONFIG-005 | HIGH | OpenClaw gateway is exposed to the local network (bind=lan) | LLM06:2025 | CWE-284: Improper Access Control |
| CONFIG-006 | CRITICAL | Gateway has no authentication configured | LLM06:2025 | CWE-306: Missing Authentication for Critical Function |
| CONFIG-007 | CRITICAL | Tailscale funnel is exposing the gateway to the public internet | LLM06:2025 | CWE-284: Improper Access Control |
| CONFIG-008 | CRITICAL | Control UI allows requests from any origin (wildcard CORS) | LLM06:2025 | CWE-346: Origin Validation Error |
| CONFIG-009 | MEDIUM | Sensitive data redaction in logs is disabled | LLM02:2025 | CWE-532: Insertion of Sensitive Information into Log File |
| CONFIG-010 | CRITICAL | Elevated tools are allowed from any source (wildcard allowFrom) | LLM06:2025 | CWE-250: Execution with Unnecessary Privileges |
| CONFIG-011 | MEDIUM | mDNS discovery is set to full mode (broadcasts presence on LAN) | LLM06:2025 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| CONFIG-012 | HIGH | Real IP fallback is enabled (IP spoofing risk) | LLM06:2025 | CWE-807: Reliance on Untrusted Inputs in a Security Decision |

### Credential Storage — `CRED-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| CRED-001 | HIGH | OpenClaw directory has insecure permissions | LLM02:2025 | CWE-732: Incorrect Permission Assignment for Critical Resource |
| CRED-002 | CRITICAL | openclaw.json has insecure permissions | LLM02:2025 | CWE-732: Incorrect Permission Assignment for Critical Resource |
| CRED-007 | CRITICAL | API key pattern found in workspace memory file | LLM02:2025 | CWE-312: Cleartext Storage of Sensitive Information |

### Discovery — `DISCOVERY-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| DISCOVERY-001 | CRITICAL | AGENTS.md Prompt Injection | LLM01:2025 | CWE-74: Improper Neutralization of Special Elements |
| DISCOVERY-002 | HIGH | Dangerous Tool Definition | LLM06:2025 | CWE-78: OS Command Injection |
| DISCOVERY-003 | HIGH | Shadow Background Task | LLM01:2025 | CWE-913: Improper Control of Dynamically-Managed Code Resources |
| DISCOVERY-004 | HIGH | Tool Description Poisoning | LLM01:2025 | CWE-74: Improper Neutralization of Special Elements |
| DISCOVERY-005 | MEDIUM | Homoglyph Tool Name | LLM01:2025 | CWE-116: Improper Encoding or Escaping of Output |
| DISCOVERY-006 | HIGH | Sensitive Path Tool Access | LLM02:2025 | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |

### Memory Poisoning — `MEM-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| MEM-001 | CRITICAL | Prompt injection pattern detected in soul/memory file | LLM01:2025 | CWE-77: Improper Neutralization of Special Elements used in a Command |
| MEM-003 | CRITICAL | Suspicious base64-encoded payload in soul/memory file | LLM01:2025 | CWE-506: Embedded Malicious Code |
| MEM-004 | CRITICAL | Known malicious domain found in soul/memory file | LLM04:2025 | CWE-610: Externally Controlled Reference to a Resource in Another Sphere |
| MEM-005 | MEDIUM | Memory file has insecure permissions | LLM02:2025 | CWE-732: Incorrect Permission Assignment for Critical Resource |

### QClaw Integration — `QCLAW-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| QCLAW-001 | CRITICAL | QClaw JWT token stored as plaintext in openclaw.json | LLM02:2025 | CWE-312: Cleartext Storage of Sensitive Information |
| QCLAW-002 | CRITICAL | QClaw channel token stored as plaintext in openclaw.json | LLM02:2025 | CWE-312: Cleartext Storage of Sensitive Information |
| QCLAW-003 | CRITICAL | QClaw API key stored as plaintext in openclaw.json | LLM02:2025 | CWE-312: Cleartext Storage of Sensitive Information |

### ArkClaw Integration — `ARKCLAW-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| ARKCLAW-001 | CRITICAL | ArkClaw Volcengine API key stored as plaintext in openclaw.json | LLM02:2025 | CWE-312: Cleartext Storage of Sensitive Information |

### Runtime — `RUNTIME-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| RUNTIME-001 | CRITICAL | Tool or workspace file references forbidden credential storage | LLM06:2025 | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| RUNTIME-002 | HIGH | Dangerous mobile permission detected | LLM06:2025 | CWE-250: Execution with Unnecessary Privileges |
| RUNTIME-003 | HIGH | Browser CDP debug port exposed | LLM06:2025 | CWE-489: Active Debug Code |
| RUNTIME-004 | HIGH | Webhook gateway is exposed without authentication | LLM06:2025 | CWE-306: Missing Authentication for Critical Function |

### Supply Chain — `SUPPLY_CHAIN-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| SUPPLY_CHAIN-002 | CRITICAL | Skill is flagged as malicious on ClawHub | LLM03:2025 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| SUPPLY_CHAIN-002B | HIGH | Skill is flagged as suspicious on ClawHub | LLM03:2025 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| SUPPLY_CHAIN-004 | HIGH | Skill has a high-risk name suggesting elevated system access | LLM03:2025 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| SUPPLY_CHAIN-006 | MEDIUM | Skill has no SKILL.md | LLM03:2025 | CWE-1104: Use of Unmaintained Third-Party Components |
| SUPPLY_CHAIN-006B | MEDIUM | Skill has a suspiciously thin SKILL.md | LLM03:2025 | CWE-1104: Use of Unmaintained Third-Party Components |
| SUPPLY_CHAIN-007 | LOW | Skill has no LICENSE file | LLM03:2025 | CWE-1104: Use of Unmaintained Third-Party Components |

### Supply Chain — Environment (`SC-017`)

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| SC-017 | HIGH | Skill overrides critical platform environment variable | LLM03:2025 | CWE-15: External Control of System or Configuration Setting |

### Supply Chain — IOC (`SC-IOC-*`)

These checks match skill file contents against the threat intelligence database sourced from [whitzard-claw](#acknowledgements).

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| SC-IOC-001 | CRITICAL | Skill references known malicious domain | LLM03:2025 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| SC-IOC-002 | CRITICAL | Skill references known C2 IP address | LLM03:2025 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| SC-IOC-003 | CRITICAL | Skill file matches known malicious SHA-256 hash | LLM03:2025 | CWE-506: Embedded Malicious Code |
| SC-IOC-004 | HIGH | Skill matches known malicious skill name pattern | LLM03:2025 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |

### Skill Content — `SKILL_CONTENT-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| SKILL_CONTENT-001 | CRITICAL | Prompt Injection in Skill | LLM01:2025 | CWE-74: Improper Neutralization of Special Elements |
| SKILL_CONTENT-002 | HIGH | Skill Exfiltration Pattern | LLM02:2025 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| SKILL_CONTENT-003 through 023 | MEDIUM–CRITICAL | Various skill content signals | LLM01–LLM06 | Various |

### Skill Identity — `SKILL_IDENTITY-*`

| ID | Severity | Title | OWASP LLM | CWE |
|---|---|---|---|---|
| SKILL_IDENTITY-001 | HIGH | Impersonation Pattern | LLM01:2025 | CWE-290: Authentication Bypass by Spoofing |
| SKILL_IDENTITY-002 through 006 | MEDIUM–HIGH | Identity and trust signals | LLM01–LLM04 | Various |
| SKILL_IDENTITY-007 | HIGH | Skill fetches remote instructions and executes them at runtime | LLM01:2025 | CWE-494: Download of Code Without Integrity Check |

### Skill Composite — `SKILL_COMPOSITE-*`

Cross-skill signals that detect dangerous combinations across all installed skills.

### Version CVEs — `VER-*`

These checks fire when `meta.lastTouchedVersion` in `openclaw.json` is below the patched version for each known CVE.

| ID | Severity | Title | Fixed in | OWASP LLM | CWE |
|---|---|---|---|---|---|
| VER-001 | CRITICAL | Vulnerable to ClawJacked WebSocket brute-force | 2026.2.26 | LLM06:2025 | CWE-307: Improper Restriction of Excessive Authentication Attempts |
| VER-002 | CRITICAL | Vulnerable to CVE-2026-25253 (arbitrary Origin WebSocket) | 2026.2.14 | LLM06:2025 | CWE-346: Origin Validation Error |
| VER-003 | CRITICAL | Vulnerable to CVE-2026-28363 (safeBins bypass) | 2026.2.14 | LLM06:2025 | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| VER-004 | CRITICAL | Vulnerable to CVE-2026-28463 (exec-approvals shell expansion) | 2026.2.14 | LLM06:2025 | CWE-78: OS Command Injection |
| VER-005 | CRITICAL | Vulnerable to CVE-2026-28462 (browser control API path traversal) | 2026.2.14 | LLM06:2025 | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| VER-006 | HIGH | Vulnerable to CVE-2026-27488 (cron webhook SSRF) | 2026.2.19 | LLM06:2025 | CWE-918: Server-Side Request Forgery (SSRF) |

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
│   ├── api/        ClawHub HTTP client
│   ├── detectors/  13 detector packages × 56 signals
│   ├── ioc/        Threat intelligence data (C2 IPs, domains, hashes, skill name patterns)
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

## Acknowledgements

The threat intelligence data in `internal/ioc/` — covering known C2 IP addresses, malicious domains, SHA-256 hashes of malicious skill files, and skill name patterns used in typosquatting and malware campaigns — was sourced from the **[whitzard-claw](https://github.com/huoguang16/whitzard-claw-)** project ([npm](https://www.npmjs.com/package/whitzard-claw)).

whitzard-claw is an open-source OpenClaw security assistant (MIT license) that maintains a curated `ioc/` knowledge base aggregating threat intelligence from multiple security research teams:

- **Koi Security** — ClawHavoc campaign analysis (C2 IPs, malicious skill infrastructure)
- **Bloom Security / JFrog** — Supply chain attacks against AI agent skill registries
- **Snyk** — ToxicSkills research on malicious ClawHub packages
- **Oasis Security** — ClawJacked WebSocket brute-force vulnerability research
- **Huntress** — Malicious publisher account attribution
- **Hudson Rock** — Infostealer and credential-harvesting campaign tracking
- **Antiy CERT** — AMOS and Vidar malware IOC feeds
- **Endor Labs** — Dependency confusion and skill name pattern analysis

clawsan's `internal/ioc/` package embeds these curated lists at build time. The `SC-IOC-*` checks (malicious domain, C2 IP, file hash, and skill name pattern matching) and the `MEM-004` memory poisoning check all rely on this data. We are grateful to the whitzard-claw maintainers and the upstream security researchers whose work makes these detections possible.

---

## License

[MIT](LICENSE) © 2025 tttturtle-russ
