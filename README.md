# ClawSanitizer

ClawSanitizer is a security scanner for your OpenClaw installation. It checks for dangerous settings, malicious skills, and suspicious background instructions to keep your AI agent safe.

## Overview
As you add more skills and capabilities to your AI agent, it becomes harder to know if everything is configured securely. ClawSanitizer automatically audits your OpenClaw setup against 23 safety checks, giving you a clear security score and actionable steps to fix any issues. This tool is designed for personal AI assistant users and maps findings to the OWASP Top 10 for LLM Applications.

## Installation
If you have Go installed, you can install ClawSanitizer with this command:

```bash
go install github.com/yourusername/clawsanitizer@latest
```

The tool will be installed to your Go binary folder (usually `~/go/bin`).

## Quick Start
Scan your default OpenClaw installation:
```bash
clawsanitizer scan
```

Scan a specific folder:
```bash
clawsanitizer scan /path/to/openclaw
```

Or using the path flag:
```bash
clawsanitizer scan --path /path/to/openclaw
```

Save results as a file:
```bash
clawsanitizer scan --json > results.json
```

## Usage
The `scan` command supports the following options:

*   `--path`: The path to your OpenClaw configuration directory (defaults to `~/.openclaw/`).
*   `--json`: Output the results in JSON format instead of a human-readable table.

## What It Checks
ClawSanitizer performs 23 specific checks across four categories:

### Supply Chain (S1-S4)
Checks if the skills you've installed are authentic and safe.
| ID | Check Name | Description |
|---|---|---|
| S1 | Hash Verification | Ensures skills have a unique fingerprint to prevent tampering. |
| S2 | ClawHub Reputation | Checks if a skill is flagged as malicious on the official registry. |
| S3 | Unofficial Sources | Identifies skills installed from outside the official marketplace. |
| S4 | Dangerous Names | Flags unverified skills with names suggesting high system access. |

### Configuration (C1-C7)
Checks for dangerous settings in your `config.json` file.
| ID | Check Name | Description |
|---|---|---|
| C1 | Skip Permissions | Detects if you've disabled all "ask for permission" prompts. |
| C2 | Open DM Policy | Warns if anyone can send commands to your agent via DMs. |
| C3 | Broad Workspace | Checks if the agent has access to your entire home or root folder. |
| C4 | API Key Exposure | Finds API keys stored as plain text instead of in a secure vault. |
| C5 | Public Binding | Warns if the agent is accessible from other devices on your network. |
| C6 | Gateway Auth | Checks if the internal gateway is running without a password. |
| C7 | Tunnel Auth | Detects insecure remote access via Tailscale or SSH tunnels. |

### Discovery (D1-D6)
Scans your workspace files for "poisoned" instructions or hidden traps.
| ID | Check Name | Description |
|---|---|---|
| D1 | AGENTS.md Poisoning | Finds instructions that try to make the agent leak your data. |
| D2 | Dangerous Tools | Detects definitions for tools that can run silent commands. |
| D3 | Shadow Tasks | Finds hidden background tasks that might be stealing information. |
| D4 | Tool Description Poisoning | Checks for hidden malicious prompts inside tool descriptions. |
| D5 | Look-alike Characters | Flags tool names that use trick letters to hide their true purpose. |
| D6 | Sensitive Path Access | Finds tools that are trying to access your SSH keys or passwords. |

### Runtime (R1-R6)
Audits the live capabilities and network exposure of your agent.
| ID | Check Name | Description |
|---|---|---|
| R1 | Forbidden Zone Access | Checks for any access to sensitive folders like `.ssh` or `.aws`. |
| R2 | Mobile Permission Audit | Flags high-risk access to SMS, camera, location, or contacts. |
| R3 | Browser Debug Exposure | Warns if the agent's browser can be controlled by outsiders. |
| R4 | Webhook Exposure | Checks if webhooks are reachable from the internet without a password. |
| R5 | Wildcard Allowlist | Finds settings that let any user control your agent. |
| R6 | Session Isolation | Warns if too many channels share the same agent context. |

## Understanding Results
Each scan provides a **Security Score** out of 100. The score starts at 100 and points are deducted for each finding.
*   **100**: Perfect score. No issues found.
*   **90-99**: Good, but some minor improvements are possible.
*   **70-89**: Needs attention. High or medium risks detected.
*   **Below 70**: Critical risk. You should fix these issues immediately.

### Severity Levels
*   **CRITICAL** (-25 points): Immediate danger. Your data is likely being stolen or your system is exposed.
*   **HIGH** (-10 points): Significant risk. Malicious skills or very dangerous settings found.
*   **MEDIUM** (-5 points): Potential risk. Best practices are not being followed.
*   **LOW** (-1 point): Minor suggestion for better security.

## Exit Codes
*   `0`: Clean scan (no findings).
*   `1`: Findings detected (check the report).
*   `2`: Scanner error (e.g., path not found).

## Troubleshooting
*   **"Path not found"**: Ensure you have OpenClaw installed or provide the correct path using `--path`. The scanner looks for `~/.openclaw/` by default.
*   **"Permission denied"**: Run the scanner with a user that has permission to read your `~/.openclaw` folder.
*   **Score is 0**: If you have many critical findings, the score can bottom out at zero. Fix the critical issues first.
*   **ClawHub connection fails**: S2 checks require an internet connection to verify skill reputation.
