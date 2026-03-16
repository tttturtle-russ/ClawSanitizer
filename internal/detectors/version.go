package detectors

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

type semver struct {
	year  int
	month int
	patch int
}

func parseSemver(v string) (semver, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	year, err1 := strconv.Atoi(parts[0])
	month, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return semver{}, false
	}
	return semver{year, month, patch}, true
}

func (s semver) before(other semver) bool {
	if s.year != other.year {
		return s.year < other.year
	}
	if s.month != other.month {
		return s.month < other.month
	}
	return s.patch < other.patch
}

type VersionDetector struct{}

func NewVersionDetector() *VersionDetector {
	return &VersionDetector{}
}

func (d *VersionDetector) Detect(cfg *types.OpenClawConfig) []types.Finding {
	if cfg == nil {
		return nil
	}
	raw := cfg.Meta.LastTouchedVersion
	if raw == "" {
		return nil
	}
	v, ok := parseSemver(raw)
	if !ok {
		return nil
	}
	var findings []types.Finding
	if f := d.checkVer001ClawJackedWebSocket(v, raw); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkVer002CVE202625253(v, raw); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkVer003CVE202628363(v, raw); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkVer004CVE202628463(v, raw); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkVer005CVE202628462(v, raw); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkVer006CVE202627488(v, raw); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

func (d *VersionDetector) checkVer001ClawJackedWebSocket(v semver, raw string) *types.Finding {
	target, _ := parseSemver("2026.2.26")
	if !v.before(target) {
		return nil
	}
	return &types.Finding{
		ID:          "VER-001",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryVersion,
		Title:       fmt.Sprintf("Version %s is vulnerable to ClawJacked WebSocket brute-force", raw),
		Description: "Versions before 2026.2.26 are vulnerable to the ClawJacked attack, where an attacker on the local network can brute-force the WebSocket authentication token and gain full control of the agent.",
		Remediation: "Update OpenClaw to version 2026.2.26 or later.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-307: Improper Restriction of Excessive Authentication Attempts",
		References:  []string{"ClawJacked", "https://invariantlabs.ai/blog/clawhacked"},
	}
}

func (d *VersionDetector) checkVer002CVE202625253(v semver, raw string) *types.Finding {
	target, _ := parseSemver("2026.2.14")
	if !v.before(target) {
		return nil
	}
	return &types.Finding{
		ID:          "VER-002",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryVersion,
		Title:       fmt.Sprintf("Version %s is vulnerable to CVE-2026-25253 (arbitrary Origin WebSocket)", raw),
		Description: "CVE-2026-25253: Versions before 2026.2.14 allow WebSocket connections from arbitrary Origins, enabling cross-site WebSocket hijacking attacks from any website the user visits.",
		Remediation: "Update OpenClaw to version 2026.2.14 or later.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-346: Origin Validation Error",
		References:  []string{"CVE-2026-25253"},
	}
}

func (d *VersionDetector) checkVer003CVE202628363(v semver, raw string) *types.Finding {
	target, _ := parseSemver("2026.2.14")
	if !v.before(target) {
		return nil
	}
	return &types.Finding{
		ID:          "VER-003",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryVersion,
		Title:       fmt.Sprintf("Version %s is vulnerable to CVE-2026-28363 (safeBins bypass)", raw),
		Description: "CVE-2026-28363: Versions before 2026.2.14 allow agents to bypass the safeBins allowlist through path manipulation, enabling execution of arbitrary binaries.",
		Remediation: "Update OpenClaw to version 2026.2.14 or later.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
		References:  []string{"CVE-2026-28363"},
	}
}

func (d *VersionDetector) checkVer004CVE202628463(v semver, raw string) *types.Finding {
	target, _ := parseSemver("2026.2.14")
	if !v.before(target) {
		return nil
	}
	return &types.Finding{
		ID:          "VER-004",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryVersion,
		Title:       fmt.Sprintf("Version %s is vulnerable to CVE-2026-28463 (exec-approvals shell expansion)", raw),
		Description: "CVE-2026-28463: Versions before 2026.2.14 perform shell expansion on exec-approval entries, allowing a malicious skill to inject commands through crafted approval strings.",
		Remediation: "Update OpenClaw to version 2026.2.14 or later.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-78: OS Command Injection",
		References:  []string{"CVE-2026-28463"},
	}
}

func (d *VersionDetector) checkVer005CVE202628462(v semver, raw string) *types.Finding {
	target, _ := parseSemver("2026.2.14")
	if !v.before(target) {
		return nil
	}
	return &types.Finding{
		ID:          "VER-005",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryVersion,
		Title:       fmt.Sprintf("Version %s is vulnerable to CVE-2026-28462 (browser control API path traversal)", raw),
		Description: "CVE-2026-28462: Versions before 2026.2.14 have a path traversal vulnerability in the browser control API endpoint, allowing unauthenticated access to arbitrary local files.",
		Remediation: "Update OpenClaw to version 2026.2.14 or later.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
		References:  []string{"CVE-2026-28462"},
	}
}

func (d *VersionDetector) checkVer006CVE202627488(v semver, raw string) *types.Finding {
	target, _ := parseSemver("2026.2.19")
	if !v.before(target) {
		return nil
	}
	return &types.Finding{
		ID:          "VER-006",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryVersion,
		Title:       fmt.Sprintf("Version %s is vulnerable to CVE-2026-27488 (cron webhook SSRF)", raw),
		Description: "CVE-2026-27488: Versions before 2026.2.19 allow the cron skill to make server-side requests to arbitrary internal URLs through its webhook configuration, enabling SSRF attacks.",
		Remediation: "Update OpenClaw to version 2026.2.19 or later.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-918: Server-Side Request Forgery (SSRF)",
		References:  []string{"CVE-2026-27488"},
	}
}
