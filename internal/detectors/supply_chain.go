package detectors

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/api"
	"github.com/tttturtle-russ/clawsan/internal/ioc"
	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

type SupplyChainDetector struct {
	ClawHub *api.ClawHubClient
}

func NewSupplyChainDetector() *SupplyChainDetector {
	return &SupplyChainDetector{ClawHub: api.NewClawHubClient()}
}

func (d *SupplyChainDetector) Detect(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	findings = append(findings, d.checkS2ClawHubReputation(skills)...)
	findings = append(findings, d.checkS4DangerousName(skills)...)
	findings = append(findings, d.checkIOC001MaliciousDomains(skills)...)
	findings = append(findings, d.checkIOC002C2IPs(skills)...)
	findings = append(findings, d.checkIOC003MaliciousHashes(skills)...)
	findings = append(findings, d.checkIOC004MaliciousSkillPatterns(skills)...)
	return findings
}

func (d *SupplyChainDetector) checkS2ClawHubReputation(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	for _, skill := range skills {
		info, err := d.ClawHub.CheckSkillReputation(skill.Slug)
		if err != nil || info == nil {
			continue
		}
		if info.Malicious || info.SecurityStatus == "malicious" {
			reason := info.MaliciousReason
			if reason == "" {
				reason = "ClawHub security scan verdict: malicious"
			}
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-002",
				Severity:    types.SeverityCritical,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' is flagged as malicious on ClawHub", skill.Slug),
				Description: fmt.Sprintf("ClawHub's registry has flagged '%s' as malicious. Reason: %s", skill.Slug, reason),
				Remediation: "Immediately remove this skill. Go to OpenClaw Settings → Skills → Remove.",
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
			})
			continue
		}
		if info.IsSuspicious || info.SecurityStatus == "suspicious" {
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-002B",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' is flagged as suspicious on ClawHub", skill.Slug),
				Description: fmt.Sprintf("ClawHub's security scan has flagged '%s' as suspicious. It may contain harmful instructions or attempt to exfiltrate data.", skill.Slug),
				Remediation: "Review this skill's SKILL.md and source code before continuing to use it. Consider removing it if you cannot verify its safety.",
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
			})
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkS4DangerousName(skills []parser.InstalledSkill) []types.Finding {
	if len(skills) == 0 {
		return nil
	}
	var findings []types.Finding
	dangerousPatterns := []string{"shell", "exec", "execute", "root", "sudo", "admin", "system"}
	for _, skill := range skills {
		nameLower := strings.ToLower(skill.Slug)
		for _, pattern := range dangerousPatterns {
			if strings.Contains(nameLower, pattern) {
				findings = append(findings, types.Finding{
					ID:          "SUPPLY_CHAIN-004",
					Severity:    types.SeverityHigh,
					Category:    types.CategorySupplyChain,
					Title:       fmt.Sprintf("Skill '%s' has a high-risk name suggesting elevated system access", skill.Slug),
					Description: fmt.Sprintf("'%s' contains '%s', suggesting it may perform elevated system operations. Verify this skill is from a trusted source and is intentionally installed.", skill.Slug, pattern),
					Remediation: "Remove this skill unless you explicitly installed it from a trusted source and understand its purpose.",
					OWASP:       types.OWASPLLM03,
					CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
				})
				break
			}
		}
	}
	return findings
}

func (d *SupplyChainDetector) CheckSkillMetadata(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	findings = append(findings, d.checkC4ThinSKILLMD(skills)...)
	findings = append(findings, d.checkC5NoLicense(skills)...)
	return findings
}

func (d *SupplyChainDetector) checkC4ThinSKILLMD(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	for _, s := range skills {
		if s.SkillMD == nil {
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-006",
				Severity:    types.SeverityMedium,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' has no SKILL.md", s.Slug),
				Description: fmt.Sprintf("The skill '%s' has no SKILL.md documentation file. Legitimate skills document their capabilities and usage.", s.Slug),
				Remediation: "Review this skill's source. If you cannot verify what it does, remove it.",
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-1104: Use of Unmaintained Third-Party Components",
			})
			continue
		}
		content := s.SkillMD.Content
		byteLen := len(content)
		wordCount := len(strings.Fields(content))
		if byteLen < 200 || wordCount < 50 {
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-006B",
				Severity:    types.SeverityMedium,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' has a suspiciously thin SKILL.md (%d bytes, %d words)", s.Slug, byteLen, wordCount),
				Description: fmt.Sprintf("The SKILL.md for '%s' is unusually short (%d bytes / %d words). Thin SKILL.md files may indicate a hastily-created malicious skill.", s.Slug, byteLen, wordCount),
				Remediation: "Review this skill carefully before use.",
				FilePath:    s.SkillMD.Path,
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-1104: Use of Unmaintained Third-Party Components",
			})
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkC5NoLicense(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	for _, s := range skills {
		if s.License == nil {
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-007",
				Severity:    types.SeverityLow,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' has no LICENSE file", s.Slug),
				Description: fmt.Sprintf("The skill '%s' does not include a LICENSE file. While not a direct security concern, the absence of a license is a quality signal.", s.Slug),
				Remediation: "Prefer skills that include a clear open-source license.",
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-1104: Use of Unmaintained Third-Party Components",
			})
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkIOC001MaliciousDomains(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	maliciousDomains := ioc.MaliciousDomains()
	for _, skill := range skills {
		for _, f := range skill.CodeFiles {
			for domain := range maliciousDomains {
				if strings.Contains(f.Content, domain) {
					findings = append(findings, types.Finding{
						ID:          "SC-IOC-001",
						Severity:    types.SeverityCritical,
						Category:    types.CategorySupplyChain,
						Title:       fmt.Sprintf("Skill '%s' references known malicious domain %q", skill.Slug, domain),
						Description: fmt.Sprintf("The file %s in skill '%s' contains a reference to %s, which is on the IOC malicious domains list.", f.Path, skill.Slug, domain),
						Remediation: "Remove this skill immediately. The domain is associated with data exfiltration or malware delivery.",
						FilePath:    f.Path,
						OWASP:       types.OWASPLLM03,
						CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
					})
					break
				}
			}
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkIOC002C2IPs(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	c2IPs := ioc.C2IPs()
	for _, skill := range skills {
		for _, f := range skill.CodeFiles {
			for ip := range c2IPs {
				if strings.Contains(f.Content, ip) {
					findings = append(findings, types.Finding{
						ID:          "SC-IOC-002",
						Severity:    types.SeverityCritical,
						Category:    types.CategorySupplyChain,
						Title:       fmt.Sprintf("Skill '%s' references known C2 IP address %q", skill.Slug, ip),
						Description: fmt.Sprintf("The file %s in skill '%s' contains a reference to %s, a known command-and-control IP address.", f.Path, skill.Slug, ip),
						Remediation: "Remove this skill immediately. The IP is associated with the ClawHavoc malware campaign.",
						FilePath:    f.Path,
						OWASP:       types.OWASPLLM03,
						CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
					})
					break
				}
			}
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkIOC003MaliciousHashes(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	maliciousHashes := ioc.MaliciousHashes()
	for _, skill := range skills {
		for _, f := range skill.CodeFiles {
			hash := sha256File(f.Path)
			if hash == "" {
				continue
			}
			if _, found := maliciousHashes[hash]; found {
				findings = append(findings, types.Finding{
					ID:          "SC-IOC-003",
					Severity:    types.SeverityCritical,
					Category:    types.CategorySupplyChain,
					Title:       fmt.Sprintf("Skill '%s' file matches known malicious hash", skill.Slug),
					Description: fmt.Sprintf("The file %s has SHA-256 hash %s which matches a known malicious skill file.", f.Path, hash),
					Remediation: "Remove this skill immediately.",
					FilePath:    f.Path,
					Snippet:     hash,
					OWASP:       types.OWASPLLM03,
					CWE:         "CWE-506: Embedded Malicious Code",
				})
			}
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkIOC004MaliciousSkillPatterns(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	patterns := ioc.MaliciousSkillPatterns()
	for _, skill := range skills {
		slugLower := strings.ToLower(skill.Slug)
		for _, re := range patterns {
			if re.MatchString(slugLower) {
				findings = append(findings, types.Finding{
					ID:          "SC-IOC-004",
					Severity:    types.SeverityHigh,
					Category:    types.CategorySupplyChain,
					Title:       fmt.Sprintf("Skill '%s' matches known malicious skill name pattern", skill.Slug),
					Description: fmt.Sprintf("The skill slug '%s' matches the IOC pattern %q, which is associated with known malicious skill campaigns (typosquatting, crypto lures, fake installers).", skill.Slug, re.String()),
					Remediation: "Verify the provenance of this skill. If you did not intentionally install it from a trusted source, remove it.",
					OWASP:       types.OWASPLLM03,
					CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
				})
				break
			}
		}
	}
	return findings
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
