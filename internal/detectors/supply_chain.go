package detectors

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/api"
	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

// SupplyChainDetector checks for supply chain vulnerabilities in installed skills
type SupplyChainDetector struct {
	ClawHub *api.ClawHubClient
}

// NewSupplyChainDetector creates a detector with a real ClawHub client
func NewSupplyChainDetector() *SupplyChainDetector {
	return &SupplyChainDetector{ClawHub: api.NewClawHubClient()}
}

// Detect runs all S1-S4 supply chain checks
func (d *SupplyChainDetector) Detect(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	findings = append(findings, d.checkS1HashVerification(cfg)...)
	findings = append(findings, d.checkS2ClawHubReputation(cfg)...)
	findings = append(findings, d.checkS3UnofficialSources(cfg)...)
	findings = append(findings, d.checkS4EmptyHashes(cfg)...)
	return findings
}

func (d *SupplyChainDetector) checkS1HashVerification(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	for _, skill := range cfg.Skills {
		if skill.Hash == "" {
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-001",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' has no integrity hash", skill.Name),
				Description: fmt.Sprintf("The skill '%s' is installed without a cryptographic hash. This means its code cannot be verified for tampering.", skill.Name),
				Remediation: "Re-install the skill from ClawHub to get a verified hash, or remove the skill if it came from an unofficial source.",
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-494: Download of Code Without Integrity Check",
			})
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkS2ClawHubReputation(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	for _, skill := range cfg.Skills {
		info, err := d.ClawHub.CheckSkillReputation(skill.Name)
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
				Title:       fmt.Sprintf("Skill '%s' is flagged as malicious on ClawHub", skill.Name),
				Description: fmt.Sprintf("ClawHub's registry has flagged '%s' as malicious. Reason: %s", skill.Name, reason),
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
				Title:       fmt.Sprintf("Skill '%s' is flagged as suspicious on ClawHub", skill.Name),
				Description: fmt.Sprintf("ClawHub's security scan has flagged '%s' as suspicious. It may contain harmful instructions or attempt to exfiltrate data.", skill.Name),
				Remediation: "Review this skill's SKILL.md and source code before continuing to use it. Consider removing it if you cannot verify its safety.",
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
			})
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkS3UnofficialSources(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	for _, skill := range cfg.Skills {
		if skill.Source == "" {
			continue
		}
		if !strings.HasPrefix(skill.Source, "clawhub://") {
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-003",
				Severity:    types.SeverityMedium,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' is from an unofficial source", skill.Name),
				Description: fmt.Sprintf("'%s' was installed from '%s' which is not the official ClawHub marketplace. Skills from unofficial sources have not been reviewed for malware.", skill.Name, skill.Source),
				Remediation: "Only install skills from the official ClawHub marketplace (clawhub://). Remove this skill and find an official alternative.",
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
			})
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkS4EmptyHashes(cfg *types.OpenClawConfig) []types.Finding {
	if len(cfg.Skills) == 0 {
		return nil
	}
	var findings []types.Finding
	dangerousPatterns := []string{"shell", "exec", "execute", "root", "sudo", "admin", "system"}
	for _, skill := range cfg.Skills {
		nameLower := strings.ToLower(skill.Name)
		for _, pattern := range dangerousPatterns {
			if strings.Contains(nameLower, pattern) && !strings.HasPrefix(skill.Source, "clawhub://") {
				findings = append(findings, types.Finding{
					ID:          "SUPPLY_CHAIN-004",
					Severity:    types.SeverityHigh,
					Category:    types.CategorySupplyChain,
					Title:       fmt.Sprintf("Skill '%s' has a high-risk name from an unverified source", skill.Name),
					Description: fmt.Sprintf("'%s' has a name suggesting elevated system access ('%s') and is not from the official ClawHub marketplace.", skill.Name, pattern),
					Remediation: "Remove this skill immediately unless you explicitly installed it from a trusted source and understand its purpose.",
					OWASP:       types.OWASPLLM03,
					CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
				})
				break
			}
		}
	}
	return findings
}

func (d *SupplyChainDetector) CheckSkillMetadata(cfg *types.OpenClawConfig, skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	findings = append(findings, d.checkC3RugPull(cfg, skills)...)
	findings = append(findings, d.checkC4ThinSKILLMD(skills)...)
	findings = append(findings, d.checkC5NoLicense(skills)...)
	return findings
}

func (d *SupplyChainDetector) checkC3RugPull(cfg *types.OpenClawConfig, skills []parser.InstalledSkill) []types.Finding {
	skillMap := make(map[string]*parser.InstalledSkill, len(skills))
	for i := range skills {
		skillMap[skills[i].Slug] = &skills[i]
	}

	var findings []types.Finding
	for _, sc := range cfg.Skills {
		if sc.Hash == "" {
			continue
		}
		installed, ok := skillMap[sc.Name]
		if !ok || installed.SkillMD == nil {
			continue
		}
		sum := sha256.Sum256([]byte(installed.SkillMD.Content))
		computed := fmt.Sprintf("sha256:%x", sum)
		if !strings.EqualFold(sc.Hash, computed) {
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-005",
				Severity:    types.SeverityCritical,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' SKILL.md hash does not match config (rug pull)", sc.Name),
				Description: fmt.Sprintf("The SKILL.md for '%s' has been modified after installation. Config hash: %s. Computed hash: %s. This is the signature of a post-install rug pull attack.", sc.Name, sc.Hash, computed),
				Remediation: "Reinstall this skill from ClawHub to get a clean verified copy. If the issue persists, remove the skill.",
				FilePath:    installed.SkillMD.Path,
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-494: Download of Code Without Integrity Check",
			})
		}
	}
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
