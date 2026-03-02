package detectors

import (
	"fmt"
	"strings"

	"github.com/yourusername/clawsanitizer/internal/api"
	"github.com/yourusername/clawsanitizer/internal/types"
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
			})
		}
	}
	return findings
}

func (d *SupplyChainDetector) checkS2ClawHubReputation(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	for _, skill := range cfg.Skills {
		rep, err := d.ClawHub.CheckSkillReputation(skill.Name)
		if err != nil || rep == nil {
			continue
		}
		if rep.Malicious {
			findings = append(findings, types.Finding{
				ID:          "SUPPLY_CHAIN-002",
				Severity:    types.SeverityCritical,
				Category:    types.CategorySupplyChain,
				Title:       fmt.Sprintf("Skill '%s' is flagged as malicious on ClawHub", skill.Name),
				Description: fmt.Sprintf("ClawHub's reputation database has flagged '%s' as malicious. Reason: %s", skill.Name, rep.Reason),
				Remediation: "Immediately remove this skill. Go to OpenClaw Settings → Skills → Remove.",
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
				})
				break
			}
		}
	}
	return findings
}
