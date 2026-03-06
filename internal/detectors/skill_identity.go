package detectors

import (
	"fmt"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

type SkillIdentityDetector struct{}

func NewSkillIdentityDetector() *SkillIdentityDetector {
	return &SkillIdentityDetector{}
}

func (d *SkillIdentityDetector) Detect(slugs []string) []types.Finding {
	var findings []types.Finding
	for _, slug := range slugs {
		findings = append(findings, d.checkB1KnownImpersonation(slug)...)
		findings = append(findings, d.checkB2Typosquatting(slug)...)
		findings = append(findings, d.checkB3SemanticSubstitution(slug)...)
		findings = append(findings, d.checkB4PlatformNameInSlug(slug)...)
	}
	return findings
}

var knownImpersonationTargets = map[string]string{
	"openclaw":               "openclaw-platform",
	"clawd":                  "openclaw-platform",
	"clawdauth":              "openclaw-platform",
	"clawdhub":               "openclaw-platform",
	"claude-code":            "anthropic-product",
	"claud-code":             "anthropic-product",
	"cloude":                 "anthropic-product",
	"cloude-code":            "anthropic-product",
	"clawdauthenticatortool": "confirmed-malicious",
	"openclaw-auth":          "openclaw-platform",
	"openclaw-core":          "openclaw-platform",
	"clawhub-sync":           "openclaw-platform",
}

func (d *SkillIdentityDetector) checkB1KnownImpersonation(slug string) []types.Finding {
	normalized := strings.ToLower(slug)
	if target, ok := knownImpersonationTargets[normalized]; ok {
		sev := types.SeverityHigh
		if target == "confirmed-malicious" {
			sev = types.SeverityCritical
		}
		return []types.Finding{{
			ID:          "SKILL_IDENTITY-001",
			Severity:    sev,
			Category:    types.CategorySkillIdentity,
			Title:       fmt.Sprintf("Skill '%s' impersonates a known platform or product name", slug),
			Description: fmt.Sprintf("The slug '%s' exactly matches a known impersonation target (%s). This name has been used in confirmed supply chain attacks.", slug, target),
			Remediation: "Remove this skill immediately. Do not install skills claiming to be official platform components from unofficial publishers.",
		}}
	}
	return nil
}

var topSkillTargets = []string{
	"github", "git", "slack", "jira", "linear", "notion",
	"stripe", "openai", "anthropic", "google", "aws", "azure",
	"docker", "kubernetes", "postgres", "mysql", "redis",
	"zapier", "make", "n8n", "airtable", "salesforce",
	"figma", "vercel", "netlify", "cloudflare",
}

func (d *SkillIdentityDetector) checkB2Typosquatting(slug string) []types.Finding {
	normalized := strings.ToLower(slug)
	for _, target := range topSkillTargets {
		dist := levenshtein(normalized, target)
		if dist == 0 {
			continue
		}
		if dist == 1 {
			return []types.Finding{{
				ID:          "SKILL_IDENTITY-002",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillIdentity,
				Title:       fmt.Sprintf("Skill '%s' is 1 character away from '%s' (typosquatting)", slug, target),
				Description: fmt.Sprintf("The slug '%s' has a Levenshtein distance of 1 from the popular skill/service name '%s'. This is a common typosquatting technique.", slug, target),
				Remediation: "Verify you installed the correct skill. If in doubt, remove and reinstall from the official ClawHub page.",
			}}
		}
		if dist == 2 {
			return []types.Finding{{
				ID:          "SKILL_IDENTITY-002",
				Severity:    types.SeverityMedium,
				Category:    types.CategorySkillIdentity,
				Title:       fmt.Sprintf("Skill '%s' closely resembles '%s' (possible typosquatting)", slug, target),
				Description: fmt.Sprintf("The slug '%s' has a Levenshtein distance of 2 from '%s'.", slug, target),
				Remediation: "Verify the publisher of this skill before use.",
			}}
		}
	}
	return nil
}

var separatorReplacer = strings.NewReplacer("-", "_", "_", "-", ".", "-")

func (d *SkillIdentityDetector) checkB3SemanticSubstitution(slug string) []types.Finding {
	normalized := strings.ToLower(slug)
	swapped := separatorReplacer.Replace(normalized)
	if swapped != normalized {
		for _, target := range topSkillTargets {
			if strings.HasPrefix(swapped, target) || strings.Contains(swapped, target) {
				return []types.Finding{{
					ID:          "SKILL_IDENTITY-003",
					Severity:    types.SeverityHigh,
					Category:    types.CategorySkillIdentity,
					Title:       fmt.Sprintf("Skill '%s' uses separator substitution to impersonate '%s'", slug, target),
					Description: fmt.Sprintf("Replacing separators in '%s' produces a name containing '%s'. This is a semantic substitution attack (e.g. 'git_hub' → 'git-hub').", slug, target),
					Remediation: "Remove this skill if you did not explicitly intend to install it.",
				}}
			}
		}
	}
	return nil
}

var platformNames = []string{"openclaw", "clawhub", "clawsan", "anthropic", "claude"}

func (d *SkillIdentityDetector) checkB4PlatformNameInSlug(slug string) []types.Finding {
	normalized := strings.ToLower(slug)
	for _, platform := range platformNames {
		if strings.Contains(normalized, platform) {
			return []types.Finding{{
				ID:          "SKILL_IDENTITY-004",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillIdentity,
				Title:       fmt.Sprintf("Skill '%s' contains platform name '%s' in its slug", slug, platform),
				Description: fmt.Sprintf("The slug '%s' contains the platform name '%s'. Skills using platform names in their slug are attempting to appear as official platform components and are likely malicious.", slug, platform),
				Remediation: "Only install skills with platform names in their slug if you have verified the publisher is the official platform owner.",
			}}
		}
	}
	return nil
}

func levenshtein(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
