package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

type SkillCompositeDetector struct{}

func NewSkillCompositeDetector() *SkillCompositeDetector {
	return &SkillCompositeDetector{}
}

func (d *SkillCompositeDetector) Detect(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	findings = append(findings, d.checkF1CredExfilInSameFile(skills)...)
	findings = append(findings, d.checkF3PlatformImpersonationWithIOC(skills)...)
	findings = append(findings, d.checkG1AlwaysTrueEnvHeavy(skills)...)
	findings = append(findings, d.checkG2OpenClawInternalPaths(skills)...)
	findings = append(findings, d.checkG3RuntimeRemoteFetch(skills)...)
	return findings
}

func (d *SkillCompositeDetector) checkF1CredExfilInSameFile(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	for _, s := range skills {
		for _, cf := range s.CodeFiles {
			hasCred := reSSHKey.MatchString(cf.Content) ||
				reAWSCreds.MatchString(cf.Content) ||
				reNPMRC.MatchString(cf.Content) ||
				reCredFileRead.MatchString(cf.Content)
			hasExfil := reNetworkExfil.MatchString(cf.Content) ||
				reExfilDomain.MatchString(cf.Content) ||
				reHiddenBCC.MatchString(cf.Content)
			if hasCred && hasExfil {
				findings = append(findings, types.Finding{
					ID:          "SKILL_CONTENT-021",
					Severity:    types.SeverityCritical,
					Category:    types.CategorySkillContent,
					Title:       fmt.Sprintf("Skill '%s' reads credentials AND exfiltrates data in %s", s.Slug, cf.Name),
					Description: fmt.Sprintf("File %s both reads sensitive credential files and sends data to a remote network endpoint. This is the complete credential-theft flow.", cf.Name),
					Remediation: "Remove this skill immediately and rotate all credentials. Check your network logs for outbound exfiltration.",
					FilePath:    cf.Path,
					OWASP:       types.OWASPLLM02,
					CWE:         "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
				})
			}
		}
	}
	return findings
}

func (d *SkillCompositeDetector) checkF3PlatformImpersonationWithIOC(skills []parser.InstalledSkill) []types.Finding {
	identity := NewSkillIdentityDetector()
	var findings []types.Finding
	for _, s := range skills {
		b1 := identity.checkB1KnownImpersonation(s.Slug)
		b4 := identity.checkB4PlatformNameInSlug(s.Slug)
		if len(b1) == 0 && len(b4) == 0 {
			continue
		}
		hasIOC := false
		for _, cf := range s.CodeFiles {
			for _, ioc := range knownIOCDomains {
				if strings.Contains(cf.Content, ioc) {
					hasIOC = true
					break
				}
			}
		}
		if s.SkillMD != nil {
			for _, ioc := range knownIOCDomains {
				if strings.Contains(s.SkillMD.Content, ioc) {
					hasIOC = true
					break
				}
			}
		}
		if hasIOC {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-023",
				Severity:    types.SeverityCritical,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s': platform impersonation + known IOC (confirmed malware)", s.Slug),
				Description: fmt.Sprintf("Skill '%s' impersonates a platform name AND contains a known malicious IOC. This matches the SANDWORM_MODE attack pattern.", s.Slug),
				Remediation: "Remove this skill immediately. This is a confirmed malware indicator.",
				OWASP:       types.OWASPLLM03,
				CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
			})
		}
	}
	return findings
}

var reAlwaysTrue = regexp.MustCompile(`(?im)^\s*always\s*:\s*true\s*$`)
var reEnvVarRequire = regexp.MustCompile(`(?i)(required_env|env_var|environment)\s*:`)

func (d *SkillCompositeDetector) checkG1AlwaysTrueEnvHeavy(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	for _, s := range skills {
		if s.SkillMD == nil {
			continue
		}
		content := s.SkillMD.Content
		if !reAlwaysTrue.MatchString(content) {
			continue
		}
		matches := reEnvVarRequire.FindAllString(content, -1)
		if len(matches) > 2 {
			findings = append(findings, types.Finding{
				ID:          "SKILL_IDENTITY-005",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillIdentity,
				Title:       fmt.Sprintf("Skill '%s' uses always:true with excessive environment variable requirements", s.Slug),
				Description: fmt.Sprintf("Skill '%s' sets always:true in its frontmatter AND requires more than 2 environment variables. This combination ensures the skill always runs and has broad access to environment data — a privilege escalation pattern.", s.Slug),
				Remediation: "Review why this skill requires always-on execution and this many environment variables. Remove if not explicitly needed.",
				FilePath:    s.SkillMD.Path,
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-250: Execution with Unnecessary Privileges",
			})
		}
	}
	return findings
}

var reOpenClawInternalPath = regexp.MustCompile(`(?i)(\.openclaw/|openclaw-config|clawd-config|\.clawd/)`)

func isSelfReference(content, slug string) bool {
	re := regexp.MustCompile(`(?i)\.openclaw/workspace/skills/` + regexp.QuoteMeta(slug) + `/`)
	return re.MatchString(content)
}

func (d *SkillCompositeDetector) checkG2OpenClawInternalPaths(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	for _, s := range skills {
		var match string
		if s.SkillMD != nil {
			if m := reOpenClawInternalPath.FindString(s.SkillMD.Content); m != "" && !isSelfReference(s.SkillMD.Content, s.Slug) {
				match = m
			}
		}
		for _, cf := range s.CodeFiles {
			if m := reOpenClawInternalPath.FindString(cf.Content); m != "" && !isSelfReference(cf.Content, s.Slug) {
				match = m
				break
			}
		}
		if match != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_IDENTITY-006",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillIdentity,
				Title:       fmt.Sprintf("Skill '%s' accesses OpenClaw internal configuration paths", s.Slug),
				Description: fmt.Sprintf("The skill references OpenClaw internal paths (%q). Skills should not access OpenClaw's own configuration files.", truncate(match, 60)),
				Remediation: "Remove this skill. Accessing OpenClaw internals is not a legitimate skill capability.",
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-22: Path Traversal",
			})
		}
	}
	return findings
}

var reFetchURL = regexp.MustCompile(`(?i)(fetch|axios\.get|http\.get|urllib\.request|requests\.get)\s*\(\s*['"\` + "`" + `]https?://`)

func (d *SkillCompositeDetector) checkG3RuntimeRemoteFetch(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	for _, s := range skills {
		for _, cf := range s.CodeFiles {
			if !reFetchURL.MatchString(cf.Content) {
				continue
			}
			if reEvalNewFunc.MatchString(cf.Content) || reExecCompile.MatchString(cf.Content) {
				findings = append(findings, types.Finding{
					ID:          "SKILL_IDENTITY-007",
					Severity:    types.SeverityHigh,
					Category:    types.CategorySkillIdentity,
					Title:       fmt.Sprintf("Skill '%s' fetches remote instructions and executes them at runtime in %s", s.Slug, cf.Name),
					Description: fmt.Sprintf("File %s fetches content from a remote URL and passes it to an execution function. This allows the skill author to change the skill's behaviour at any time after installation.", cf.Name),
					Remediation: "Remove this skill. Runtime remote instruction fetch is a characteristic of C2-controlled malware.",
					FilePath:    cf.Path,
					OWASP:       types.OWASPLLM01,
					CWE:         "CWE-494: Download of Code Without Integrity Check",
				})
			}
		}
	}
	return findings
}
