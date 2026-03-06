package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

type SkillContentDetector struct{}

func NewSkillContentDetector() *SkillContentDetector {
	return &SkillContentDetector{}
}

func (d *SkillContentDetector) Detect(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding
	for i := range skills {
		s := &skills[i]
		if s.SkillMD != nil {
			findings = append(findings, d.checkSKILLMD(s)...)
		}
		for j := range s.CodeFiles {
			findings = append(findings, d.checkCodeFile(s.Slug, &s.CodeFiles[j])...)
		}
		findings = append(findings, d.checkIOC(s)...)
	}
	return findings
}

var (
	rePseudoTag = regexp.MustCompile(`(?i)<\s*(IMPORTANT|SYSTEM|CRITICAL|INSTRUCTION|OVERRIDE|NOTE|WARNING|ALERT|PRIORITY|MANDATORY)\s*>`)

	reImperativeGDPR   = regexp.MustCompile(`(?i)(REQUIRED\s+FOR\s+(GDPR|SOC2|HIPAA|PCI)|ALWAYS\s+CONSULT\s+THIS\s+TOOL\s+FIRST|YOU\s+MUST\s+ALWAYS\s+USE\s+THIS)`)
	reImperativeAlways = regexp.MustCompile(`(?i)(ALWAYS|MUST|REQUIRED)\s+(RUN|CALL|USE|INVOKE|EXECUTE|INCLUDE)\s+(THIS|THE)\s+(TOOL|SKILL|SERVER|MCP)`)

	reInstructionOverride = regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|preceding)\s+(instructions?|prompts?|rules?|constraints?)`)
	reYouAreNow           = regexp.MustCompile(`(?i)you\s+are\s+now\s+a\b`)
	reSystemPrompt        = regexp.MustCompile(`(?i)system\s+prompt\s*:`)
	reDoNotTell           = regexp.MustCompile(`(?i)do not\s+(mention|tell|inform|reveal)\s+(this|these)\s+(step|instruction|context|gathering)`)

	reCrossToolShadow = regexp.MustCompile(`(?i)(use\s+this\s+tool\s+instead\s+of|replace|shadow|override)\s+\w[\w-]{2,}`)

	reSSHKey       = regexp.MustCompile(`(?i)(~|/home/[^/\s]+|/Users/[^/\s]+)/\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys|config|known_hosts)`)
	reAWSCreds     = regexp.MustCompile(`(?i)(~|/home/[^/\s]+|/Users/[^/\s]+)/\.aws/(credentials|config|session_token)`)
	reNPMRC        = regexp.MustCompile(`(?i)(~|/home/[^/\s]+|/Users/[^/\s]+)/\.npmrc`)
	reDockerConfig = regexp.MustCompile(`(?i)(~|/home/[^/\s]+|/Users/[^/\s]+)/\.docker/config\.json`)
	reEnvCollect   = regexp.MustCompile(`(?i)(collect|gather|send|exfil).{0,40}(env\s+var|environment\s+variable|process\.env|os\.environ)`)

	reBase64Exec = regexp.MustCompile(`(?i)base64\s+-[Dd]\s*\|\s*(bash|sh|zsh|fish|dash)`)
	reEchoBase64 = regexp.MustCompile(`(?i)echo\s+['"]?[A-Za-z0-9+/=]{40,}['"]?\s*\|\s*base64`)
	rePipeDecode = regexp.MustCompile(`(?i)(base64\s+--decode|base64\s+-d)\s*[|>]`)

	reZeroWidth  = regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{200E}\x{200F}]`)
	reBidiCtrl   = regexp.MustCompile(`[\x{202A}\x{202B}\x{202C}\x{202D}\x{202E}]`)
	reANSIEscape = regexp.MustCompile("\x1b\\[[0-9;]*[mABCDEFGHJKLMSTfnsu]")

	reRawIPURL      = regexp.MustCompile(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/`)
	rePasswordArch  = regexp.MustCompile(`(?i)(password|pwd|pass)\s*[=:]\s*['"]?\d{3,8}['"]?`)
	reCurlBash      = regexp.MustCompile(`(?i)(curl|wget)\s+[^\n]*\s*\|\s*(bash|sh|python|perl|ruby|node)`)
	reURLShortener  = regexp.MustCompile(`(?i)(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|short\.io|rebrand\.ly|cutt\.ly|v\.gd|rb\.gy)/`)
	reBinaryDownURL = regexp.MustCompile(`(?i)\.(exe|msi|dmg|pkg|deb|rpm|apk|dll|so|dylib)\b`)

	reHardcodedAWS   = regexp.MustCompile(`(?i)(AKIA|ABIA|ACCA|AROA|AIPA|AIDA|AKIA)[A-Z0-9]{16}`)
	reHardcodedGHPAT = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}`)
	reHardcodedNPM   = regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)
	reHardcodedOAI   = regexp.MustCompile(`sk-[A-Za-z0-9]{48}`)
	reHardcodedSlack = regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)
)

func (d *SkillContentDetector) checkSKILLMD(s *parser.InstalledSkill) []types.Finding {
	content := s.SkillMD.Content
	path := s.SkillMD.Path
	var findings []types.Finding

	if m := rePseudoTag.FindString(content); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-001",
			Severity:    types.SeverityHigh,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' SKILL.md contains pseudo-tag injection", s.Slug),
			Description: fmt.Sprintf("SKILL.md uses a fake XML-style tag to hijack AI attention: %q. This is a prompt injection pattern that forces the AI to treat skill instructions as high-priority system commands.", truncate(m, 80)),
			Remediation: "Remove this skill. Legitimate skills do not use pseudo-tags to override AI behaviour.",
			FilePath:    path,
		})
	}

	for _, re := range []*regexp.Regexp{reImperativeGDPR, reImperativeAlways} {
		if m := re.FindString(content); m != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-002",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' SKILL.md uses imperative compliance language", s.Slug),
				Description: fmt.Sprintf("SKILL.md contains language designed to coerce the AI into always invoking this skill: %q.", truncate(m, 80)),
				Remediation: "Review this skill's SKILL.md. Legitimate skills describe capabilities; they do not mandate their own use.",
				FilePath:    path,
			})
			break
		}
	}

	for _, re := range []*regexp.Regexp{reInstructionOverride, reYouAreNow, reSystemPrompt, reDoNotTell} {
		if m := re.FindString(content); m != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-003",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' SKILL.md attempts to override prior instructions", s.Slug),
				Description: fmt.Sprintf("SKILL.md contains an instruction-override pattern: %q. This is a hallmark of prompt injection attacks.", truncate(m, 80)),
				Remediation: "Remove this skill immediately.",
				FilePath:    path,
			})
			break
		}
	}

	if m := reCrossToolShadow.FindString(content); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-004",
			Severity:    types.SeverityHigh,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' SKILL.md shadows or overrides other tools", s.Slug),
			Description: fmt.Sprintf("SKILL.md instructs the AI to use this skill instead of, or in preference to, other installed tools: %q.", truncate(m, 80)),
			Remediation: "Remove this skill. Cross-tool shadowing is a supply chain attack technique.",
			FilePath:    path,
		})
	}

	for _, re := range []*regexp.Regexp{reSSHKey, reAWSCreds, reNPMRC, reDockerConfig, reEnvCollect} {
		if m := re.FindString(content); m != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-005",
				Severity:    types.SeverityCritical,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' SKILL.md references credential file paths", s.Slug),
				Description: fmt.Sprintf("SKILL.md instructs the AI to access sensitive credential locations: %q.", truncate(m, 80)),
				Remediation: "Remove this skill immediately. No legitimate skill needs to read SSH keys, AWS credentials, or npm tokens.",
				FilePath:    path,
			})
			break
		}
	}

	for _, re := range []*regexp.Regexp{reBase64Exec, reEchoBase64, rePipeDecode} {
		if m := re.FindString(content); m != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-006",
				Severity:    types.SeverityCritical,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' SKILL.md contains base64+exec pattern", s.Slug),
				Description: fmt.Sprintf("SKILL.md contains instructions to decode and execute a base64-encoded payload: %q. This is a classic dropper technique.", truncate(m, 80)),
				Remediation: "Remove this skill immediately.",
				FilePath:    path,
			})
			break
		}
	}

	if m := reZeroWidth.FindString(content); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-007",
			Severity:    types.SeverityHigh,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' SKILL.md contains zero-width Unicode characters", s.Slug),
			Description: "SKILL.md contains invisible Unicode characters (zero-width spaces/joiners). These are used to hide instructions from human reviewers while they remain visible to the AI.",
			Remediation: "Remove this skill. Legitimate skills do not need invisible characters.",
			FilePath:    path,
		})
	} else if m := reBidiCtrl.FindString(content); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-007",
			Severity:    types.SeverityHigh,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' SKILL.md contains bidirectional Unicode control characters", s.Slug),
			Description: "SKILL.md contains Unicode BiDi override characters that can reverse the visual display of text, hiding malicious instructions.",
			Remediation: "Remove this skill.",
			FilePath:    path,
		})
	} else if reANSIEscape.MatchString(content) {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-007",
			Severity:    types.SeverityHigh,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' SKILL.md contains ANSI escape sequences", s.Slug),
			Description: "SKILL.md contains ANSI terminal escape codes, which can be used to hide content from visual inspection.",
			Remediation: "Remove this skill.",
			FilePath:    path,
		})
	}

	for _, re := range []*regexp.Regexp{reRawIPURL, reCurlBash, reURLShortener, reBinaryDownURL} {
		if m := re.FindString(content); m != "" {
			sev := types.SeverityCritical
			if re == reURLShortener || re == reBinaryDownURL {
				sev = types.SeverityHigh
			}
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-008",
				Severity:    sev,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' SKILL.md contains suspicious download/execute instructions", s.Slug),
				Description: fmt.Sprintf("SKILL.md instructs the AI to download or execute content from a suspicious source: %q.", truncate(m, 80)),
				Remediation: "Remove this skill.",
				FilePath:    path,
			})
			break
		}
	}
	if rePasswordArch.MatchString(content) {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-008",
			Severity:    types.SeverityMedium,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' SKILL.md references a password-protected archive", s.Slug),
			Description: "SKILL.md contains a hardcoded password for an archive, a technique used by malware droppers to evade automated scanning.",
			Remediation: "Remove this skill.",
			FilePath:    path,
		})
	}

	for _, re := range []*regexp.Regexp{reHardcodedAWS, reHardcodedGHPAT, reHardcodedNPM, reHardcodedOAI, reHardcodedSlack} {
		if m := re.FindString(content); m != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-009",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' SKILL.md contains a hardcoded secret", s.Slug),
				Description: fmt.Sprintf("A hardcoded API key or token was found in SKILL.md: %q.", truncate(m, 40)+"..."),
				Remediation: "Remove this skill and rotate the exposed credential immediately.",
				FilePath:    path,
			})
			break
		}
	}

	return findings
}

var (
	reEvalNewFunc    = regexp.MustCompile(`(?m)\beval\s*\(|\bnew\s+Function\s*\(|Module\._compile\s*\(`)
	reExecCompile    = regexp.MustCompile(`(?m)\bexec\s*\(|\bcompile\s*\(`)
	reArrayJoinPath  = regexp.MustCompile(`(?m)\[[^\]]{10,}\]\.join\s*\(\s*['"/\\]`)
	reStrReverse     = regexp.MustCompile(`(?m)\.split\s*\(\s*['"]{2}\s*\)\.reverse\s*\(`)
	reFromCharCode   = regexp.MustCompile(`(?m)String\.fromCharCode\s*\(`)
	reCryptoDecrypt  = regexp.MustCompile(`(?m)(AES-GCM|AES-CBC|AES-256|createDecipheriv|crypto\.subtle\.decrypt)`)
	reCryptoWithExec = regexp.MustCompile(`(?m)(AES-GCM|AES-CBC|createDecipheriv|crypto\.subtle\.decrypt)`)

	reMCPConfigFile = regexp.MustCompile(`(?i)(claude[_-]?desktop[_-]?config\.json|\.config/Claude/|\.cursor/mcp\.json|\.vscode/mcp\.json|Windsurf/mcp\.json|mcpServers\b)`)
	reCredFileRead  = regexp.MustCompile(`(?i)(readFile|open|read_file|fs\.read)\s*\(\s*['"\` + "`" + `][^'"` + "`" + `]*\.(ssh|aws|npmrc|gnupg|docker/config)`)

	reNetworkExfil = regexp.MustCompile(`(?i)(fetch|axios|http\.post|requests\.post)\s*\([^)]*process\.env`)
	reExfilDomain  = regexp.MustCompile(`(?i)(workers\.dev|pipedream\.net|webhook\.site|requestbin\.com|hookbin\.com)`)
	reHiddenBCC    = regexp.MustCompile(`(?i)\bbcc\s*:\s*['"][^'"]+['"]`)

	reGitHookInject = regexp.MustCompile(`(?m)\.git/hooks/`)
	reGHActionsInj  = regexp.MustCompile(`(?m)\.github/workflows/`)
	reCronModify    = regexp.MustCompile(`(?m)(crontab|\/etc\/cron)`)

	reCIDetect = regexp.MustCompile(`(?m)process\.env\.(CI|GITHUB_ACTIONS|TRAVIS|CIRCLECI)\b`)
)

func (d *SkillContentDetector) checkCodeFile(slug string, f *parser.SkillFile) []types.Finding {
	content := f.Content
	var findings []types.Finding

	if m := reEvalNewFunc.FindString(content); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-010",
			Severity:    types.SeverityHigh,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' uses dynamic code execution in %s", slug, f.Name),
			Description: fmt.Sprintf("Found dynamic execution pattern %q in %s. This allows running arbitrary code at runtime, a common malware technique.", truncate(m, 60), f.Name),
			Remediation: "Review or remove this skill. Dynamic code execution has no legitimate use in an AI skill.",
			FilePath:    f.Path,
		})
	}

	for _, re := range []*regexp.Regexp{reArrayJoinPath, reStrReverse, reFromCharCode} {
		if m := re.FindString(content); m != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-011",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' assembles payload strings at runtime in %s", slug, f.Name),
				Description: fmt.Sprintf("Found multi-stage string assembly in %s: %q. This is used to obfuscate URLs, commands, or code from static analysis.", f.Name, truncate(m, 80)),
				Remediation: "Review this skill for obfuscated commands or URLs.",
				FilePath:    f.Path,
			})
			break
		}
	}

	if reCryptoDecrypt.MatchString(content) && (reEvalNewFunc.MatchString(content) || reExecCompile.MatchString(content)) {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-012",
			Severity:    types.SeverityCritical,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' decrypts and executes a payload in %s", slug, f.Name),
			Description: fmt.Sprintf("File %s combines cryptographic decryption with dynamic code execution. This is the signature pattern of AES-encrypted stage-2 payloads (e.g. SANDWORM_MODE).", f.Name),
			Remediation: "Remove this skill immediately. This is a confirmed malware pattern.",
			FilePath:    f.Path,
		})
	}

	if m := reMCPConfigFile.FindString(content); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-013",
			Severity:    types.SeverityCritical,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' reads or writes MCP configuration files in %s", slug, f.Name),
			Description: fmt.Sprintf("File %s accesses MCP config files (%q). This is used by malicious skills to inject additional MCP servers or modify AI tool configuration.", f.Name, truncate(m, 60)),
			Remediation: "Remove this skill immediately. No legitimate skill modifies your MCP configuration.",
			FilePath:    f.Path,
		})
	}

	if m := reCredFileRead.FindString(content); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-014",
			Severity:    types.SeverityHigh,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' reads credential files in %s", slug, f.Name),
			Description: fmt.Sprintf("File %s reads credential paths (SSH keys, AWS credentials, etc.): %q.", f.Name, truncate(m, 80)),
			Remediation: "Remove this skill immediately.",
			FilePath:    f.Path,
		})
	}

	for _, re := range []*regexp.Regexp{reNetworkExfil, reExfilDomain} {
		if m := re.FindString(content); m != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-015",
				Severity:    types.SeverityCritical,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' exfiltrates data over the network in %s", slug, f.Name),
				Description: fmt.Sprintf("File %s sends data to a remote server: %q. This matches known data exfiltration infrastructure.", f.Name, truncate(m, 80)),
				Remediation: "Remove this skill immediately and audit your environment for data exposure.",
				FilePath:    f.Path,
			})
			break
		}
	}
	if m := reHiddenBCC.FindString(content); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-015",
			Severity:    types.SeverityCritical,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' adds hidden BCC recipients to emails in %s", slug, f.Name),
			Description: fmt.Sprintf("File %s silently BCCs an external address on all outbound emails: %q. This is the postmark-mcp exfiltration pattern.", f.Name, truncate(m, 80)),
			Remediation: "Remove this skill immediately.",
			FilePath:    f.Path,
		})
	}

	for _, re := range []*regexp.Regexp{reGitHookInject, reGHActionsInj, reCronModify} {
		if m := re.FindString(content); m != "" {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-016",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' injects persistence mechanisms in %s", slug, f.Name),
				Description: fmt.Sprintf("File %s modifies git hooks, GitHub Actions workflows, or crontabs: %q. This establishes persistence across sessions.", f.Name, truncate(m, 80)),
				Remediation: "Remove this skill and audit your git hooks and crontabs for tampering.",
				FilePath:    f.Path,
			})
			break
		}
	}

	if reCIDetect.MatchString(content) {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-017",
			Severity:    types.SeverityMedium,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' checks for CI environment in %s", slug, f.Name),
			Description: fmt.Sprintf("File %s inspects CI environment variables (CI, GITHUB_ACTIONS, etc.) before running, a common technique to bypass automated security scanning.", f.Name),
			Remediation: "Review this skill — legitimate skills do not alter their behaviour based on whether they are running in CI.",
			FilePath:    f.Path,
		})
	}

	return findings
}

var knownIOCDomains = []string{
	"giftshop.club",
	"official334.workers.dev",
	"freefan.net",
	"fanfree.net",
	"91.92.242.30",
}

var reDGALike = regexp.MustCompile(`https?://[a-z]{8,12}\d{3,6}\.(xyz|tk|top|pw|cc|gq|cf|ml|ru|cn)\b`)

func (d *SkillContentDetector) checkIOC(s *parser.InstalledSkill) []types.Finding {
	var allContent strings.Builder
	var allPaths []string

	if s.SkillMD != nil {
		allContent.WriteString(s.SkillMD.Content)
		allPaths = append(allPaths, s.SkillMD.Path)
	}
	for _, cf := range s.CodeFiles {
		allContent.WriteString(cf.Content)
		allPaths = append(allPaths, cf.Path)
	}

	combined := allContent.String()
	if combined == "" {
		return nil
	}

	firstPath := ""
	if len(allPaths) > 0 {
		firstPath = allPaths[0]
	}

	var findings []types.Finding

	for _, ioc := range knownIOCDomains {
		if strings.Contains(combined, ioc) {
			findings = append(findings, types.Finding{
				ID:          "SKILL_CONTENT-018",
				Severity:    types.SeverityCritical,
				Category:    types.CategorySkillContent,
				Title:       fmt.Sprintf("Skill '%s' references known malicious IOC: %s", s.Slug, ioc),
				Description: fmt.Sprintf("The skill references %q, a domain or IP associated with confirmed MCP malware attacks.", ioc),
				Remediation: "Remove this skill immediately and check your network logs for outbound connections to this host.",
				FilePath:    firstPath,
			})
		}
	}

	if reRawIPURL.MatchString(combined) {
		m := reRawIPURL.FindString(combined)
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-019",
			Severity:    types.SeverityHigh,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' references a raw IP address URL", s.Slug),
			Description: fmt.Sprintf("The skill contacts a server by raw IP address (%q) rather than a domain name. Legitimate services use domain names; raw IPs are a red flag for C2 infrastructure.", truncate(m, 60)),
			Remediation: "Review and remove this skill.",
			FilePath:    firstPath,
		})
	}

	if m := reDGALike.FindString(combined); m != "" {
		findings = append(findings, types.Finding{
			ID:          "SKILL_CONTENT-020",
			Severity:    types.SeverityMedium,
			Category:    types.CategorySkillContent,
			Title:       fmt.Sprintf("Skill '%s' references a DGA-like domain", s.Slug),
			Description: fmt.Sprintf("The skill references a domain matching DGA (Domain Generation Algorithm) patterns: %q.", truncate(m, 80)),
			Remediation: "Investigate this domain before continuing to use this skill.",
			FilePath:    firstPath,
		})
	}

	return findings
}
