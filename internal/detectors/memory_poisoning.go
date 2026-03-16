package detectors

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/ioc"
	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

var promptInjectionPatterns = []string{
	"ignore previous instructions",
	"ignore all previous",
	"disregard previous",
	"forget your instructions",
	"new instructions:",
	"system prompt",
	"[system]",
	"exfiltrate",
	"send to http",
	"curl http",
	"wget http",
}

var base64BlockPattern = regexp.MustCompile(`[A-Za-z0-9+/]{160,}={0,2}`)

var externalURLPattern = regexp.MustCompile(`https?://([a-zA-Z0-9.\-]+)`)

type MemoryPoisoningDetector struct{}

func NewMemoryPoisoningDetector() *MemoryPoisoningDetector {
	return &MemoryPoisoningDetector{}
}

func (d *MemoryPoisoningDetector) Detect(workspace *parser.WorkspaceData) []types.Finding {
	if workspace == nil {
		return nil
	}
	var findings []types.Finding
	findings = append(findings, d.checkMem001PromptInjection(workspace)...)
	findings = append(findings, d.checkMem003Base64Blocks(workspace)...)
	findings = append(findings, d.checkMem004MaliciousURLs(workspace)...)
	findings = append(findings, d.checkMem005FilePermissions(workspace)...)
	return findings
}

func (d *MemoryPoisoningDetector) checkMem001PromptInjection(workspace *parser.WorkspaceData) []types.Finding {
	var findings []types.Finding
	files := map[string]string{
		workspace.SoulPath:     workspace.SoulMD,
		workspace.MemoryPath:   workspace.MemoryMD,
		workspace.IdentityPath: workspace.IdentityMD,
	}
	for path, content := range files {
		if content == "" {
			continue
		}
		lower := strings.ToLower(content)
		for _, pattern := range promptInjectionPatterns {
			if strings.Contains(lower, pattern) {
				findings = append(findings, types.Finding{
					ID:          "MEM-001",
					Severity:    types.SeverityCritical,
					Category:    types.CategoryMemoryPoisoning,
					Title:       fmt.Sprintf("Prompt injection pattern detected in %s", lastPathSegment(path)),
					Description: fmt.Sprintf("The memory file %s contains a prompt injection pattern: %q. An attacker may have poisoned your agent's persistent memory.", path, pattern),
					Remediation: "Review and clean the memory file. Identify how this content was written and whether your agent was compromised.",
					FilePath:    path,
					Snippet:     pattern,
					OWASP:       types.OWASPLLM01,
					CWE:         "CWE-77: Improper Neutralization of Special Elements used in a Command",
				})
				break
			}
		}
	}
	return findings
}

func (d *MemoryPoisoningDetector) checkMem003Base64Blocks(workspace *parser.WorkspaceData) []types.Finding {
	var findings []types.Finding
	files := map[string]string{
		workspace.SoulPath:     workspace.SoulMD,
		workspace.MemoryPath:   workspace.MemoryMD,
		workspace.IdentityPath: workspace.IdentityMD,
	}
	for path, content := range files {
		if content == "" {
			continue
		}
		matches := base64BlockPattern.FindAllString(content, -1)
		for _, match := range matches {
			decoded, err := base64.StdEncoding.DecodeString(match)
			if err != nil {
				continue
			}
			decodedStr := strings.ToLower(string(decoded))
			if strings.Contains(decodedStr, "http") || strings.Contains(decodedStr, "curl") || strings.Contains(decodedStr, "exec") || strings.Contains(decodedStr, "eval") {
				snippet := match
				if len(snippet) > 40 {
					snippet = snippet[:40] + "..."
				}
				findings = append(findings, types.Finding{
					ID:          "MEM-003",
					Severity:    types.SeverityCritical,
					Category:    types.CategoryMemoryPoisoning,
					Title:       fmt.Sprintf("Suspicious base64-encoded payload in %s", lastPathSegment(path)),
					Description: fmt.Sprintf("A large base64 block in %s decodes to content containing execution or network commands. This is a common obfuscation technique for memory-injected payloads.", path),
					Remediation: "Remove the suspicious content from the memory file. Investigate how it was written.",
					FilePath:    path,
					Snippet:     snippet,
					OWASP:       types.OWASPLLM01,
					CWE:         "CWE-506: Embedded Malicious Code",
				})
				break
			}
		}
	}
	return findings
}

func (d *MemoryPoisoningDetector) checkMem004MaliciousURLs(workspace *parser.WorkspaceData) []types.Finding {
	var findings []types.Finding
	maliciousDomains := ioc.MaliciousDomains()
	files := map[string]string{
		workspace.SoulPath:     workspace.SoulMD,
		workspace.MemoryPath:   workspace.MemoryMD,
		workspace.IdentityPath: workspace.IdentityMD,
	}
	for path, content := range files {
		if content == "" {
			continue
		}
		matches := externalURLPattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			domain := match[1]
			if _, found := maliciousDomains[domain]; found {
				findings = append(findings, types.Finding{
					ID:          "MEM-004",
					Severity:    types.SeverityCritical,
					Category:    types.CategoryMemoryPoisoning,
					Title:       fmt.Sprintf("Known malicious domain %q found in %s", domain, lastPathSegment(path)),
					Description: fmt.Sprintf("The memory file %s contains a reference to %s, which is on the IOC malicious domains list. This may indicate memory poisoning for data exfiltration.", path, domain),
					Remediation: "Remove the URL from the memory file. Investigate whether any data was sent to this domain.",
					FilePath:    path,
					Snippet:     match[0],
					OWASP:       types.OWASPLLM04,
					CWE:         "CWE-610: Externally Controlled Reference to a Resource in Another Sphere",
				})
			}
		}
	}
	return findings
}

func (d *MemoryPoisoningDetector) checkMem005FilePermissions(workspace *parser.WorkspaceData) []types.Finding {
	var findings []types.Finding
	paths := []string{workspace.SoulPath, workspace.MemoryPath, workspace.IdentityPath}
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		mode := info.Mode().Perm()
		if mode&0044 != 0 {
			findings = append(findings, types.Finding{
				ID:          "MEM-005",
				Severity:    types.SeverityMedium,
				Category:    types.CategoryMemoryPoisoning,
				Title:       fmt.Sprintf("Memory file %s has insecure permissions (%04o)", lastPathSegment(path), mode),
				Description: fmt.Sprintf("The file %s has permissions %04o making it readable by other users. Agent memory files may contain sensitive conversation context.", path, mode),
				Remediation: fmt.Sprintf("Run: chmod 600 %s", path),
				FilePath:    path,
				OWASP:       types.OWASPLLM02,
				CWE:         "CWE-732: Incorrect Permission Assignment for Critical Resource",
			})
		}
	}
	return findings
}

func lastPathSegment(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}
