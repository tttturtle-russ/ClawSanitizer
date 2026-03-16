package detectors

import (
	"fmt"
	"os"
	"regexp"

	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

var apiKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`sk-proj-[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`xoxb-[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`xoxp-[A-Za-z0-9_\-]{20,}`),
}

type CredentialStorageDetector struct{}

func NewCredentialStorageDetector() *CredentialStorageDetector {
	return &CredentialStorageDetector{}
}

func (d *CredentialStorageDetector) Detect(installPath string, workspace *parser.WorkspaceData) []types.Finding {
	var findings []types.Finding
	if f := d.checkCred001DirPermissions(installPath); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkCred002ConfigPermissions(installPath); f != nil {
		findings = append(findings, *f)
	}
	if workspace != nil {
		findings = append(findings, d.checkCred007ApiKeysInMemoryFiles(workspace)...)
	}
	return findings
}

func (d *CredentialStorageDetector) checkCred001DirPermissions(installPath string) *types.Finding {
	info, err := os.Stat(installPath)
	if err != nil {
		return nil
	}
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return &types.Finding{
			ID:          "CRED-001",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryCredentialStorage,
			Title:       fmt.Sprintf("OpenClaw directory has insecure permissions (%04o)", mode),
			Description: fmt.Sprintf("The directory %s has permissions %04o. Other users on this system may be able to read your credentials and configuration.", installPath, mode),
			Remediation: fmt.Sprintf("Run: chmod 700 %s", installPath),
			FilePath:    installPath,
			OWASP:       types.OWASPLLM02,
			CWE:         "CWE-732: Incorrect Permission Assignment for Critical Resource",
		}
	}
	return nil
}

func (d *CredentialStorageDetector) checkCred002ConfigPermissions(installPath string) *types.Finding {
	configPath := installPath + "/openclaw.json"
	info, err := os.Stat(configPath)
	if err != nil {
		return nil
	}
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return &types.Finding{
			ID:          "CRED-002",
			Severity:    types.SeverityCritical,
			Category:    types.CategoryCredentialStorage,
			Title:       fmt.Sprintf("openclaw.json has insecure permissions (%04o)", mode),
			Description: fmt.Sprintf("The file %s has permissions %04o. This file contains authentication tokens and API keys that are readable by other users.", configPath, mode),
			Remediation: fmt.Sprintf("Run: chmod 600 %s", configPath),
			FilePath:    configPath,
			OWASP:       types.OWASPLLM02,
			CWE:         "CWE-732: Incorrect Permission Assignment for Critical Resource",
		}
	}
	return nil
}

func (d *CredentialStorageDetector) checkCred007ApiKeysInMemoryFiles(workspace *parser.WorkspaceData) []types.Finding {
	var findings []types.Finding
	files := map[string]string{
		workspace.SoulPath:     workspace.SoulMD,
		workspace.MemoryPath:   workspace.MemoryMD,
		workspace.IdentityPath: workspace.IdentityMD,
		workspace.AgentsPath:   workspace.AgentsMD,
	}
	for path, content := range files {
		if content == "" {
			continue
		}
		for _, re := range apiKeyPatterns {
			if loc := re.FindStringIndex(content); loc != nil {
				snippet := content[loc[0]:loc[1]]
				if len(snippet) > 20 {
					snippet = snippet[:8] + "..."
				}
				findings = append(findings, types.Finding{
					ID:          "CRED-007",
					Severity:    types.SeverityCritical,
					Category:    types.CategoryCredentialStorage,
					Title:       "API key pattern found in workspace memory file",
					Description: fmt.Sprintf("A credential matching an API key pattern was found in %s. Memory files are persisted to disk and may be transmitted to AI models.", path),
					Remediation: "Remove the API key from the memory file immediately. Rotate the compromised credential.",
					FilePath:    path,
					Snippet:     snippet,
					OWASP:       types.OWASPLLM02,
					CWE:         "CWE-312: Cleartext Storage of Sensitive Information",
				})
				break
			}
		}
	}
	return findings
}
