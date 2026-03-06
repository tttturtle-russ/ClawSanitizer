package detectors

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

type DiscoveryDetector struct{}

func NewDiscoveryDetector() *DiscoveryDetector {
	return &DiscoveryDetector{}
}

func (d *DiscoveryDetector) Detect(workspace *parser.WorkspaceData, tools []parser.MCPTool) []types.Finding {
	var findings []types.Finding
	if workspace != nil {
		findings = append(findings, d.checkD1AgentsMDPoisoning(workspace)...)
		findings = append(findings, d.checkD2DangerousTools(workspace)...)
		findings = append(findings, d.checkD3HeartbeatShadowTasks(workspace)...)
	}
	findings = append(findings, d.checkD4MCPToolPoisoning(tools)...)
	findings = append(findings, d.checkD5UnicodeHomograph(tools)...)
	findings = append(findings, d.checkD6PermissionOverreach(tools)...)
	return findings
}

var poisoningPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)send.{0,30}(to|via).{0,50}(https?://|ftp://)`),
	regexp.MustCompile(`(?i)ignore.{0,30}(safety|security|instruction|guideline|rule)`),
	regexp.MustCompile(`(?i)read.{0,30}(\.env|\.ssh|\.aws|id_rsa|credentials|password|secret)`),
	regexp.MustCompile(`(?i)(exfiltrate|exfil|steal|leak|send).{0,30}(data|file|credential|key|token)`),
	regexp.MustCompile(`(?i)(http|https|ftp)://[a-z0-9.-]+\.(xyz|tk|top|pw|cc|gq|cf|ml)\b`),
	regexp.MustCompile(`(?i)do not (tell|inform|notify|mention).{0,30}(user|owner|human)`),
	regexp.MustCompile(`(?i)(post|curl|wget|http).{0,50}(collector|exfil|harvest|beacon)`),
}

func (d *DiscoveryDetector) checkD1AgentsMDPoisoning(workspace *parser.WorkspaceData) []types.Finding {
	if workspace.AgentsMD == "" {
		return nil
	}

	var findings []types.Finding
	for _, re := range poisoningPatterns {
		if match := re.FindString(workspace.AgentsMD); match != "" {
			findings = append(findings, types.Finding{
				ID:          "DISCOVERY-001",
				Severity:    types.SeverityCritical,
				Category:    types.CategoryDiscovery,
				Title:       "Suspicious instructions found in AGENTS.md",
				Description: fmt.Sprintf("Your AGENTS.md file contains instructions that look like an attempt to make your AI agent secretly send data or bypass safety rules. Suspicious pattern: \"%s\"", truncate(match, 100)),
				Remediation: "Open ~/.openclaw/workspace/AGENTS.md and remove any instructions you did not write yourself. If you did not create this file, delete it entirely.",
				FilePath:    workspace.AgentsPath,
				OWASP:       types.OWASPLLM01,
				CWE:         "CWE-74: Improper Neutralization of Special Elements in Output",
			})
			break
		}
	}

	return findings
}

var dangerousToolPatterns = []string{
	"shell_execute", "shell_exec", "run_command", "exec_command",
	"unsafe_web_browser", "unrestricted_browser",
	"file_access", "read_all_files", "write_all_files",
}

func (d *DiscoveryDetector) checkD2DangerousTools(workspace *parser.WorkspaceData) []types.Finding {
	if workspace.ToolsMD == "" {
		return nil
	}

	var findings []types.Finding
	toolsLower := strings.ToLower(workspace.ToolsMD)
	for _, pattern := range dangerousToolPatterns {
		if strings.Contains(toolsLower, pattern) {
			findings = append(findings, types.Finding{
				ID:          "DISCOVERY-002",
				Severity:    types.SeverityHigh,
				Category:    types.CategoryDiscovery,
				Title:       fmt.Sprintf("Dangerous tool capability '%s' found in TOOLS.md", pattern),
				Description: fmt.Sprintf("Your TOOLS.md file defines a tool called '%s' which can give the AI agent unrestricted access to run commands or access files on your computer.", pattern),
				Remediation: "Review ~/.openclaw/workspace/TOOLS.md and remove or restrict any tool definitions that allow unrestricted shell access or file access.",
				FilePath:    workspace.ToolsPath,
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-250: Execution with Unnecessary Privileges",
			})
			break
		}
	}

	return findings
}

var shadowTaskPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(every|each|schedule|cron|timer).{0,50}(minute|hour|day|second)`),
	regexp.MustCompile(`(?i)(post|send|upload|transmit|exfil).{0,50}(http|https|ftp)`),
	regexp.MustCompile(`(?i)scan.{0,30}(~\/\.ssh|~\/\.aws|\.env|credential|password)`),
	regexp.MustCompile(`(?i)(beacon|heartbeat|checkin|check.in).{0,30}(http|https|remote|server)`),
}

func (d *DiscoveryDetector) checkD3HeartbeatShadowTasks(workspace *parser.WorkspaceData) []types.Finding {
	if workspace.HeartbeatMD == "" {
		return nil
	}

	var findings []types.Finding
	for _, re := range shadowTaskPatterns {
		if match := re.FindString(workspace.HeartbeatMD); match != "" {
			findings = append(findings, types.Finding{
				ID:          "DISCOVERY-003",
				Severity:    types.SeverityCritical,
				Category:    types.CategoryDiscovery,
				Title:       "Suspicious background task found in HEARTBEAT.md",
				Description: fmt.Sprintf("Your HEARTBEAT.md file contains a scheduled task that looks suspicious: \"%s\". This task may be sending your data to a remote server in the background.", truncate(match, 100)),
				Remediation: "Open ~/.openclaw/workspace/HEARTBEAT.md and remove any tasks you did not create yourself. If you are unsure, delete the file entirely.",
				FilePath:    workspace.HeartbeatPath,
				OWASP:       types.OWASPLLM01,
				CWE:         "CWE-74: Improper Neutralization of Special Elements in Output",
			})
			break
		}
	}

	return findings
}

var toolPoisoningPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(ignore|bypass|override).{0,30}(instruction|safety|rule|guideline)`),
	regexp.MustCompile(`(?i)(send|post|upload).{0,50}(https?://)`),
	regexp.MustCompile(`(?i)read.{0,30}(\.env|\.ssh|password|secret|token|credential)`),
	regexp.MustCompile(`(?i)(always|must|should).{0,30}(first|before).{0,30}(check|send|report)`),
}

func (d *DiscoveryDetector) checkD4MCPToolPoisoning(tools []parser.MCPTool) []types.Finding {
	var findings []types.Finding
	for _, tool := range tools {
		for _, re := range toolPoisoningPatterns {
			if match := re.FindString(tool.Description); match != "" {
				findings = append(findings, types.Finding{
					ID:          "DISCOVERY-004",
					Severity:    types.SeverityCritical,
					Category:    types.CategoryDiscovery,
					Title:       fmt.Sprintf("Tool '%s' contains hidden instructions in its description", tool.Name),
					Description: fmt.Sprintf("The MCP tool '%s' has hidden instructions in its description field that try to make the AI behave maliciously. Pattern found: \"%s\"", tool.Name, truncate(match, 100)),
					Remediation: fmt.Sprintf("Remove or replace the skill that provides the tool '%s'. This is a supply chain attack known as 'prompt injection via tool description'.", tool.Name),
					FilePath:    tool.Source,
					OWASP:       types.OWASPLLM01,
					CWE:         "CWE-74: Improper Neutralization of Special Elements in Output",
				})
				break
			}
		}
	}

	return findings
}

func (d *DiscoveryDetector) checkD5UnicodeHomograph(tools []parser.MCPTool) []types.Finding {
	var findings []types.Finding
	for _, tool := range tools {
		if hasHomographChars(tool.Name) {
			findings = append(findings, types.Finding{
				ID:          "DISCOVERY-005",
				Severity:    types.SeverityHigh,
				Category:    types.CategoryDiscovery,
				Title:       fmt.Sprintf("Tool name '%s' contains suspicious look-alike characters", tool.Name),
				Description: fmt.Sprintf("The tool '%s' uses non-standard Unicode characters that look like regular letters but are different. This is a trick used to make malicious tools look like legitimate ones.", tool.Name),
				Remediation: "Remove this tool/skill. Legitimate tools should only use standard ASCII letters, numbers, and hyphens in their names.",
				FilePath:    tool.Source,
				OWASP:       types.OWASPLLM01,
				CWE:         "CWE-1007: Insufficient Visual Distinction of Homoglyphs",
			})
		}
	}

	return findings
}

func hasHomographChars(s string) bool {
	for _, r := range s {
		if r > 127 && unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

var sensitivePathPatterns = []string{
	"~/.ssh", ".ssh/id_rsa", ".ssh/id_ed25519",
	"~/.gnupg", ".gnupg/",
	"~/.aws/credentials", ".aws/credentials",
	"~/.config/google-chrome", "Application Support/Google/Chrome",
	"Library/Keychains",
	".env",
}

func (d *DiscoveryDetector) checkD6PermissionOverreach(tools []parser.MCPTool) []types.Finding {
	var findings []types.Finding
	for _, tool := range tools {
		descLower := strings.ToLower(tool.Description)
		for _, sensitive := range sensitivePathPatterns {
			if strings.Contains(descLower, strings.ToLower(sensitive)) {
				findings = append(findings, types.Finding{
					ID:          "DISCOVERY-006",
					Severity:    types.SeverityHigh,
					Category:    types.CategoryDiscovery,
					Title:       fmt.Sprintf("Tool '%s' references sensitive credential path", tool.Name),
					Description: fmt.Sprintf("The tool '%s' mentions access to '%s' in its description. This sensitive location contains credentials or encryption keys and should not be accessible to AI tools.", tool.Name, sensitive),
					Remediation: "Review and remove this tool. No legitimate AI assistant tool needs direct access to SSH keys, browser profiles, or credential stores.",
					FilePath:    tool.Source,
					OWASP:       types.OWASPLLM06,
					CWE:         "CWE-250: Execution with Unnecessary Privileges",
				})
				break
			}
		}
	}

	return findings
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
