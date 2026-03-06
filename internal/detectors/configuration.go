package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

// ConfigurationDetector checks for dangerous OpenClaw configuration settings
type ConfigurationDetector struct{}

// NewConfigurationDetector creates a new configuration detector
func NewConfigurationDetector() *ConfigurationDetector {
	return &ConfigurationDetector{}
}

// Detect runs all C1-C7 configuration checks
func (d *ConfigurationDetector) Detect(cfg *types.OpenClawConfig) []types.Finding {
	if cfg == nil {
		return nil
	}
	var findings []types.Finding
	if f := d.checkC1DangerouslySkipPermissions(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC2DMPolicy(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC3WorkspaceDir(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC4APIKeyInConfig(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC5GatewayBinding(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC6GatewayAuth(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC7TunnelAuth(cfg); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

// C1: dangerously_skip_permissions: true — disables ALL confirmation prompts
func (d *ConfigurationDetector) checkC1DangerouslySkipPermissions(cfg *types.OpenClawConfig) *types.Finding {
	if !cfg.DangerouslySkipPermissions {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-001",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryConfiguration,
		Title:       "All permission prompts are disabled",
		Description: "The setting 'dangerously_skip_permissions: true' is enabled. This means OpenClaw can read files, run commands, and send messages WITHOUT asking you first. Any skill or instruction can do anything on your computer silently.",
		Remediation: "Open ~/.openclaw/config.json and change 'dangerously_skip_permissions' to false. Then restart OpenClaw.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-732: Incorrect Permission Assignment for Critical Resource",
	}
}

// C2: dmPolicy: "open" with allowFrom: ["*"] — anyone can DM and control the agent
func (d *ConfigurationDetector) checkC2DMPolicy(cfg *types.OpenClawConfig) *types.Finding {
	if cfg.DMPolicy != "open" {
		return nil
	}
	hasWildcard := false
	for _, from := range cfg.AllowFrom {
		if from == "*" {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard && len(cfg.AllowFrom) > 0 {
		return nil // open but restricted to specific senders is less dangerous
	}
	return &types.Finding{
		ID:          "CONFIG-002",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       "Anyone can send commands to your AI agent via direct messages",
		Description: "The DM policy is set to 'open' with no sender restrictions. This means any user on any connected platform (Slack, Discord, Telegram, etc.) can send instructions to your OpenClaw agent and it will execute them.",
		Remediation: "In ~/.openclaw/config.json, change 'dmPolicy' to 'closed' or set 'allowFrom' to a list of trusted user IDs only.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-284: Improper Access Control",
	}
}

// C3: workspace_dir set to dangerous path (/ or ~)
func (d *ConfigurationDetector) checkC3WorkspaceDir(cfg *types.OpenClawConfig) *types.Finding {
	dir := cfg.WorkspaceDir
	if dir == "" {
		return nil
	}
	dangerous := dir == "/" || dir == "~" || dir == "~/" || dir == "/home" || dir == "/root"
	if !dangerous {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-003",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       "Workspace directory is set to an overly broad path",
		Description: fmt.Sprintf("The workspace_dir is set to '%s'. This gives the AI agent access to a very large portion of your filesystem, making it easy for a malicious skill to read or modify important files.", dir),
		Remediation: "Set workspace_dir to a specific, limited directory like '~/.openclaw/workspace' in your config.json.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-732: Incorrect Permission Assignment for Critical Resource",
	}
}

// C4: API key stored in plaintext config
func (d *ConfigurationDetector) checkC4APIKeyInConfig(cfg *types.OpenClawConfig) *types.Finding {
	if cfg.APIKey == "" {
		return nil
	}
	// Check if it looks like a real API key (not empty or placeholder)
	apiKeyRe := regexp.MustCompile(`^(sk-|pk-|key-|token-|secret-)?[a-zA-Z0-9_\-]{16,}$`)
	if !apiKeyRe.MatchString(cfg.APIKey) {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-004",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       "API key is stored in plaintext in config file",
		Description: "Your API key is stored as plain text in ~/.openclaw/config.json. Any program that can read this file — including malicious skills — can steal your API key and use it to run up charges or access your AI account.",
		Remediation: "Remove the API key from config.json and use your operating system's secure keychain instead. Check OpenClaw's documentation for 'secure credential storage'.",
		OWASP:       types.OWASPLLM02,
		CWE:         "CWE-312: Cleartext Storage of Sensitive Information",
	}
}

// C5: Gateway bound to all interfaces (0.0.0.0)
func (d *ConfigurationDetector) checkC5GatewayBinding(cfg *types.OpenClawConfig) *types.Finding {
	if cfg.Gateway.Bind != "0.0.0.0" {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-005",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       "OpenClaw gateway is exposed to all network interfaces",
		Description: "The gateway is bound to 0.0.0.0, which means it is accessible from other devices on your network (and potentially the internet). Anyone who can reach your computer on the network can connect to your AI agent.",
		Remediation: "In ~/.openclaw/config.json, change gateway.bind to '127.0.0.1' to restrict access to your local machine only.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-284: Improper Access Control",
	}
}

// C6: Gateway authentication disabled
func (d *ConfigurationDetector) checkC6GatewayAuth(cfg *types.OpenClawConfig) *types.Finding {
	if cfg.Gateway.Auth {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-006",
		Severity:    types.SeverityMedium,
		Category:    types.CategoryConfiguration,
		Title:       "Gateway authentication is disabled",
		Description: "The OpenClaw gateway does not require authentication. Any application or browser on your computer can connect to and control your AI agent without needing a password or token.",
		Remediation: "In ~/.openclaw/config.json, set gateway.auth to true. Then update any integrations to use the generated authentication token.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-306: Missing Authentication for Critical Function",
	}
}

// C7: Tailscale or SSH tunnel without authentication
func (d *ConfigurationDetector) checkC7TunnelAuth(cfg *types.OpenClawConfig) *types.Finding {
	tailscaleRisk := cfg.Tailscale.Enabled && !cfg.Tailscale.Auth
	sshRisk := cfg.SSH.Enabled && !cfg.SSH.Auth

	if !tailscaleRisk && !sshRisk {
		return nil
	}

	var tunnelType string
	if tailscaleRisk && sshRisk {
		tunnelType = "Tailscale and SSH tunnels are"
	} else if tailscaleRisk {
		tunnelType = "Tailscale tunnel is"
	} else {
		tunnelType = "SSH tunnel is"
	}

	return &types.Finding{
		ID:          "CONFIG-007",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       fmt.Sprintf("%s enabled without authentication", strings.ToUpper(tunnelType[:1])+tunnelType[1:]),
		Description: fmt.Sprintf("The %s enabled but does not require authentication. This creates a remote access path to your AI agent without any password protection.", tunnelType),
		Remediation: "Enable authentication for the tunnel in config.json. Check OpenClaw's documentation for 'remote access security'.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-306: Missing Authentication for Critical Function",
	}
}
