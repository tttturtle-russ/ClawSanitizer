package detectors

import (
	"fmt"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

type AccessControlDetector struct{}

func NewAccessControlDetector() *AccessControlDetector {
	return &AccessControlDetector{}
}

func (d *AccessControlDetector) Detect(cfg *types.OpenClawConfig) []types.Finding {
	if cfg == nil {
		return nil
	}
	var findings []types.Finding
	findings = append(findings, d.checkAC001ChannelDmPolicyOpen(cfg)...)
	findings = append(findings, d.checkAC002ChannelGroupPolicyOpen(cfg)...)
	findings = append(findings, d.checkAC003ChannelWildcardAllowlist(cfg)...)
	findings = append(findings, d.checkAC004SandboxDisabled(cfg)...)
	findings = append(findings, d.checkAC005AcpAutoApproveAll(cfg)...)
	if f := d.checkAC006SessionDmScopeGlobal(cfg); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

func (d *AccessControlDetector) checkAC001ChannelDmPolicyOpen(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	for name, ch := range cfg.Channels {
		if ch.DmPolicy == "open" {
			findings = append(findings, types.Finding{
				ID:          "AC-001",
				Severity:    types.SeverityHigh,
				Category:    types.CategoryAccessControl,
				Title:       fmt.Sprintf("Channel %q has DM policy set to 'open'", name),
				Description: fmt.Sprintf("The channel %q allows DMs from any user (dmPolicy=open). Any person who can reach this channel can send commands to your agent.", name),
				Remediation: "Set dmPolicy to 'allowlist' and explicitly configure allowFrom with trusted user IDs.",
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-284: Improper Access Control",
			})
		}
	}
	return findings
}

func (d *AccessControlDetector) checkAC002ChannelGroupPolicyOpen(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	for name, ch := range cfg.Channels {
		if ch.GroupPolicy == "open" {
			findings = append(findings, types.Finding{
				ID:          "AC-002",
				Severity:    types.SeverityHigh,
				Category:    types.CategoryAccessControl,
				Title:       fmt.Sprintf("Channel %q has group policy set to 'open'", name),
				Description: fmt.Sprintf("The channel %q allows group messages from any group (groupPolicy=open). Any group member can send commands to your agent.", name),
				Remediation: "Set groupPolicy to 'allowlist' and restrict which groups can interact with the agent.",
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-284: Improper Access Control",
			})
		}
	}
	return findings
}

func (d *AccessControlDetector) checkAC003ChannelWildcardAllowlist(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	for name, ch := range cfg.Channels {
		for _, entry := range ch.AllowFrom {
			if entry == "*" {
				findings = append(findings, types.Finding{
					ID:          "AC-003",
					Severity:    types.SeverityHigh,
					Category:    types.CategoryAccessControl,
					Title:       fmt.Sprintf("Channel %q allowFrom contains wildcard '*'", name),
					Description: fmt.Sprintf("The channel %q has a wildcard entry in allowFrom. This grants any user access to issue commands to the agent.", name),
					Remediation: "Replace '*' with specific trusted user IDs in the allowFrom list.",
					OWASP:       types.OWASPLLM06,
					CWE:         "CWE-284: Improper Access Control",
				})
				break
			}
		}
		for _, entry := range ch.AllowList {
			if entry == "*" {
				findings = append(findings, types.Finding{
					ID:          "AC-003B",
					Severity:    types.SeverityHigh,
					Category:    types.CategoryAccessControl,
					Title:       fmt.Sprintf("Channel %q allowlist contains wildcard '*'", name),
					Description: fmt.Sprintf("The channel %q has a wildcard entry in allowlist. This grants any user access.", name),
					Remediation: "Replace '*' with specific trusted user IDs.",
					OWASP:       types.OWASPLLM06,
					CWE:         "CWE-284: Improper Access Control",
				})
				break
			}
		}
	}
	return findings
}

func (d *AccessControlDetector) checkAC004SandboxDisabled(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	mode := cfg.Sandbox.Mode
	if mode == "off" || mode == "none" || mode == "permissive" {
		findings = append(findings, types.Finding{
			ID:          "AC-004",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryAccessControl,
			Title:       fmt.Sprintf("Execution sandbox is disabled or weakened (mode=%q)", mode),
			Description: fmt.Sprintf("The sandbox.mode is set to %q. Agent tool calls run with reduced or no sandboxing, increasing the blast radius of prompt injection or malicious skill execution.", mode),
			Remediation: "Set sandbox.mode to 'strict' to restrict filesystem and network access for agent tool calls.",
			OWASP:       types.OWASPLLM06,
			CWE:         "CWE-693: Protection Mechanism Failure",
		})
	}
	return findings
}

func (d *AccessControlDetector) checkAC005AcpAutoApproveAll(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	if cfg.Acp.AutoApprove == "all" {
		findings = append(findings, types.Finding{
			ID:          "AC-005",
			Severity:    types.SeverityCritical,
			Category:    types.CategoryAccessControl,
			Title:       "ACP auto-approval is set to 'all' (GHSA-7jx5)",
			Description: "acp.autoApprove=all causes the agent to approve all tool calls without human review. This is the configuration exploited in GHSA-7jx5 to achieve arbitrary command execution via prompt injection.",
			Remediation: "Set acp.autoApprove to 'none' or 'trusted'. Never use 'all' in production.",
			OWASP:       types.OWASPLLM06,
			CWE:         "CWE-306: Missing Authentication for Critical Function",
			References:  []string{"GHSA-7jx5"},
		})
	}
	return findings
}

func (d *AccessControlDetector) checkAC006SessionDmScopeGlobal(cfg *types.OpenClawConfig) *types.Finding {
	if len(cfg.Channels) < 2 {
		return nil
	}
	if cfg.Session.DmScope == "global" || cfg.Session.DmScope == "" {
		return &types.Finding{
			ID:          "AC-006",
			Severity:    types.SeverityMedium,
			Category:    types.CategoryAccessControl,
			Title:       "Session DM scope is global across multiple channels",
			Description: fmt.Sprintf("With %d channels configured, session.dmScope=%q allows conversation context from one channel to bleed into another. An attacker in one channel may manipulate the agent's context for actions in another channel.", len(cfg.Channels), cfg.Session.DmScope),
			Remediation: "Set session.dmScope to 'per-channel-peer' to isolate context between channels.",
			OWASP:       types.OWASPLLM01,
			CWE:         "CWE-668: Exposure of Resource to Wrong Sphere",
		}
	}
	return nil
}
