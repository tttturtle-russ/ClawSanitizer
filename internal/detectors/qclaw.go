package detectors

import (
	"github.com/tttturtle-russ/clawsan/internal/types"
)

const qclawChannelKey = "wechat-openclaw-channel"

type QClawDetector struct{}

func NewQClawDetector() *QClawDetector {
	return &QClawDetector{}
}

func (d *QClawDetector) Detect(cfg *types.OpenClawConfig) []types.Finding {
	if cfg == nil {
		return nil
	}
	ch, ok := cfg.Channels[qclawChannelKey]
	if !ok || ch.QClaw == nil {
		return nil
	}
	var findings []types.Finding
	if ch.QClaw.JwtToken != "" {
		findings = append(findings, types.Finding{
			ID:          "QCLAW-001",
			Severity:    types.SeverityCritical,
			Category:    types.CategoryQClaw,
			Title:       "QClaw JWT token stored as plaintext in openclaw.json",
			Description: "channels.wechat-openclaw-channel.qclaw.jwtToken contains a non-empty JWT. This token authenticates to the QClaw/Tencent messaging gateway and is stored unencrypted in the config file.",
			Remediation: "Remove the jwtToken from openclaw.json. Use QClaw's QR-code login flow so tokens are stored in the OS keychain instead.",
			OWASP:       types.OWASPLLM02,
			CWE:         "CWE-312: Cleartext Storage of Sensitive Information",
		})
	}
	if ch.QClaw.ChannelToken != "" {
		findings = append(findings, types.Finding{
			ID:          "QCLAW-002",
			Severity:    types.SeverityCritical,
			Category:    types.CategoryQClaw,
			Title:       "QClaw channel token stored as plaintext in openclaw.json",
			Description: "channels.wechat-openclaw-channel.qclaw.channelToken contains a non-empty value. This token is used for QClaw channel authentication and is stored unencrypted in the config file.",
			Remediation: "Remove the channelToken from openclaw.json and rotate it via the QClaw developer console.",
			OWASP:       types.OWASPLLM02,
			CWE:         "CWE-312: Cleartext Storage of Sensitive Information",
		})
	}
	if ch.QClaw.ApiKey != "" {
		findings = append(findings, types.Finding{
			ID:          "QCLAW-003",
			Severity:    types.SeverityCritical,
			Category:    types.CategoryQClaw,
			Title:       "QClaw API key stored as plaintext in openclaw.json",
			Description: "channels.wechat-openclaw-channel.qclaw.apiKey contains a non-empty value. This key is stored unencrypted and grants access to QClaw API endpoints.",
			Remediation: "Remove the apiKey from openclaw.json. Store it in the OS keychain or an environment variable.",
			OWASP:       types.OWASPLLM02,
			CWE:         "CWE-312: Cleartext Storage of Sensitive Information",
		})
	}
	return findings
}
