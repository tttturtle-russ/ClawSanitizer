package detectors

import (
	"github.com/tttturtle-russ/clawsan/internal/types"
)

const arkClawProviderKey = "volcengine"

type ArkClawDetector struct{}

func NewArkClawDetector() *ArkClawDetector {
	return &ArkClawDetector{}
}

func (d *ArkClawDetector) Detect(cfg *types.OpenClawConfig) []types.Finding {
	if cfg == nil {
		return nil
	}
	provider, ok := cfg.Models.Providers[arkClawProviderKey]
	if !ok {
		return nil
	}
	if provider.ApiKey == "" {
		return nil
	}
	return []types.Finding{
		{
			ID:          "ARKCLAW-001",
			Severity:    types.SeverityCritical,
			Category:    types.CategoryArkClaw,
			Title:       "ArkClaw Volcengine API key stored as plaintext in openclaw.json",
			Description: "models.providers.volcengine.apiKey contains a non-empty value. This Volcano Engine API key is stored unencrypted in the config file and grants access to ArkClaw model endpoints.",
			Remediation: "Remove the apiKey from openclaw.json. Set it via the VOLCENGINE_API_KEY environment variable or the OS keychain.",
			OWASP:       types.OWASPLLM02,
			CWE:         "CWE-312: Cleartext Storage of Sensitive Information",
			References:  []string{"https://ark.volcengine.com/api/v1"},
		},
	}
}
