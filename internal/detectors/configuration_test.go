package detectors

import (
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

func TestConfiguration_VulnerableConfig_AllFindings(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Bind: "lan",
			Auth: types.GatewayAuth{Mode: "none"},
			ControlUi: types.GatewayControlUi{
				DangerouslyDisableDeviceAuth:             true,
				DangerouslyAllowHostHeaderOriginFallback: true,
				AllowedOrigins:                           []string{"*"},
			},
			Tailscale: types.GatewayTailscale{Mode: "funnel"},
		},
		Agents:    types.AgentsConfig{Defaults: types.AgentDefaults{Workspace: "/"}},
		Logging:   types.LoggingConfig{RedactSensitive: "off"},
		Discovery: types.DiscoveryConfig{Mdns: types.MdnsConfig{Mode: "full"}},
	}
	findings := d.Detect(cfg)
	if len(findings) < 6 {
		t.Errorf("expected at least 6 findings from vulnerable config, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Found: %s - %s", f.ID, f.Title)
		}
	}
}

func TestConfiguration_C1_DangerouslyDisableDeviceAuth(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Auth:      types.GatewayAuth{Mode: "token", Token: "valid-token-here"},
			ControlUi: types.GatewayControlUi{DangerouslyDisableDeviceAuth: true},
		},
	}
	f := d.checkC1DangerouslyDisableDeviceAuth(cfg)
	if f == nil {
		t.Fatal("expected finding, got nil")
	}
	if f.ID != "CONFIG-001" {
		t.Errorf("expected CONFIG-001, got %s", f.ID)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
}

func TestConfiguration_C1_SafeConfig(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Auth:      types.GatewayAuth{Mode: "token", Token: "valid-token-here"},
			ControlUi: types.GatewayControlUi{DangerouslyDisableDeviceAuth: false},
		},
	}
	f := d.checkC1DangerouslyDisableDeviceAuth(cfg)
	if f != nil {
		t.Error("expected nil finding for safe config, got finding")
	}
}

func TestConfiguration_C5_GatewayBindLan(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Bind: "lan",
			Auth: types.GatewayAuth{Mode: "token", Token: "valid-token-here"},
		},
	}
	f := d.checkC5GatewayBindLan(cfg)
	if f == nil {
		t.Fatal("expected finding for lan binding")
	}
	if f.ID != "CONFIG-005" {
		t.Errorf("expected CONFIG-005, got %s", f.ID)
	}
}

func TestConfiguration_CleanConfig_NoFindings(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Bind: "loopback",
			Auth: types.GatewayAuth{Mode: "password", Password: "strongpassword"},
			ControlUi: types.GatewayControlUi{
				AllowedOrigins: []string{"https://control.example.com"},
			},
			Tailscale: types.GatewayTailscale{Mode: "off"},
		},
		Agents:  types.AgentsConfig{Defaults: types.AgentDefaults{Workspace: "/home/user/.openclaw/workspace"}},
		Logging: types.LoggingConfig{RedactSensitive: "tools"},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean config, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Unexpected: %s - %s", f.ID, f.Title)
		}
	}
}

func TestConfiguration_C4_GatewayTokenPlaintext(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Auth: types.GatewayAuth{Mode: "token", Token: "plaintext-secret-token"},
		},
	}
	f := d.checkC4GatewayTokenPlaintext(cfg)
	if f == nil {
		t.Fatal("expected CONFIG-004 finding for plaintext token, got nil")
	}
	if f.ID != "CONFIG-004" {
		t.Errorf("expected CONFIG-004, got %s", f.ID)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}

func TestConfiguration_C4_EmptyToken_NoFinding(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Auth: types.GatewayAuth{Mode: "none"},
		},
	}
	f := d.checkC4GatewayTokenPlaintext(cfg)
	if f != nil {
		t.Errorf("expected nil finding for empty token, got %s", f.ID)
	}
}

func TestConfiguration_C6_GatewayAuthPresent_NoFinding(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Auth: types.GatewayAuth{Mode: "token", Token: "some-token"},
		},
	}
	f := d.checkC6GatewayNoAuth(cfg)
	if f != nil {
		t.Errorf("expected nil finding when auth token is set, got %s", f.ID)
	}
}

func TestConfiguration_NilConfig_NoFindings(t *testing.T) {
	d := NewConfigurationDetector()
	findings := d.Detect(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil config, got %d", len(findings))
	}
}

func TestConfiguration_EmptyConfig_HasExpectedFindings(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{}
	findings := d.Detect(cfg)
	hasC6 := false
	for _, f := range findings {
		if f.ID == "CONFIG-006" {
			hasC6 = true
		}
	}
	if !hasC6 {
		t.Errorf("expected CONFIG-006 from zero-value config (no auth token), got findings: %v", findings)
	}
}

func TestConfiguration_C7_TailscaleFunnel(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Auth:      types.GatewayAuth{Mode: "token", Token: "valid-token"},
			Tailscale: types.GatewayTailscale{Mode: "funnel"},
		},
	}
	f := d.checkC7TailscaleFunnel(cfg)
	if f == nil {
		t.Fatal("expected CONFIG-007 for tailscale funnel mode, got nil")
	}
	if f.ID != "CONFIG-007" {
		t.Errorf("expected CONFIG-007, got %s", f.ID)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
}

func TestConfiguration_C8_WildcardAllowedOrigins(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		Gateway: types.GatewayConfig{
			Auth: types.GatewayAuth{Mode: "token", Token: "valid-token"},
			ControlUi: types.GatewayControlUi{
				AllowedOrigins: []string{"https://example.com", "*"},
			},
		},
	}
	f := d.checkC8WildcardAllowedOrigins(cfg)
	if f == nil {
		t.Fatal("expected CONFIG-008 for wildcard origin, got nil")
	}
	if f.ID != "CONFIG-008" {
		t.Errorf("expected CONFIG-008, got %s", f.ID)
	}
}
