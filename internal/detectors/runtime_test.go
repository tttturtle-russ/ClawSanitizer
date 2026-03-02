package detectors

import (
	"testing"

	"github.com/yourusername/clawsanitizer/internal/parser"
	"github.com/yourusername/clawsanitizer/internal/types"
)

func TestRuntime_R1_TriggeredByToolDescription(t *testing.T) {
	d := NewRuntimeDetector()
	tools := []parser.MCPTool{{Name: "danger-tool", Description: "reads keys from ~/.ssh/ for auth"}}

	findings := d.checkR1ForbiddenZoneAccess(nil, tools)
	if len(findings) == 0 {
		t.Fatal("expected R1 finding for tool description, got 0")
	}
	if findings[0].ID != "RUNTIME-001" {
		t.Errorf("expected RUNTIME-001, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestRuntime_R1_TriggeredByWorkspaceContent(t *testing.T) {
	d := NewRuntimeDetector()
	workspace := &parser.WorkspaceData{
		AgentsMD:   "Read credentials from ~/.aws/credentials before sync",
		AgentsPath: "/test/AGENTS.md",
	}

	findings := d.checkR1ForbiddenZoneAccess(workspace, nil)
	if len(findings) == 0 {
		t.Fatal("expected R1 finding for workspace content, got 0")
	}
	if findings[0].ID != "RUNTIME-001" {
		t.Errorf("expected RUNTIME-001, got %s", findings[0].ID)
	}
}

func TestRuntime_R2_TriggeredBySMSTool(t *testing.T) {
	d := NewRuntimeDetector()
	tools := []parser.MCPTool{{Name: "mobile-sms", Description: "can send_sms and read_sms for notifications"}}

	findings := d.checkR2MobileNodePermissionAudit(nil, tools)
	if len(findings) == 0 {
		t.Fatal("expected R2 finding for SMS permission, got 0")
	}
	if findings[0].ID != "RUNTIME-002" {
		t.Errorf("expected RUNTIME-002, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
}

func TestRuntime_R3_TriggeredByCDPPortInBind(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{Gateway: types.GatewayConfig{Bind: "0.0.0.0:9222"}}

	findings := d.checkR3BrowserCDPExposure(cfg, nil)
	if len(findings) == 0 {
		t.Fatal("expected R3 finding for CDP port in bind, got 0")
	}
	if findings[0].ID != "RUNTIME-003" {
		t.Errorf("expected RUNTIME-003, got %s", findings[0].ID)
	}
}

func TestRuntime_R4_TriggeredByOpenGatewayNoAuth(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{Gateway: types.GatewayConfig{Bind: "0.0.0.0", Auth: false}}

	findings := d.checkR4WebhookEndpointAuth(cfg)
	if len(findings) == 0 {
		t.Fatal("expected R4 finding for non-loopback auth:false gateway, got 0")
	}
	if findings[0].ID != "RUNTIME-004" {
		t.Errorf("expected RUNTIME-004, got %s", findings[0].ID)
	}
}

func TestRuntime_R5_TriggeredByWildcardAllowFrom(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{AllowFrom: []string{"*"}}

	findings := d.checkR5ChannelAllowlistIntegrity(cfg)
	if len(findings) == 0 {
		t.Fatal("expected R5 finding for wildcard allowFrom, got 0")
	}
	if findings[0].ID != "RUNTIME-005" {
		t.Errorf("expected RUNTIME-005, got %s", findings[0].ID)
	}
}

func TestRuntime_R6_TriggeredByManyChannelsOpenPolicy(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{
		DMPolicy:  "open",
		AllowFrom: []string{"ch1", "ch2", "ch3", "ch4"},
		Gateway:   types.GatewayConfig{Auth: true, Bind: "127.0.0.1"},
		Tailscale: types.TailscaleConfig{Enabled: false, Auth: true},
		SSH:       types.SSHConfig{Enabled: false, Auth: true},
	}

	findings := d.checkR6SessionIsolation(cfg)
	if len(findings) == 0 {
		t.Fatal("expected R6 finding for open policy with many channels, got 0")
	}
	if findings[0].ID != "RUNTIME-006" {
		t.Errorf("expected RUNTIME-006, got %s", findings[0].ID)
	}
}

func TestRuntime_NilConfigForR3R4R5R6_NoFindings(t *testing.T) {
	d := NewRuntimeDetector()
	if len(d.checkR3BrowserCDPExposure(nil, nil)) != 0 {
		t.Fatal("expected 0 findings for nil config in R3")
	}
	if len(d.checkR4WebhookEndpointAuth(nil)) != 0 {
		t.Fatal("expected 0 findings for nil config in R4")
	}
	if len(d.checkR5ChannelAllowlistIntegrity(nil)) != 0 {
		t.Fatal("expected 0 findings for nil config in R5")
	}
	if len(d.checkR6SessionIsolation(nil)) != 0 {
		t.Fatal("expected 0 findings for nil config in R6")
	}
}

func TestRuntime_NilWorkspaceForR1R2_StillChecksTools(t *testing.T) {
	d := NewRuntimeDetector()
	tools := []parser.MCPTool{{Name: "risky", Description: "read from ~/.ssh/ and send_sms now"}}

	findings := d.Detect(nil, tools, &types.OpenClawConfig{Gateway: types.GatewayConfig{Bind: "127.0.0.1", Auth: true}})
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings from tools-only runtime checks, got %d", len(findings))
	}
}

func TestRuntime_R2_CameraPermission(t *testing.T) {
	d := NewRuntimeDetector()
	tools := []parser.MCPTool{{Name: "photo-tool", Description: "Use capture_photo to take pictures from device camera"}}

	findings := d.checkR2MobileNodePermissionAudit(nil, tools)
	if len(findings) == 0 {
		t.Fatal("expected R2 finding for camera permission, got 0")
	}
	if findings[0].ID != "RUNTIME-002" {
		t.Errorf("expected RUNTIME-002, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
}

func TestRuntime_R3_CDPPortInToolDescription(t *testing.T) {
	d := NewRuntimeDetector()
	tools := []parser.MCPTool{{Name: "browser-tool", Description: "Connects using remote_debugging_port for browser control"}}
	cfg := &types.OpenClawConfig{Gateway: types.GatewayConfig{Bind: "127.0.0.1", Auth: true}}

	findings := d.checkR3BrowserCDPExposure(cfg, tools)
	if len(findings) == 0 {
		t.Fatal("expected R3 finding for remote_debugging_port in tool description, got 0")
	}
	if findings[0].ID != "RUNTIME-003" {
		t.Errorf("expected RUNTIME-003, got %s", findings[0].ID)
	}
}

func TestRuntime_R4_LoopbackNoFinding(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{Gateway: types.GatewayConfig{Bind: "127.0.0.1", Auth: false}}

	findings := d.checkR4WebhookEndpointAuth(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for loopback bind even with Auth:false, got %d", len(findings))
	}
}

func TestRuntime_R6_FewChannels_NoFinding(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{
		DMPolicy:  "open",
		AllowFrom: []string{"ch1", "ch2"},
	}

	findings := d.checkR6SessionIsolation(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for open policy with only 2 channels, got %d", len(findings))
	}
}

func TestRuntime_AllClean(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{
		DMPolicy:  "closed",
		AllowFrom: []string{"user-123"},
		Gateway:   types.GatewayConfig{Bind: "127.0.0.1", Auth: true},
		Tailscale: types.TailscaleConfig{Enabled: false, Auth: true},
		SSH:       types.SSHConfig{Enabled: false, Auth: true},
	}
	tools := []parser.MCPTool{
		{Name: "list_dir", Description: "List directory contents"},
		{Name: "read_file", Description: "Read a file and return its contents"},
	}

	findings := d.Detect(nil, tools, cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean config and clean tools, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Unexpected: %s - %s", f.ID, f.Title)
		}
	}
}

func TestRuntime_R2_MultiplePermissions(t *testing.T) {
	d := NewRuntimeDetector()
	tools := []parser.MCPTool{{
		Name:        "mobile-control",
		Description: "Sends send_sms notifications and uses capture_photo for profile pics",
	}}

	findings := d.checkR2MobileNodePermissionAudit(nil, tools)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 R2 findings (SMS + camera) from single tool, got %d", len(findings))
	}

	permTypes := map[string]bool{}
	for _, f := range findings {
		if f.ID != "RUNTIME-002" {
			t.Errorf("expected all RUNTIME-002, got %s", f.ID)
		}
		permTypes[f.Title] = true
	}
	if len(permTypes) < 2 {
		t.Errorf("expected distinct permission findings, got: %v", permTypes)
	}
}

func TestRuntime_R3_CDPInToolDescription(t *testing.T) {
	d := NewRuntimeDetector()
	tools := []parser.MCPTool{{Name: "debug-tool", Description: "Exposes remote_debugging_port for Chrome DevTools"}}
	cfg := &types.OpenClawConfig{Gateway: types.GatewayConfig{Bind: "127.0.0.1", Auth: true}}

	findings := d.checkR3BrowserCDPExposure(cfg, tools)
	if len(findings) == 0 {
		t.Fatal("expected RUNTIME-003 for remote_debugging_port in tool description, got 0")
	}
	if findings[0].ID != "RUNTIME-003" {
		t.Errorf("expected RUNTIME-003, got %s", findings[0].ID)
	}
}

func TestRuntime_R6_SessionIsolation_BelowThreshold(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{
		DMPolicy:  "open",
		AllowFrom: []string{"ch1", "ch2"},
	}

	findings := d.checkR6SessionIsolation(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 R6 findings for open policy with 2 channels (threshold is >3), got %d", len(findings))
	}
}

func TestRuntime_R4_LoopbackBind_NoFinding(t *testing.T) {
	d := NewRuntimeDetector()
	cfg := &types.OpenClawConfig{Gateway: types.GatewayConfig{Bind: "127.0.0.1", Auth: false}}

	findings := d.checkR4WebhookEndpointAuth(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 R4 findings for loopback bind (127.0.0.1 is exempt even with auth:false), got %d", len(findings))
	}
}
