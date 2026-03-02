package detectors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/clawsanitizer/internal/api"
	"github.com/yourusername/clawsanitizer/internal/types"
)

func makeTestSupplyChainDetector(server *httptest.Server) *SupplyChainDetector {
	client := api.NewClawHubClient()
	if server != nil {
		client.BaseURL = server.URL
	}
	return &SupplyChainDetector{ClawHub: client}
}

func TestSupplyChain_S1_MissingHash(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "my-skill", Source: "clawhub://my-skill@1.0.0", Hash: ""},
		},
	}
	findings := d.checkS1HashVerification(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-001" {
		t.Errorf("expected ID SUPPLY_CHAIN-001, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S2_MaliciousSkill(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"evil-skill","malicious":true,"reason":"Known data exfiltration tool"}`))
	}))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "evil-skill", Source: "clawhub://evil-skill@1.0.0", Hash: "abc123"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-002" {
		t.Errorf("expected ID SUPPLY_CHAIN-002, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S2_OfflineFallback(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "skill-a", Source: "clawhub://skill-a@1.0.0", Hash: "abc"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 0 {
		t.Errorf("offline should produce 0 findings, got %d", len(findings))
	}
}

func TestSupplyChain_S3_UnofficialSource(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "my-skill", Source: "https://github.com/unknown/my-skill", Hash: "abc"},
		},
	}
	findings := d.checkS3UnofficialSources(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-003" {
		t.Errorf("expected SUPPLY_CHAIN-003, got %s", findings[0].ID)
	}
}

func TestSupplyChain_NoSkills(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{Skills: []types.SkillConfig{}}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty skills, got %d", len(findings))
	}
}
