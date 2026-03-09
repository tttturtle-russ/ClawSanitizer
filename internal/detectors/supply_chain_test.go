package detectors

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/api"
	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

func makeTestSupplyChainDetector(server *httptest.Server) *SupplyChainDetector {
	client := api.NewClawHubClient()
	if server != nil {
		client.BaseURL = server.URL
	}
	return &SupplyChainDetector{ClawHub: client}
}

func skillHandler(skillBody, versionBody string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[2] == "versions" && versionBody != "" {
			w.Write([]byte(versionBody))
			return
		}
		w.Write([]byte(skillBody))
	}
}

func TestSupplyChain_S2_MaliciousSkill(t *testing.T) {
	skillBody := `{"skill":{"slug":"evil-skill","displayName":"Evil Skill"},"latestVersion":{"version":"1.0.0"},"moderation":{"isMalwareBlocked":true,"isSuspicious":false}}`
	server := httptest.NewServer(skillHandler(skillBody, ""))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	skills := []parser.InstalledSkill{{Slug: "evil-skill"}}
	findings := d.checkS2ClawHubReputation(skills)
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

func TestSupplyChain_S2_SuspiciousSkill(t *testing.T) {
	skillBody := `{"skill":{"slug":"feed-watcher","displayName":"Feed Watcher"},"latestVersion":{"version":"1.2.0"},"moderation":null}`
	versionBody := `{"version":{"version":"1.2.0","security":{"status":"suspicious","hasWarnings":true,"checkedAt":1772465516623,"model":"gpt-5-mini"}}}`
	server := httptest.NewServer(skillHandler(skillBody, versionBody))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	skills := []parser.InstalledSkill{{Slug: "feed-watcher"}}
	findings := d.checkS2ClawHubReputation(skills)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for suspicious skill, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-002B" {
		t.Errorf("expected ID SUPPLY_CHAIN-002B, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected HIGH severity for suspicious skill, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S2_MaliciousViaSecurityStatus(t *testing.T) {
	skillBody := `{"skill":{"slug":"data-harvester-v2","displayName":"Data Harvester"},"latestVersion":{"version":"2.0.0"},"moderation":null}`
	versionBody := `{"version":{"version":"2.0.0","security":{"status":"malicious","hasWarnings":true,"checkedAt":1772465516623,"model":"gpt-5-mini"}}}`
	server := httptest.NewServer(skillHandler(skillBody, versionBody))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	skills := []parser.InstalledSkill{{Slug: "data-harvester-v2"}}
	findings := d.checkS2ClawHubReputation(skills)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for malicious security status, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S2_OfflineFallback(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	skills := []parser.InstalledSkill{{Slug: "skill-a"}}
	findings := d.checkS2ClawHubReputation(skills)
	if len(findings) != 0 {
		t.Errorf("offline should produce 0 findings, got %d", len(findings))
	}
}

func TestSupplyChain_NoSkills(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	findings := d.Detect(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil skills, got %d", len(findings))
	}
}

func TestSupplyChain_S2_OfflineGracefulFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()

	client := api.NewClawHubClient()
	client.BaseURL = server.URL
	d := &SupplyChainDetector{ClawHub: client}

	skills := []parser.InstalledSkill{{Slug: "any-skill"}}
	findings := d.checkS2ClawHubReputation(skills)
	if len(findings) != 0 {
		t.Errorf("offline fallback should produce 0 findings, got %d", len(findings))
	}
}

func TestSupplyChain_S2_CleanSkill(t *testing.T) {
	skillBody := `{"skill":{"slug":"clean-skill","displayName":"Clean Skill"},"latestVersion":{"version":"1.0.0"},"moderation":null}`
	versionBody := `{"version":{"version":"1.0.0","security":{"status":"clean","hasWarnings":false,"checkedAt":1772465516623,"model":"gpt-5-mini"}}}`
	server := httptest.NewServer(skillHandler(skillBody, versionBody))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	skills := []parser.InstalledSkill{{Slug: "clean-skill"}}
	findings := d.checkS2ClawHubReputation(skills)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean skill, got %d", len(findings))
	}
}

func TestSupplyChain_S4_DangerousName(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	skills := []parser.InstalledSkill{{Slug: "shell-runner"}}
	findings := d.checkS4DangerousName(skills)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for dangerous-named skill, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-004" {
		t.Errorf("expected ID SUPPLY_CHAIN-004, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected severity HIGH, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S4_SafeName_NoFinding(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	skills := []parser.InstalledSkill{{Slug: "markdown-helper"}}
	findings := d.checkS4DangerousName(skills)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe-named skill, got %d findings", len(findings))
	}
}

func TestSupplyChain_S4_AllDangerousKeywords(t *testing.T) {
	keywords := []string{"shell", "exec", "execute", "root", "sudo", "admin", "system"}
	for _, kw := range keywords {
		kw := kw
		t.Run(kw, func(t *testing.T) {
			d := makeTestSupplyChainDetector(nil)
			skills := []parser.InstalledSkill{{Slug: kw + "-tool"}}
			findings := d.checkS4DangerousName(skills)
			if len(findings) != 1 {
				t.Errorf("keyword %q: expected 1 finding, got %d", kw, len(findings))
			}
		})
	}
}

func TestSupplyChain_FindingHasCorrectFields(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	skills := []parser.InstalledSkill{{Slug: "shell-evil"}}
	findings := d.Detect(skills)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding but got none")
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Errorf("finding ID must not be empty")
		}
		if f.Severity == "" {
			t.Errorf("finding Severity must not be empty (ID=%s)", f.ID)
		}
		if f.Category == "" {
			t.Errorf("finding Category must not be empty (ID=%s)", f.ID)
		}
		if f.Title == "" {
			t.Errorf("finding Title must not be empty (ID=%s)", f.ID)
		}
		if f.Description == "" {
			t.Errorf("finding Description must not be empty (ID=%s)", f.ID)
		}
		if f.Remediation == "" {
			t.Errorf("finding Remediation must not be empty (ID=%s)", f.ID)
		}
	}
}

func TestSupplyChain_S4_NoSkills(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	findings := d.checkS4DangerousName(nil)
	if findings != nil {
		t.Errorf("expected nil findings for nil skills, got %v", findings)
	}
}

func TestSupplyChain_S2_KnownBadSkill(t *testing.T) {
	const skillName = "credential-harvester"

	skillBody := fmt.Sprintf(`{"skill":{"slug":%q,"displayName":%q},"latestVersion":{"version":"0.1.0"},"moderation":{"isMalwareBlocked":true,"isSuspicious":false}}`, skillName, skillName)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, skillName) {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(skillBody))
	}))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	skills := []parser.InstalledSkill{{Slug: skillName}}
	findings := d.checkS2ClawHubReputation(skills)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for known-bad skill, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "SUPPLY_CHAIN-002" {
		t.Errorf("wrong ID: %s, want SUPPLY_CHAIN-002", f.ID)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("wrong severity: %s, want CRITICAL", f.Severity)
	}
	if f.Category != types.CategorySupplyChain {
		t.Errorf("wrong category: %s", f.Category)
	}
	if !strings.Contains(f.Title, skillName) {
		t.Errorf("title should mention skill name %q, got: %s", skillName, f.Title)
	}
}
