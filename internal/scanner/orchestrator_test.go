package scanner

import (
	"os"
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

func TestMain(m *testing.M) {
	// Git does not preserve 0700/0600 permissions; set them so CRED-001/CRED-002 don't fire on clean-config in CI.
	_ = os.Chmod("../../testdata/clean-config", 0700)
	_ = os.Chmod("../../testdata/clean-config/openclaw.json", 0600)
	os.Exit(m.Run())
}

func TestScan_VulnerableConfig(t *testing.T) {
	result, err := Scan("../../testdata/vulnerable-config")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected findings for vulnerable config, got 0")
	}
	if result.Score >= 100 {
		t.Fatalf("expected score < 100, got %d", result.Score)
	}
	if result.TotalChecks != 56 {
		t.Fatalf("expected total checks to be 56, got %d", result.TotalChecks)
	}

	hasConfiguration := false
	hasDiscovery := false
	for _, finding := range result.Findings {
		if finding.Category == types.CategoryConfiguration {
			hasConfiguration = true
		}
		if finding.Category == types.CategoryDiscovery {
			hasDiscovery = true
		}
	}

	if !hasConfiguration {
		t.Fatal("expected at least one CONFIGURATION finding")
	}
	if !hasDiscovery {
		t.Fatal("expected at least one DISCOVERY finding")
	}
}

func TestScan_CleanConfig(t *testing.T) {
	result, err := Scan("../../testdata/clean-config")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for clean config, got %d", len(result.Findings))
	}
	if result.Score != 100 {
		t.Fatalf("expected score 100 for clean config, got %d", result.Score)
	}
}

func TestScan_InvalidPath_ReturnsError(t *testing.T) {
	result, err := Scan("/nonexistent/path")

	if err == nil {
		t.Fatal("expected an error for invalid path, got nil")
	}
	if result != nil {
		t.Fatal("expected nil result for invalid path")
	}
}

func TestScan_FindingsHaveRequiredFields(t *testing.T) {
	result, err := Scan("../../testdata/vulnerable-config")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	for _, finding := range result.Findings {
		if finding.ID == "" {
			t.Fatal("expected finding.ID to be set")
		}
		if finding.Severity == "" {
			t.Fatal("expected finding.Severity to be set")
		}
		if finding.Category == "" {
			t.Fatal("expected finding.Category to be set")
		}
		if finding.Title == "" {
			t.Fatal("expected finding.Title to be set")
		}
		if finding.Description == "" {
			t.Fatal("expected finding.Description to be set")
		}
		if finding.Remediation == "" {
			t.Fatal("expected finding.Remediation to be set")
		}
	}
}
