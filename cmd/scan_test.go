package cmd_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tttturtle-russ/clawsan/internal/scanner"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

func TestScan_VulnerableConfig(t *testing.T) {
	result, err := scanner.Scan("../testdata/vulnerable-config")

	assert.NoError(t, err)
	if !assert.NotNil(t, result) {
		return
	}

	assert.NotEmpty(t, result.Findings)
	assert.Less(t, result.Score, 100)
	assert.Equal(t, 55, result.TotalChecks)

	hasCritical := false
	hasSupplyChain := false
	hasConfiguration := false
	hasDiscovery := false
	hasRuntime := false

	for _, finding := range result.Findings {
		if finding.Severity == types.SeverityCritical {
			hasCritical = true
		}

		switch finding.Category {
		case types.CategorySupplyChain:
			hasSupplyChain = true
		case types.CategoryConfiguration:
			hasConfiguration = true
		case types.CategoryDiscovery:
			hasDiscovery = true
		case types.CategoryRuntime:
			hasRuntime = true
		}
	}

	assert.True(t, hasCritical, "expected at least one CRITICAL finding")
	assert.True(t, hasSupplyChain, "expected at least one SUPPLY_CHAIN finding")
	assert.True(t, hasConfiguration, "expected at least one CONFIGURATION finding")
	assert.True(t, hasDiscovery, "expected at least one DISCOVERY finding")
	assert.True(t, hasRuntime, "expected at least one RUNTIME finding")
}

func TestScan_CleanConfig(t *testing.T) {
	result, err := scanner.Scan("../testdata/clean-config")

	assert.NoError(t, err)
	if !assert.NotNil(t, result) {
		return
	}

	assert.Len(t, result.Findings, 0)
	assert.Equal(t, 100, result.Score)
}

func TestScan_InvalidPath(t *testing.T) {
	result, err := scanner.Scan("/nonexistent/path/xyz")

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestScan_FindingIDsUnique(t *testing.T) {
	result, err := scanner.Scan("../testdata/vulnerable-config")

	assert.NoError(t, err)
	if !assert.NotNil(t, result) {
		return
	}

	seen := make(map[string]struct{})
	for _, finding := range result.Findings {
		key := finding.ID + "|" + finding.FilePath
		_, exists := seen[key]
		assert.False(t, exists, "duplicate finding detected for key %q", key)
		seen[key] = struct{}{}
	}
}
