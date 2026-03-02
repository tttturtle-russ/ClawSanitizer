package scanner

import (
	"log"

	"github.com/yourusername/clawsanitizer/internal/detectors"
	"github.com/yourusername/clawsanitizer/internal/parser"
	"github.com/yourusername/clawsanitizer/internal/scoring"
	"github.com/yourusername/clawsanitizer/internal/types"
)

func Scan(path string) (*types.ScanResult, error) {
	cfg, err := parser.ParseConfig(path)
	if err != nil {
		return nil, err
	}

	workspace, err := parser.ParseWorkspaceFiles(path)
	if err != nil {
		log.Printf("warning: could not parse workspace files: %v", err)
		workspace = nil
	}

	tools, err := parser.ParseMCPTools(path)
	if err != nil {
		log.Printf("warning: could not parse MCP tools: %v", err)
		tools = []parser.MCPTool{}
	}

	var allFindings []types.Finding

	supplyChain := detectors.NewSupplyChainDetector()
	allFindings = append(allFindings, supplyChain.Detect(cfg)...)

	configuration := detectors.NewConfigurationDetector()
	allFindings = append(allFindings, configuration.Detect(cfg)...)

	discovery := detectors.NewDiscoveryDetector()
	allFindings = append(allFindings, discovery.Detect(workspace, tools)...)

	runtime := detectors.NewRuntimeDetector()
	allFindings = append(allFindings, runtime.Detect(workspace, tools, cfg)...)

	score := scoring.CalculateScore(allFindings)

	return &types.ScanResult{
		Findings:    allFindings,
		Score:       score,
		TotalChecks: 23,
	}, nil
}
