package scanner

import (
	"time"

	"github.com/tttturtle-russ/clawsan/internal/detectors"
	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/scoring"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

var Version = "dev"

func Scan(path string) (*types.ScanResult, error) {
	start := time.Now()

	cfg, err := parser.ParseConfig(path)
	if err != nil {
		return nil, err
	}

	var warnings []string

	workspace, err := parser.ParseWorkspaceFiles(path)
	if err != nil {
		warnings = append(warnings, "could not parse workspace files: "+err.Error())
		workspace = nil
	}

	tools, err := parser.ParseMCPTools(path)
	if err != nil {
		warnings = append(warnings, "could not parse MCP tools: "+err.Error())
		tools = []parser.MCPTool{}
	}

	installedSkills, err := parser.ParseSkillFiles(path)
	if err != nil {
		warnings = append(warnings, "could not parse skill files: "+err.Error())
		installedSkills = nil
	}

	var allFindings []types.Finding

	supplyChain := detectors.NewSupplyChainDetector()
	allFindings = append(allFindings, supplyChain.Detect(installedSkills)...)
	if len(installedSkills) > 0 {
		allFindings = append(allFindings, supplyChain.CheckSkillMetadata(installedSkills)...)
	}

	configuration := detectors.NewConfigurationDetector()
	allFindings = append(allFindings, configuration.Detect(cfg)...)

	discovery := detectors.NewDiscoveryDetector()
	allFindings = append(allFindings, discovery.Detect(workspace, tools)...)

	runtime := detectors.NewRuntimeDetector()
	allFindings = append(allFindings, runtime.Detect(workspace, tools, cfg)...)

	slugs := make([]string, len(installedSkills))
	for i, s := range installedSkills {
		slugs[i] = s.Slug
	}

	if len(installedSkills) > 0 {
		skillContent := detectors.NewSkillContentDetector()
		allFindings = append(allFindings, skillContent.Detect(installedSkills)...)

		skillIdentity := detectors.NewSkillIdentityDetector()
		allFindings = append(allFindings, skillIdentity.Detect(slugs)...)

		composite := detectors.NewSkillCompositeDetector()
		allFindings = append(allFindings, composite.Detect(installedSkills)...)
	} else {
		skillIdentity := detectors.NewSkillIdentityDetector()
		allFindings = append(allFindings, skillIdentity.Detect(slugs)...)
	}

	credStorage := detectors.NewCredentialStorageDetector()
	allFindings = append(allFindings, credStorage.Detect(path, workspace)...)

	memPoisoning := detectors.NewMemoryPoisoningDetector()
	allFindings = append(allFindings, memPoisoning.Detect(workspace)...)

	accessControl := detectors.NewAccessControlDetector()
	allFindings = append(allFindings, accessControl.Detect(cfg)...)

	version := detectors.NewVersionDetector()
	allFindings = append(allFindings, version.Detect(cfg)...)

	qclaw := detectors.NewQClawDetector()
	allFindings = append(allFindings, qclaw.Detect(cfg)...)

	arkClaw := detectors.NewArkClawDetector()
	allFindings = append(allFindings, arkClaw.Detect(cfg)...)

	scEnv := detectors.NewSupplyChainEnvDetector()
	allFindings = append(allFindings, scEnv.Detect(cfg)...)

	suspiciousURL := detectors.NewSuspiciousURLDetector()
	allFindings = append(allFindings, suspiciousURL.Detect(workspace, installedSkills)...)

	if len(installedSkills) > 0 {
		taint := detectors.NewTaintDetector()
		allFindings = append(allFindings, taint.Detect(installedSkills)...)
	}

	score, grade, critical, high, medium, low := scoring.Calculate(allFindings)

	return &types.ScanResult{
		Findings:    allFindings,
		Score:       score,
		Grade:       grade,
		TotalChecks: 58,
		Warnings:    warnings,
		ScannedPath: path,
		ScannedAt:   start,
		Version:     Version,
		DurationMs:  time.Since(start).Milliseconds(),
		Critical:    critical,
		High:        high,
		Medium:      medium,
		Low:         low,
	}, nil
}
