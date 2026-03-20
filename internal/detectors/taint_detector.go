package detectors

import (
	"fmt"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/analysis/taint"
	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

type TaintDetector struct{}

func NewTaintDetector() *TaintDetector {
	return &TaintDetector{}
}

func (d *TaintDetector) Detect(skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding

	for _, skill := range skills {
		for _, codeFile := range skill.CodeFiles {
			if !d.isSupportedLanguage(codeFile.Path) {
				continue
			}

			tracker := taint.NewTracker()
			flows := tracker.TrackFile(codeFile.Content)

			for _, flow := range flows {
				findings = append(findings, d.createFinding(flow, codeFile.Path))
			}
		}
	}

	return findings
}

func (d *TaintDetector) isSupportedLanguage(filePath string) bool {
	return strings.HasSuffix(filePath, ".py") ||
		strings.HasSuffix(filePath, ".js") ||
		strings.HasSuffix(filePath, ".ts") ||
		strings.HasSuffix(filePath, ".go")
}

func (d *TaintDetector) createFinding(flow taint.Flow, filePath string) types.Finding {
	var findingID string
	var title string
	var description string
	var remediation string
	var cwe string

	sourceDesc := d.formatSourceType(flow.Variable.Source)

	switch flow.SinkType {
	case taint.SinkNetwork:
		findingID = "TAINT-001"
		title = fmt.Sprintf("Credential exfiltration: %s sent to network", sourceDesc)
		description = fmt.Sprintf(
			"Taint analysis detected %s from '%s' (line %d) being transmitted over network (line %d). "+
				"This may expose sensitive credentials to unauthorized parties.",
			sourceDesc,
			flow.Variable.SourcePath,
			flow.Variable.LineNum,
			flow.SinkLineNum,
		)
		remediation = "Remove network transmission of credentials. Use environment variables or secure credential stores on the server side. If this is legitimate credential validation, add an explanatory comment."
		cwe = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"

	case taint.SinkEval:
		findingID = "TAINT-002"
		title = fmt.Sprintf("Code injection: %s passed to eval/exec", sourceDesc)
		description = fmt.Sprintf(
			"Taint analysis detected %s from '%s' (line %d) being passed to eval/exec (line %d). "+
				"This enables arbitrary code execution and credential exposure.",
			sourceDesc,
			flow.Variable.SourcePath,
			flow.Variable.LineNum,
			flow.SinkLineNum,
		)
		remediation = "Never pass external data to eval/exec. Use safer alternatives like json.loads(), ast.literal_eval(), or parameterized queries."
		cwe = "CWE-94: Improper Control of Generation of Code (Code Injection)"

	case taint.SinkSubprocess:
		findingID = "TAINT-003"
		title = fmt.Sprintf("Command injection: %s passed to subprocess", sourceDesc)
		description = fmt.Sprintf(
			"Taint analysis detected %s from '%s' (line %d) being passed to subprocess execution (line %d). "+
				"This enables arbitrary command execution.",
			sourceDesc,
			flow.Variable.SourcePath,
			flow.Variable.LineNum,
			flow.SinkLineNum,
		)
		remediation = "Use subprocess with shell=False and a list of validated arguments. Never pass unvalidated input to shell commands."
		cwe = "CWE-78: Improper Neutralization of Special Elements used in an OS Command"
	}

	return types.Finding{
		ID:          findingID,
		Severity:    flow.Severity,
		Category:    types.CategoryTaint,
		Title:       title,
		Description: description,
		Remediation: remediation,
		FilePath:    filePath,
		LineNumber:  flow.SinkLineNum,
		OWASP:       types.OWASPLLM02,
		CWE:         cwe,
	}
}

func (d *TaintDetector) formatSourceType(source taint.SourceType) string {
	switch source {
	case taint.SourceCredentialFile:
		return "credential file"
	case taint.SourceEnvVar:
		return "sensitive environment variable"
	case taint.SourceSensitiveFile:
		return "sensitive system file"
	default:
		return "sensitive data"
	}
}
