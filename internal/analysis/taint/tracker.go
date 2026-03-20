package taint

import (
	"regexp"
	"strings"
)

type SourceType string

const (
	SourceCredentialFile SourceType = "credential_file"
	SourceEnvVar         SourceType = "env_var"
	SourceSensitiveFile  SourceType = "sensitive_file"
)

type SinkType string

const (
	SinkNetwork    SinkType = "network"
	SinkEval       SinkType = "eval"
	SinkSubprocess SinkType = "subprocess"
)

type TaintedVariable struct {
	Name       string
	Source     SourceType
	SourcePath string
	LineNum    int
}

type Flow struct {
	Variable    TaintedVariable
	SinkType    SinkType
	SinkLineNum int
	Severity    string
}

type Tracker struct {
	taintedVars    map[string]TaintedVariable
	sourcePatterns []*regexp.Regexp
	assignPatterns []*regexp.Regexp
	sinkPatterns   []*regexp.Regexp
}

func NewTracker() *Tracker {
	return &Tracker{
		taintedVars:    make(map[string]TaintedVariable),
		sourcePatterns: compileSourcePatterns(),
		assignPatterns: compileAssignPatterns(),
		sinkPatterns:   compileSinkPatterns(),
	}
}

func compileSourcePatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(\w+)\s*=\s*open\s*\(\s*['"]([^'"]*\.(?:env|pem|key|p12|pfx|jks|credentials))['"]\s*\)`),
		regexp.MustCompile(`(\w+)\s*=\s*Path\s*\(\s*['"]([^'"]*\.(?:env|pem|key))['"]\s*\)\.read_(?:text|bytes)\(\)`),
		regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*(?:fs\.)?readFileSync\s*\(\s*['"]([^'"]*\.env)['"]\s*\)`),
		regexp.MustCompile(`(\w+)\s*:?=\s*(?:ioutil|os)\.ReadFile\s*\(\s*"([^"]*\.(?:env|pem|key))"\s*\)`),
		regexp.MustCompile(`(\w+)\s*=\s*os\.(?:environ\.get|getenv)\s*\(\s*['"]([A-Z_]+)['"]\s*\)`),
		regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*process\.env\.([A-Z_]+)`),
		regexp.MustCompile(`(\w+)\s*:?=\s*os\.Getenv\s*\(\s*"([A-Z_]+)"\s*\)`),
		regexp.MustCompile(`(\w+)\s*=\s*open\s*\(\s*['"]([^'"]*(?:/etc/passwd|/etc/shadow|\.ssh/id_rsa|\.aws/credentials))['"]\s*\)`),
	}
}

func compileAssignPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(\w+)\s*=\s*(\w+)(?:\s|$|;|\))`),
		regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*(\w+)(?:\s|$|;|\))`),
		regexp.MustCompile(`(\w+)\s*:=\s*(\w+)(?:\s|$|;|\))`),
	}
}

func compileSinkPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`requests\.(?:post|put|patch)\s*\([^)]*(?:data|json)\s*=\s*(\w+)`),
		regexp.MustCompile(`urllib\.request\.urlopen\s*\(\s*(\w+)`),
		regexp.MustCompile(`socket\.(?:connect|sendto|sendall)\s*\(\s*\(?[^)]*?\s*(\w+)`),
		regexp.MustCompile(`(?:fetch|axios\.post)\s*\([^{]*\{\s*[^}]*body\s*:\s*(\w+)`),
		regexp.MustCompile(`http\.Post\([^,]*,\s*[^,]*,\s*(\w+)\)`),
		regexp.MustCompile(`\beval\s*\(\s*(\w+)\s*\)`),
		regexp.MustCompile(`\bexec\s*\(\s*(\w+)\s*\)`),
		regexp.MustCompile(`subprocess\.(?:call|run|Popen)\s*\(\s*(\w+)`),
		regexp.MustCompile(`os\.system\s*\(\s*(\w+)\s*\)`),
	}
}

func (t *Tracker) TrackFile(code string) []Flow {
	lines := strings.Split(code, "\n")

	for lineNum, line := range lines {
		t.trackSources(line, lineNum+1)
	}

	for i := 0; i < 2; i++ {
		changed := false
		for lineNum, line := range lines {
			if t.propagateAssignments(line, lineNum+1) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	var flows []Flow
	for lineNum, line := range lines {
		flows = append(flows, t.checkSinks(line, lineNum+1)...)
	}

	return flows
}

func (t *Tracker) trackSources(line string, lineNum int) {
	for i, pattern := range t.sourcePatterns {
		if match := pattern.FindStringSubmatch(line); match != nil {
			if len(match) < 3 {
				continue
			}

			varName := match[1]
			sourcePath := match[2]

			var sourceType SourceType
			isEnvVarPattern := i >= 4 && i <= 6

			if strings.Contains(sourcePath, "/etc/") || strings.Contains(sourcePath, ".ssh/") || strings.Contains(sourcePath, ".aws/") {
				sourceType = SourceSensitiveFile
			} else if isEnvVarPattern {
				if !isSensitiveEnvVar(sourcePath) {
					continue
				}
				sourceType = SourceEnvVar
			} else {
				sourceType = SourceCredentialFile
			}

			t.taintedVars[varName] = TaintedVariable{
				Name:       varName,
				Source:     sourceType,
				SourcePath: sourcePath,
				LineNum:    lineNum,
			}
		}
	}
}

func (t *Tracker) propagateAssignments(line string, lineNum int) bool {
	changed := false

	for _, pattern := range t.assignPatterns {
		if match := pattern.FindStringSubmatch(line); match != nil {
			if len(match) < 3 {
				continue
			}

			target := match[1]
			source := match[2]

			if taint, found := t.taintedVars[source]; found {
				if _, exists := t.taintedVars[target]; !exists {
					t.taintedVars[target] = TaintedVariable{
						Name:       target,
						Source:     taint.Source,
						SourcePath: taint.SourcePath,
						LineNum:    taint.LineNum,
					}
					changed = true
				}
			}
		}
	}

	return changed
}

func (t *Tracker) checkSinks(line string, lineNum int) []Flow {
	var flows []Flow

	for _, pattern := range t.sinkPatterns {
		if match := pattern.FindStringSubmatch(line); match != nil {
			if len(match) < 2 {
				continue
			}

			varName := extractVarName(match[1])

			if taint, found := t.taintedVars[varName]; found {
				sinkType := determineSinkType(line)
				severity := getSeverity(taint, sinkType)

				flows = append(flows, Flow{
					Variable:    taint,
					SinkType:    sinkType,
					SinkLineNum: lineNum,
					Severity:    severity,
				})
			}
		}
	}

	return flows
}

func isSensitiveEnvVar(name string) bool {
	sensitive := []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API", "AUTH"}
	upper := strings.ToUpper(name)
	for _, keyword := range sensitive {
		if strings.Contains(upper, keyword) {
			return true
		}
	}
	return false
}

func extractVarName(expr string) string {
	parts := strings.FieldsFunc(expr, func(r rune) bool {
		return r == '=' || r == ',' || r == ' ' || r == '(' || r == ')' || r == '{' || r == '}'
	})
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return strings.TrimSpace(expr)
}

func determineSinkType(line string) SinkType {
	if strings.Contains(line, "eval") || strings.Contains(line, "exec") {
		return SinkEval
	}
	if strings.Contains(line, "subprocess") || strings.Contains(line, "os.system") {
		return SinkSubprocess
	}
	return SinkNetwork
}

func getSeverity(taint TaintedVariable, sinkType SinkType) string {
	if taint.Source == SourceSensitiveFile {
		return "CRITICAL"
	}
	if taint.Source == SourceCredentialFile {
		return "CRITICAL"
	}
	if sinkType == SinkEval {
		return "CRITICAL"
	}
	return "HIGH"
}
