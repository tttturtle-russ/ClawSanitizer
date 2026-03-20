package types

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

const (
	CategorySupplyChain       = "SUPPLY_CHAIN"
	CategoryConfiguration     = "CONFIGURATION"
	CategoryDiscovery         = "DISCOVERY"
	CategoryRuntime           = "RUNTIME"
	CategorySkillContent      = "SKILL_CONTENT"
	CategorySkillIdentity     = "SKILL_IDENTITY"
	CategoryCredentialStorage = "CREDENTIAL_STORAGE"
	CategoryMemoryPoisoning   = "MEMORY_POISONING"
	CategoryAccessControl     = "ACCESS_CONTROL"
	CategoryVersion           = "VERSION"
	CategoryQClaw             = "QCLAW"
	CategoryArkClaw           = "ARKCLAW"
	CategorySuspiciousURL     = "SUSPICIOUS_URL"
	CategoryTaint             = "TAINT"
)

const (
	OWASPLLM01 = "LLM01:2025 Prompt Injection"
	OWASPLLM02 = "LLM02:2025 Sensitive Information Disclosure"
	OWASPLLM03 = "LLM03:2025 Supply Chain Vulnerabilities"
	OWASPLLM04 = "LLM04:2025 Data and Model Poisoning"
	OWASPLLM05 = "LLM05:2025 Improper Output Handling"
	OWASPLLM06 = "LLM06:2025 Excessive Agency"
	OWASPLLM07 = "LLM07:2025 System Prompt Leakage"
	OWASPLLM08 = "LLM08:2025 Vector and Embedding Weaknesses"
	OWASPLLM09 = "LLM09:2025 Misinformation"
	OWASPLLM10 = "LLM10:2025 Unbounded Consumption"
)

type Finding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	FilePath    string   `json:"file_path,omitempty"`
	OWASP       string   `json:"owasp,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
	LineNumber  int      `json:"line_number,omitempty"`
	References  []string `json:"references,omitempty"`
}
