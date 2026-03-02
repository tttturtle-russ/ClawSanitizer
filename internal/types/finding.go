package types

// Severity constants
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Category constants
const (
	CategorySupplyChain   = "SUPPLY_CHAIN"
	CategoryConfiguration = "CONFIGURATION"
	CategoryDiscovery     = "DISCOVERY"
	CategoryRuntime       = "RUNTIME"
)

// Finding represents a single security vulnerability detected
type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	FilePath    string `json:"file_path,omitempty"`
}
