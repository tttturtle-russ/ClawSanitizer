package types

// ScanResult holds aggregated scan output
type ScanResult struct {
	Findings    []Finding `json:"findings"`
	Score       int       `json:"score"`
	TotalChecks int       `json:"total_checks"`
	Summary     string    `json:"summary"`
}
