package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ClawHubClient checks skills against the ClawHub reputation API
type ClawHubClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClawHubClient creates a new client with 5s timeout
func NewClawHubClient() *ClawHubClient {
	return &ClawHubClient{
		BaseURL:    "https://api.clawhub.io/v1",
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// SkillReputation holds reputation data for a skill
type SkillReputation struct {
	Name      string `json:"name"`
	Malicious bool   `json:"malicious"`
	Reason    string `json:"reason"`
}

// CheckSkillReputation returns reputation info for a skill name.
// Returns nil, nil if the API is unreachable (graceful offline fallback).
func (c *ClawHubClient) CheckSkillReputation(skillName string) (*SkillReputation, error) {
	url := fmt.Sprintf("%s/skills/%s/reputation", c.BaseURL, skillName)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		// Network error = offline fallback (not fatal)
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Unknown skill = not flagged
		return &SkillReputation{Name: skillName, Malicious: false}, nil
	}
	if resp.StatusCode != 200 {
		return nil, nil // API error = graceful fallback
	}

	var rep SkillReputation
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return nil, nil // Parse error = graceful fallback
	}
	return &rep, nil
}
