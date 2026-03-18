package api

import (
	"testing"
	"time"
)

func TestNewClawHubClient_Defaults(t *testing.T) {
	c := NewClawHubClient()
	if c.BaseURL != "https://clawhub.ai/api/v1" {
		t.Errorf("unexpected BaseURL: %s", c.BaseURL)
	}
	if c.HTTPClient == nil {
		t.Fatal("HTTPClient must not be nil")
	}
}

func TestCheckSkillReputation_NetworkError_GracefulFallback(t *testing.T) {
	c := NewClawHubClient()
	c.BaseURL = "http://127.0.0.1:1"
	c.HTTPClient.SetTimeout(100 * time.Millisecond)

	info, err := c.CheckSkillReputation("any-skill")
	if err != nil {
		t.Fatalf("expected nil error on network failure, got: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil SkillInfo on network failure, got: %+v", info)
	}
}
