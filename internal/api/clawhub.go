package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
)

type ClawHubClient struct {
	BaseURL    string
	HTTPClient *resty.Client
}

func NewClawHubClient() *ClawHubClient {
	return &ClawHubClient{
		BaseURL:    "https://clawhub.ai/api/v1",
		HTTPClient: resty.New().SetTimeout(time.Second * 5),
	}
}

type skillOwner struct {
	Handle      *string `json:"handle"`
	DisplayName *string `json:"displayName"`
}

type skillModeration struct {
	IsSuspicious     bool `json:"isSuspicious"`
	IsMalwareBlocked bool `json:"isMalwareBlocked"`
}

type skillDetail struct {
	Slug        string  `json:"slug"`
	DisplayName string  `json:"displayName"`
	Summary     *string `json:"summary"`
}

type skillResponse struct {
	Skill         *skillDetail `json:"skill"`
	LatestVersion *struct {
		Version string `json:"version"`
	} `json:"latestVersion"`
	Moderation *skillModeration `json:"moderation"`
	Owner      *skillOwner      `json:"owner"`
}

type versionSecurity struct {
	Status      string `json:"status"`
	HasWarnings bool   `json:"hasWarnings"`
	CheckedAt   *int64 `json:"checkedAt"`
	Model       string `json:"model"`
}

type versionResponse struct {
	Version *struct {
		Version  string           `json:"version"`
		Security *versionSecurity `json:"security"`
	} `json:"version"`
}

type SkillInfo struct {
	Slug           string
	DisplayName    string
	KnownToClawHub bool
	// SecurityStatus values: "clean", "suspicious", "malicious", "pending", "error", "" (not scanned).
	SecurityStatus    string
	HasWarnings       bool
	SecurityCheckedAt *int64
	IsMalwareBlocked  bool
	IsSuspicious      bool
	Malicious         bool
	MaliciousReason   string
}

func (c *ClawHubClient) CheckSkillReputation(skillName string) (*SkillInfo, error) {
	var body skillResponse
	skillURL := fmt.Sprintf("%s/skills/%s", c.BaseURL, skillName)
	resp, err := c.HTTPClient.R().SetResult(&body).Get(skillURL)
	if err != nil {
		return nil, nil
	}
	defer resp.RawBody().Close()

	switch resp.StatusCode() {
	case http.StatusNotFound:
		return &SkillInfo{Slug: skillName, KnownToClawHub: false}, nil
	case http.StatusForbidden:
		return &SkillInfo{
			Slug:            skillName,
			KnownToClawHub:  true,
			IsSuspicious:    true,
			MaliciousReason: "skill is hidden by moderation (HTTP 403)",
		}, nil
	case http.StatusGone:
		return &SkillInfo{
			Slug:             skillName,
			KnownToClawHub:   true,
			IsMalwareBlocked: true,
			Malicious:        true,
			MaliciousReason:  "skill was removed by moderation (HTTP 410)",
		}, nil
	case http.StatusLocked:
		return &SkillInfo{
			Slug:           skillName,
			KnownToClawHub: true,
			SecurityStatus: "pending",
		}, nil
	case http.StatusOK:
	default:
		return nil, nil
	}

	info := &SkillInfo{KnownToClawHub: true}
	if body.Skill != nil {
		info.Slug = body.Skill.Slug
		info.DisplayName = body.Skill.DisplayName
	}

	if body.Moderation != nil {
		info.IsSuspicious = body.Moderation.IsSuspicious
		info.IsMalwareBlocked = body.Moderation.IsMalwareBlocked
		if info.IsMalwareBlocked {
			info.Malicious = true
			info.MaliciousReason = "flagged as malware by ClawHub moderation"
		}
	}

	if body.LatestVersion != nil && body.LatestVersion.Version != "" {
		c.fetchVersionSecurity(info, body.LatestVersion.Version)
	}

	return info, nil
}

func (c *ClawHubClient) fetchVersionSecurity(info *SkillInfo, version string) {
	var body versionResponse
	url := fmt.Sprintf("%s/skills/%s/versions/%s", c.BaseURL, info.Slug, version)
	resp, err := c.HTTPClient.R().SetResult(&body).Get(url)
	if err != nil || !resp.IsSuccess() {
		if resp != nil {
			resp.RawBody().Close()
		}
		return
	}
	defer resp.RawBody().Close()

	if body.Version == nil || body.Version.Security == nil {
		return
	}

	sec := body.Version.Security
	info.SecurityStatus = sec.Status
	info.HasWarnings = sec.HasWarnings
	info.SecurityCheckedAt = sec.CheckedAt

	switch sec.Status {
	case "malicious":
		info.Malicious = true
		if info.MaliciousReason == "" {
			info.MaliciousReason = "ClawHub security scan verdict: malicious"
		}
	case "suspicious":
		info.IsSuspicious = true
	}
}
