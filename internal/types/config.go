package types

// OpenClawConfig represents the OpenClaw configuration file (~/.openclaw/config.json)
type OpenClawConfig struct {
	DangerouslySkipPermissions bool            `json:"dangerously_skip_permissions"`
	DMPolicy                   string          `json:"dmPolicy"`
	AllowFrom                  []string        `json:"allowFrom"`
	WorkspaceDir               string          `json:"workspace_dir"`
	APIKey                     string          `json:"api_key"`
	Gateway                    GatewayConfig   `json:"gateway"`
	Tailscale                  TailscaleConfig `json:"tailscale"`
	SSH                        SSHConfig       `json:"ssh"`
	Skills                     []SkillConfig   `json:"skills"`
}

type GatewayConfig struct {
	Bind string `json:"bind"`
	Auth bool   `json:"auth"`
}

type TailscaleConfig struct {
	Enabled bool `json:"enabled"`
	Auth    bool `json:"auth"`
}

type SSHConfig struct {
	Enabled bool `json:"enabled"`
	Auth    bool `json:"auth"`
}

type SkillConfig struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Hash   string `json:"hash"`
}
