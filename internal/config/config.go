package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

type AuthConfig struct {
	Method          string            `json:"method"`
	Username        string            `json:"username"`
	Password        string            `json:"password"`
	Token           string            `json:"token"`
	LoginURL        string            `json:"login_url"`
	LoginSelectors  map[string]string `json:"login_selectors"`
}

type IssuesConfig struct {
	URL           string `json:"url"`
	AuthRequired  bool   `json:"auth_required"`
}

type ScopeConfig struct {
	IncludePaths   []string `json:"include_paths"`
	ExcludePaths   []string `json:"exclude_paths"`
	MaxDepth       int      `json:"max_depth"`
	RateLimitRPS   int      `json:"rate_limit_rps"`
	Timeout        string   `json:"timeout"`
	SlowThresholdMs int    `json:"slow_threshold_ms"`
}

type TestsConfig struct {
	Recon      bool `json:"recon"`
	Discovery  bool `json:"discovery"`
	Auth       bool `json:"auth"`
	Authz      bool `json:"authz"`
	Injection  bool `json:"injection"`
	Logic      bool `json:"logic"`
	ClientSide bool `json:"client_side"`
	Infra      bool `json:"infra"`
	DDoS      bool `json:"ddos"`
	Fuzz      bool `json:"fuzz"`
}

type ScheduleConfig struct {
	Interval string `json:"interval"`
	Cron     string `json:"cron"`
}

type Target struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	URL      string         `json:"url"`
	Enabled  bool           `json:"enabled"`
	Auth     AuthConfig     `json:"auth"`
	Issues   IssuesConfig   `json:"issues"`
	Scope    ScopeConfig    `json:"scope"`
	Tests    TestsConfig    `json:"tests"`
	Schedule ScheduleConfig `json:"schedule"`
}

type AgentConfig struct {
	Headless          bool   `json:"headless"`
	AutoDownloadChrome bool  `json:"auto_download_chrome"`
	UserAgent         string `json:"user_agent"`
	MaxIterations     int    `json:"max_iterations"`
	Proxy             string `json:"proxy"`
}

type DashboardConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type Config struct {
	Targets   []Target        `json:"targets"`
	Agent     AgentConfig     `json:"agent"`
	Dashboard DashboardConfig `json:"dashboard"`

	mu        sync.RWMutex
	filePath  string
}

func Load(path string) (*Config, error) {
	c := &Config{filePath: path}
	if err := c.reload(); err != nil {
		return nil, err
	}
	applyEnvOverrides(c)
	return c, nil
}

func Default() *Config {
	return &Config{
		Targets: []Target{},
		Agent: AgentConfig{
			Headless:           true,
			AutoDownloadChrome: true,
			UserAgent:          "RedTeamAgent/2.0",
			MaxIterations:      0,
		},
		Dashboard: DashboardConfig{
			Host: "0.0.0.0",
			Port: 5555,
		},
		filePath: "config.json",
	}
}

func (c *Config) reload() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return c.saveLocked()
		}
		return fmt.Errorf("read config: %w", err)
	}

	// Preserve runtime fields
	fp := c.filePath
	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	c.filePath = fp
	return nil
}

func (c *Config) Reload() error {
	if err := c.reload(); err != nil {
		return err
	}
	applyEnvOverrides(c)
	return nil
}

func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

func (c *Config) saveLocked() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.filePath, data, 0644)
}

func (c *Config) GetEnabledTargets() []Target {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var enabled []Target
	for _, t := range c.Targets {
		if t.Enabled {
			enabled = append(enabled, t)
		}
	}
	return enabled
}

func (c *Config) GetTarget(id string) *Target {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Targets {
		if c.Targets[i].ID == id {
			return &c.Targets[i]
		}
	}
	return nil
}

func (c *Config) AddTarget(t Target) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Targets = append(c.Targets, t)
}

func (c *Config) UpdateTarget(id string, t Target) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Targets {
		if c.Targets[i].ID == id {
			c.Targets[i] = t
			return nil
		}
	}
	return fmt.Errorf("target %s not found", id)
}

func (c *Config) DeleteTarget(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Targets {
		if c.Targets[i].ID == id {
			c.Targets = append(c.Targets[:i], c.Targets[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("target %s not found", id)
}

func (c *Config) ToJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.MarshalIndent(c, "", "  ")
}

func (c *Config) DashboardAddr() string {
	return fmt.Sprintf("%s:%d", c.Dashboard.Host, c.Dashboard.Port)
}

func (c *Config) FilePath() string {
	return c.filePath
}

func (c *Config) SetFilePath(p string) {
	c.filePath = p
}

// ─── Environment Variable Overrides ───
//
// Supported env vars:
//
//   RTA_AGENT_HEADLESS=true
//   RTA_AGENT_PROXY=socks5://...
//   RTA_AGENT_USER_AGENT=...
//   RTA_DASHBOARD_HOST=0.0.0.0
//   RTA_DASHBOARD_PORT=5555
//
// Per-target (replace {ID} with target ID, uppercase, non-alphanum replaced with _):
//   RTA_TARGET_{ID}_URL=https://myapp.example.com
//   RTA_TARGET_{ID}_USERNAME=admin
//   RTA_TARGET_{ID}_PASSWORD=secret123
//   RTA_TARGET_{ID}_TOKEN=eyJhbG...
//   RTA_TARGET_{ID}_LOGIN_URL=/login
//   RTA_TARGET_{ID}_ENABLED=true
//
// Example for target ID "my-app":
//   RTA_TARGET_MY_APP_URL=https://staging.example.com
//   RTA_TARGET_MY_APP_USERNAME=testuser
//   RTA_TARGET_MY_APP_PASSWORD=testpass
//
// Example for target ID "api-prod":
//   RTA_TARGET_API_PROD_TOKEN=eyJhbG...

func applyEnvOverrides(c *Config) {
	// Global agent overrides
	if v := os.Getenv("RTA_AGENT_HEADLESS"); v != "" {
		c.Agent.Headless = v == "true" || v == "1"
	}
	if v := os.Getenv("RTA_AGENT_PROXY"); v != "" {
		c.Agent.Proxy = v
	}
	if v := os.Getenv("RTA_AGENT_USER_AGENT"); v != "" {
		c.Agent.UserAgent = v
	}
	if v := os.Getenv("RTA_DASHBOARD_HOST"); v != "" {
		c.Dashboard.Host = v
	}
	if v := os.Getenv("RTA_DASHBOARD_PORT"); v != "" {
		c.Dashboard.Port = envInt(v, c.Dashboard.Port)
	}

	// Per-target overrides
	for i := range c.Targets {
		prefix := "RTA_TARGET_" + envKey(c.Targets[i].ID) + "_"
		if v := os.Getenv(prefix + "URL"); v != "" {
			c.Targets[i].URL = v
		}
		if v := os.Getenv(prefix + "USERNAME"); v != "" {
			c.Targets[i].Auth.Username = v
		}
		if v := os.Getenv(prefix + "PASSWORD"); v != "" {
			c.Targets[i].Auth.Password = v
		}
		if v := os.Getenv(prefix + "TOKEN"); v != "" {
			c.Targets[i].Auth.Token = v
		}
		if v := os.Getenv(prefix + "LOGIN_URL"); v != "" {
			c.Targets[i].Auth.LoginURL = v
		}
		if v := os.Getenv(prefix + "ENABLED"); v != "" {
			c.Targets[i].Enabled = v == "true" || v == "1"
		}
		if v := os.Getenv(prefix + "INTERVAL"); v != "" {
			c.Targets[i].Schedule.Interval = v
		}
		if v := os.Getenv(prefix + "CRON"); v != "" {
			c.Targets[i].Schedule.Cron = v
		}
		// Auto-detect auth method from env
		if os.Getenv(prefix+"TOKEN") != "" && c.Targets[i].Auth.Method == "none" {
			c.Targets[i].Auth.Method = "token"
		}
		if os.Getenv(prefix+"USERNAME") != "" && c.Targets[i].Auth.Method == "none" {
			c.Targets[i].Auth.Method = "form"
		}
	}
}

// envKey converts a target ID to env var format: "my-app" → "MY_APP"
func envKey(id string) string {
	upper := strings.ToUpper(id)
	result := strings.Builder{}
	for _, r := range upper {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}

func envInt(s string, fallback int) int {
	n := fallback
	fmt.Sscanf(s, "%d", &n)
	return n
}
