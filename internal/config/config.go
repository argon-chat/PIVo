package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

const (
	appDir     = "PIVo"
	configFile = "config.json"
)

// Ports is the ordered list of ports the agent tries to bind.
// The frontend should probe them in the same order.
var Ports = []int{9283, 10293, 14582, 17383}

type Config struct {
	PairedOrigins []string `json:"pairedOrigins"`
	LogLevel      string   `json:"logLevel"`

	mu   sync.RWMutex
	path string
}

func configDir() (string, error) {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		appData = filepath.Join(home, "AppData", "Roaming")
	}
	return filepath.Join(appData, appDir), nil
}

func Load() (*Config, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, configFile)

	cfg := &Config{
		LogLevel: "info",
		path:     path,
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.path = path
	return cfg, nil
}

func (c *Config) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0o600)
}

func (c *Config) IsPaired(origin string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, o := range c.PairedOrigins {
		if o == origin {
			return true
		}
	}
	return false
}

func (c *Config) AddOrigin(origin string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, o := range c.PairedOrigins {
		if o == origin {
			return nil
		}
	}
	c.PairedOrigins = append(c.PairedOrigins, origin)
	return nil
}

func (c *Config) RemoveOrigin(origin string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, o := range c.PairedOrigins {
		if o == origin {
			c.PairedOrigins = append(c.PairedOrigins[:i], c.PairedOrigins[i+1:]...)
			return true
		}
	}
	return false
}

func (c *Config) Origins() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, len(c.PairedOrigins))
	copy(out, c.PairedOrigins)
	return out
}
