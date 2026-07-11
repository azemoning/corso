package config

import (
	"os"
	"time"

	"k8s.io/klog/v2"
)

// Config holds the agent configuration
type Config struct {
	NodeName      string        `json:"node_name"`
	Namespace     string        `json:"namespace"`
	PollInterval  time.Duration `json:"poll_interval"`
	AllowlistName string        `json:"allowlist_name"`
	Verbose       bool          `json:"verbose"`
}

// LoadConfig reads config from environment
func LoadConfig() *Config {
	cfg := &Config{
		NodeName:      getEnvOrDefault("NODE_NAME", ""),
		Namespace:     getEnvOrDefault("CORSO_NAMESPACE", "corso-system"),
		PollInterval:  30 * time.Second,
		AllowlistName: getEnvOrDefault("CORSO_ALLOWLIST", "default"),
		Verbose:       os.Getenv("VERBOSE") == "true",
	}

	if cfg.NodeName == "" {
		klog.Warning("NODE_NAME not set, trying to detect from hostname")
		hostname, _ := os.Hostname()
		cfg.NodeName = hostname
	}

	return cfg
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
