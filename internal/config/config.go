package config

import (
	"os"
	"time"

	"k8s.io/klog/v2"
)

// Config holds the agent configuration
type Config struct {
	NodeName          string        `json:"node_name"`
	Namespace         string        `json:"namespace"`
	PollInterval      time.Duration `json:"poll_interval"`
	AllowlistName     string        `json:"allowlist_name"`
	Verbose           bool          `json:"verbose"`
	WebhookURL        string        `json:"webhook_url,omitempty"`
	WebhookTimeout    time.Duration `json:"webhook_timeout,omitempty"`
	ControllerEnabled bool          `json:"controller_enabled"`
}

// LoadConfig reads config from environment
func LoadConfig() *Config {
	cfg := &Config{
		NodeName:          getEnvOrDefault("NODE_NAME", ""),
		Namespace:         getEnvOrDefault("CORSO_NAMESPACE", "corso-system"),
		PollInterval:      30 * time.Second,
		AllowlistName:     getEnvOrDefault("CORSO_ALLOWLIST", "default"),
		Verbose:           os.Getenv("VERBOSE") == "true",
		WebhookURL:        os.Getenv("CORSO_WEBHOOK_URL"),
		ControllerEnabled: os.Getenv("CORSO_CONTROLLER_ENABLED") != "false",
	}

	if cfg.NodeName == "" {
		klog.Warning("NODE_NAME not set, trying to detect from hostname")
		hostname, _ := os.Hostname()
		cfg.NodeName = hostname
	}

	if v := os.Getenv("CORSO_WEBHOOK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.WebhookTimeout = d
		} else {
			klog.Warningf("Invalid CORSO_WEBHOOK_TIMEOUT %q, using default", v)
		}
	}

	return cfg
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
