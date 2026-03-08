package config

import "testing"

func TestNormalizeAppliesMasterPortOverride(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ControllerID: "controller-01",
		Master: MasterConfig{
			BaseURL: "http://10.8.0.1:8080",
			Port:    18080,
		},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if got := cfg.Master.BaseURL; got != "http://10.8.0.1:18080" {
		t.Fatalf("expected master base_url with overridden port, got %q", got)
	}
}

func TestNormalizeRejectsInvalidPorts(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ControllerID: "controller-01",
		Master: MasterConfig{
			BaseURL: "http://10.8.0.1:8080",
			Port:    70000,
		},
	}
	if err := cfg.Normalize(); err == nil {
		t.Fatalf("expected error for invalid master.port")
	}

	cfg = Config{
		ControllerID: "controller-01",
		Master: MasterConfig{
			BaseURL: "http://10.8.0.1:8080",
		},
		Slave: SlaveConfig{
			DefaultPort: 70000,
		},
	}
	if err := cfg.Normalize(); err == nil {
		t.Fatalf("expected error for invalid slave.default_port")
	}
}
