package config

import (
	"os"
	"testing"
)

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

func TestNormalizeAppliesEnvSecretOverrides(t *testing.T) {
	t.Parallel()

	oldShared := os.Getenv("CONTROLLER_SHARED_TOKEN")
	oldMasterKey := os.Getenv("CONTROLLER_MASTER_KEY")
	t.Cleanup(func() {
		_ = os.Setenv("CONTROLLER_SHARED_TOKEN", oldShared)
		_ = os.Setenv("CONTROLLER_MASTER_KEY", oldMasterKey)
	})
	if err := os.Setenv("CONTROLLER_SHARED_TOKEN", "token-from-env"); err != nil {
		t.Fatalf("Setenv shared token: %v", err)
	}
	if err := os.Setenv("CONTROLLER_MASTER_KEY", "master-key-from-env"); err != nil {
		t.Fatalf("Setenv master key: %v", err)
	}

	cfg := Config{
		ControllerID: "controller-01",
		Master: MasterConfig{
			BaseURL:     "http://10.8.0.1:8080",
			SharedToken: "replace-with-controller-shared-token",
			MasterKey:   "",
		},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if cfg.Master.SharedToken != "token-from-env" {
		t.Fatalf("expected env shared token override, got %q", cfg.Master.SharedToken)
	}
	if cfg.Master.MasterKey != "master-key-from-env" {
		t.Fatalf("expected env master key override, got %q", cfg.Master.MasterKey)
	}
}

func TestSecretLooksUnset(t *testing.T) {
	t.Parallel()

	if !SecretLooksUnset("") {
		t.Fatalf("expected empty secret to be unset")
	}
	if !SecretLooksUnset("replace-with-controller-shared-token") {
		t.Fatalf("expected placeholder secret to be unset")
	}
	if SecretLooksUnset("real-token") {
		t.Fatalf("expected real secret to be considered set")
	}
}
