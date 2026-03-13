package main

import (
	"testing"

	"pwdb-controller/internal/config"
)

func TestValidateSecretsRequiresSharedToken(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Master: config.MasterConfig{
			SharedToken: "",
		},
	}
	if err := validateSecrets(cfg); err == nil {
		t.Fatalf("expected error when shared token is missing")
	}
}

func TestValidateSecretsAcceptsConfiguredSharedToken(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Master: config.MasterConfig{
			SharedToken: "real-shared-token",
		},
	}
	if err := validateSecrets(cfg); err != nil {
		t.Fatalf("unexpected validateSecrets error: %v", err)
	}
}
