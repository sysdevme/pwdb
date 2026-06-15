package main

import "testing"

func TestValidateMasterPassword(t *testing.T) {
	if err := validateMasterPassword(""); err == nil {
		t.Fatal("expected empty MASTER_PASSWORD to be rejected")
	}
	if err := validateMasterPassword("configured-secret"); err != nil {
		t.Fatalf("expected configured MASTER_PASSWORD to be accepted: %v", err)
	}
}
