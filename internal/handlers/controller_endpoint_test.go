package handlers

import (
	"net/http/httptest"
	"testing"
)

func TestNormalizeControllerSlaveEndpointRejectsDangerousTargets(t *testing.T) {
	t.Parallel()

	tests := []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://169.254.1.1:8080",
		"http://[::1]:8080",
		"http://10.0.0.5:8080/path",
		"ftp://10.0.0.5:8080",
	}
	for _, input := range tests {
		if _, err := normalizeControllerSlaveEndpoint(input); err == nil {
			t.Fatalf("expected %q to be rejected", input)
		}
	}
}

func TestNormalizeControllerSlaveEndpointAcceptsCanonicalAddress(t *testing.T) {
	t.Parallel()

	got, err := normalizeControllerSlaveEndpoint("http://10.8.0.2:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "http://10.8.0.2:8080" {
		t.Fatalf("unexpected normalized endpoint %q", got)
	}
}

func TestControllerGrantMatchesRequest(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("POST", "http://10.8.0.2:8080/controller/snapshot/apply", nil)
	req.Host = "10.8.0.2:8080"
	if !controllerGrantMatchesRequest(req, "http://10.8.0.2:8080") {
		t.Fatalf("expected request host to match granted endpoint")
	}
	if controllerGrantMatchesRequest(req, "http://10.8.0.3:8080") {
		t.Fatalf("expected different host to fail grant match")
	}
}
