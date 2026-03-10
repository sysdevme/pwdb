package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"pwdb-controller/internal/config"
	"pwdb-controller/internal/master"
)

type registerMasterStub struct {
	controllers []master.ControllerInfo
	nextToken   string
	pairSlaveID string
	pairURL     string
}

func (s *registerMasterStub) Bootstrap(controllerID string, masterKey string) (string, error) {
	return "", nil
}

func (s *registerMasterStub) ListControllers(token string) ([]master.ControllerInfo, string, error) {
	return s.controllers, s.nextToken, nil
}

func (s *registerMasterStub) PairSlave(token string, slaveID string, slaveURL string) (string, error) {
	s.pairSlaveID = slaveID
	s.pairURL = slaveURL
	return s.nextToken, nil
}

func (s *registerMasterStub) ApplyUpdateToSlave(slaveURL string, grantToken string, masterServerID string, eventID string, vaultVersion int64, payloadHash string) error {
	return nil
}

func (s *registerMasterStub) ExportSnapshot(token string) (master.SnapshotExport, string, error) {
	return master.SnapshotExport{}, s.nextToken, nil
}

func (s *registerMasterStub) IssueSlaveGrant(token string, slaveURL string) (string, string, error) {
	return "grant-token", s.nextToken, nil
}

func (s *registerMasterStub) ApplySnapshotToSlave(slaveURL string, grantToken string, masterServerID string, masterURL string, snapshot master.SnapshotExport) error {
	return nil
}

func (s *registerMasterStub) AckUpdate(token string, masterServerID string, slaveID string, eventID string, statusValue string) (string, error) {
	return s.nextToken, nil
}

func TestHandleRegisterSlaveAppliesDefaultPort(t *testing.T) {
	t.Parallel()

	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("NewStateStore error: %v", err)
	}
	if err := store.SetToken("token-1"); err != nil {
		t.Fatalf("SetToken error: %v", err)
	}

	stub := &registerMasterStub{
		controllers: []master.ControllerInfo{{ID: "controller-01", Status: "active", Weight: 1}},
		nextToken:   "token-2",
	}
	srv := New(config.Config{
		ControllerID: "controller-01",
		Slave:        config.SlaveConfig{DefaultPort: 18080},
	}, stub, store)

	reqBody, _ := json.Marshal(map[string]string{
		"slave_id":  "slave-1",
		"slave_url": "http://10.0.0.25",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/slaves/register", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()

	srv.handleRegisterSlave(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if stub.pairSlaveID != "slave-1" {
		t.Fatalf("expected pair slave id slave-1, got %q", stub.pairSlaveID)
	}
	if stub.pairURL != "http://10.0.0.25:18080" {
		t.Fatalf("expected normalized pair url with default port, got %q", stub.pairURL)
	}

	st := store.Snapshot()
	if len(st.Slaves) != 1 {
		t.Fatalf("expected one registered slave, got %d", len(st.Slaves))
	}
	if st.Slaves[0].SlaveURL != "http://10.0.0.25:18080" {
		t.Fatalf("expected stored slave URL with default port, got %q", st.Slaves[0].SlaveURL)
	}
}
