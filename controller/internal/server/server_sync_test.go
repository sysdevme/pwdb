package server

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"pwdb-controller/internal/config"
	"pwdb-controller/internal/master"
)

type fakeMaster struct {
	controllers []master.ControllerInfo
	nextToken   string
	listErr     error
	pairErrFor  map[string]error
	pairCalls   []string
	applyCalls  []string
	ackCalls    []string
}

func (f *fakeMaster) Bootstrap(controllerID string, masterKey string) (string, error) {
	return "", errors.New("not used in this test")
}

func (f *fakeMaster) ListControllers(token string) ([]master.ControllerInfo, string, error) {
	if f.listErr != nil {
		return nil, "", f.listErr
	}
	return f.controllers, f.nextToken, nil
}

func (f *fakeMaster) PairSlave(slaveID string, slaveURL string) error {
	f.pairCalls = append(f.pairCalls, slaveID)
	if err := f.pairErrFor[slaveID]; err != nil {
		return err
	}
	return nil
}

func (f *fakeMaster) ApplyUpdateToSlave(slaveURL string, masterServerID string, eventID string, vaultVersion int64, payloadHash string) error {
	f.applyCalls = append(f.applyCalls, eventID)
	return nil
}

func (f *fakeMaster) AckUpdate(masterServerID string, slaveID string, eventID string, statusValue string) error {
	f.ackCalls = append(f.ackCalls, eventID)
	return nil
}

func TestSyncSlavesWithMasterSuccess(t *testing.T) {
	t.Parallel()

	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("NewStateStore error: %v", err)
	}
	if err := store.SetToken("token-1"); err != nil {
		t.Fatalf("SetToken error: %v", err)
	}
	if err := store.UpsertSlave(SlaveRegistration{
		SlaveID:      "slave-1",
		SlaveURL:     "http://10.0.0.1:8080",
		ControllerID: "controller-01",
		RegisteredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Upsert slave-1 error: %v", err)
	}
	if err := store.UpsertSlave(SlaveRegistration{
		SlaveID:      "slave-2",
		SlaveURL:     "http://10.0.0.2:8080",
		ControllerID: "controller-02",
		RegisteredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Upsert slave-2 error: %v", err)
	}

	fm := &fakeMaster{
		controllers: []master.ControllerInfo{
			{ID: "controller-01", Status: "active"},
			{ID: "controller-02", Status: "disabled"},
		},
		nextToken:  "token-2",
		pairErrFor: map[string]error{},
	}

	srv := New(config.Config{ControllerID: "controller-01", Master: config.MasterConfig{BaseURL: "http://10.1.12.36:8080"}}, fm, store)
	res, err := srv.syncSlavesWithMaster()
	if err != nil {
		t.Fatalf("syncSlavesWithMaster error: %v", err)
	}

	if res.Attempted != 2 || res.Paired != 1 || res.UpdatesSent != 1 || res.SkippedInactive != 1 || res.Failed != 0 {
		t.Fatalf("unexpected sync result: %+v", res)
	}
	if len(fm.pairCalls) != 1 || fm.pairCalls[0] != "slave-1" {
		t.Fatalf("unexpected pair calls: %+v", fm.pairCalls)
	}

	st := store.Snapshot()
	if st.CurrentToken != "token-2" {
		t.Fatalf("expected rotated token token-2, got %q", st.CurrentToken)
	}
	if st.CurrentVaultVersion == 0 {
		t.Fatalf("expected non-zero vault version after first sync")
	}
	if len(fm.applyCalls) != 1 || len(fm.ackCalls) != 1 {
		t.Fatalf("expected one apply and one ack call, got apply=%d ack=%d", len(fm.applyCalls), len(fm.ackCalls))
	}

	// Second sync without fingerprint change should not emit a new update.
	res, err = srv.syncSlavesWithMaster()
	if err != nil {
		t.Fatalf("second syncSlavesWithMaster error: %v", err)
	}
	if res.UpdatesSent != 0 || res.SkippedUpToDate != 1 {
		t.Fatalf("expected up-to-date skip on second sync, got %+v", res)
	}

	status := srv.getStatus()
	if status.ConsecutiveFailures != 0 {
		t.Fatalf("expected zero failures, got %d", status.ConsecutiveFailures)
	}
	if status.LastSuccessAt.IsZero() {
		t.Fatalf("expected LastSuccessAt to be set")
	}
}

func TestSyncSlavesWithMasterMissingToken(t *testing.T) {
	t.Parallel()

	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("NewStateStore error: %v", err)
	}
	srv := New(config.Config{ControllerID: "controller-01"}, &fakeMaster{}, store)

	_, err = srv.syncSlavesWithMaster()
	if err == nil {
		t.Fatalf("expected sync error when token is missing")
	}
	status := srv.getStatus()
	if status.ConsecutiveFailures == 0 {
		t.Fatalf("expected failure counter to increment")
	}
	if status.LastError == "" {
		t.Fatalf("expected last error to be set")
	}
}

func TestNextBackoffCaps(t *testing.T) {
	t.Parallel()

	base := 30 * time.Second
	if got := nextBackoff(base, 0); got != base {
		t.Fatalf("expected base backoff %v, got %v", base, got)
	}
	got := nextBackoff(base, 10)
	if got != 5*time.Minute {
		t.Fatalf("expected capped backoff 5m, got %v", got)
	}
}
