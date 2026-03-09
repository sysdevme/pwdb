package server

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"pwdb-controller/internal/config"
	"pwdb-controller/internal/master"
)

type fakeMaster struct {
	controllers    []master.ControllerInfo
	nextToken      string
	listErr        error
	pairErrFor     map[string]error
	pairCalls      []string
	applyCalls     []string
	ackCalls       []string
	exportCalls    int
	bootstrapToken string
	bootstrapErr   error
	bootstrapCalls int
	snapshot       master.SnapshotExport
}

func (f *fakeMaster) Bootstrap(controllerID string, masterKey string) (string, error) {
	f.bootstrapCalls++
	if f.bootstrapErr != nil {
		return "", f.bootstrapErr
	}
	return f.bootstrapToken, nil
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

func (f *fakeMaster) ExportSnapshot() (master.SnapshotExport, error) {
	f.exportCalls++
	return f.snapshot, nil
}

func (f *fakeMaster) ApplySnapshotToSlave(slaveURL string, masterServerID string, masterURL string, snapshot master.SnapshotExport) error {
	f.applyCalls = append(f.applyCalls, slaveURL)
	return nil
}

func (f *fakeMaster) ApplyUpdateToSlave(slaveURL string, masterServerID string, eventID string, vaultVersion int64, payloadHash string) error {
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
		snapshot: master.SnapshotExport{
			SnapshotVersion: 101,
			PayloadHash:     "payload-1",
			Snapshot:        json.RawMessage(`{"version":101,"created_at":"2026-03-09T00:00:00Z","users":[{"id":"u1"}],"passwords":[],"notes":[],"password_shares":[],"note_shares":[]}`),
		},
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
	if st.CurrentVaultVersion != 101 {
		t.Fatalf("expected vault version 101 after first sync, got %d", st.CurrentVaultVersion)
	}
	if len(fm.applyCalls) != 1 || len(fm.ackCalls) != 1 || fm.exportCalls != 1 {
		t.Fatalf("expected one export, one apply, and one ack call, got export=%d apply=%d ack=%d", fm.exportCalls, len(fm.applyCalls), len(fm.ackCalls))
	}

	// Second sync with a new exported timestamp/version but identical content should not reapply.
	fm.snapshot = master.SnapshotExport{
		SnapshotVersion: 202,
		PayloadHash:     "payload-2",
		Snapshot:        json.RawMessage(`{"version":202,"created_at":"2026-03-09T00:01:00Z","users":[{"id":"u1"}],"passwords":[],"notes":[],"password_shares":[],"note_shares":[]}`),
	}
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

func TestSyncSlavesWithMasterAutoBootstrapSuccess(t *testing.T) {
	t.Parallel()

	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("NewStateStore error: %v", err)
	}

	fm := &fakeMaster{
		controllers:    []master.ControllerInfo{},
		nextToken:      "token-rotated",
		bootstrapToken: "token-bootstrapped",
		snapshot: master.SnapshotExport{
			SnapshotVersion: 1,
			Snapshot:        json.RawMessage(`{"version":1,"created_at":"2026-03-09T00:00:00Z","users":[],"passwords":[],"notes":[],"password_shares":[],"note_shares":[]}`),
		},
	}

	srv := New(config.Config{
		ControllerID: "controller-01",
		Master:       config.MasterConfig{MasterKey: "key-1"},
	}, fm, store)

	res, err := srv.syncSlavesWithMaster()
	if err != nil {
		t.Fatalf("syncSlavesWithMaster error: %v", err)
	}
	if res != (syncResult{}) {
		t.Fatalf("expected empty sync result with no slaves, got %+v", res)
	}
	if fm.bootstrapCalls != 1 {
		t.Fatalf("expected exactly one bootstrap call, got %d", fm.bootstrapCalls)
	}

	st := store.Snapshot()
	if st.CurrentToken != "token-bootstrapped" {
		t.Fatalf("expected bootstrapped token, got %q", st.CurrentToken)
	}
}

func TestSyncSlavesWithMasterAutoBootstrapPendingApproval(t *testing.T) {
	t.Parallel()

	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("NewStateStore error: %v", err)
	}

	fm := &fakeMaster{
		bootstrapErr: master.PendingApprovalError{Body: `{"status":"pending_approval","approved":false}`},
	}
	srv := New(config.Config{
		ControllerID: "controller-01",
		Master:       config.MasterConfig{MasterKey: "key-1"},
	}, fm, store)

	res, err := srv.syncSlavesWithMaster()
	if err != nil {
		t.Fatalf("expected pending approval to be non-fatal, got err=%v", err)
	}
	if res != (syncResult{}) {
		t.Fatalf("expected empty sync result on pending approval, got %+v", res)
	}
	if fm.bootstrapCalls != 1 {
		t.Fatalf("expected bootstrap call, got %d", fm.bootstrapCalls)
	}

	status := srv.getStatus()
	if status.LastError != "controller is pending master approval" {
		t.Fatalf("expected pending approval status message, got %q", status.LastError)
	}
	if status.ConsecutiveFailures != 0 {
		t.Fatalf("expected no failure increment on pending approval, got %d", status.ConsecutiveFailures)
	}
}
