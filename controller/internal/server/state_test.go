package server

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStateStoreUpsertDedupeAndRemove(t *testing.T) {
	t.Parallel()

	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("NewStateStore error: %v", err)
	}

	first := SlaveRegistration{
		SlaveID:      "slave-1",
		SlaveURL:     "http://10.0.0.1:8080",
		ControllerID: "controller-01",
		RegisteredAt: time.Now().UTC(),
	}
	if err := store.UpsertSlave(first); err != nil {
		t.Fatalf("UpsertSlave first error: %v", err)
	}

	// Same endpoint with different slave ID should replace existing entry.
	second := SlaveRegistration{
		SlaveID:      "slave-2",
		SlaveURL:     "http://10.0.0.1:8080",
		ControllerID: "controller-01",
		RegisteredAt: time.Now().UTC(),
	}
	if err := store.UpsertSlave(second); err != nil {
		t.Fatalf("UpsertSlave second error: %v", err)
	}

	st := store.Snapshot()
	if len(st.Slaves) != 1 {
		t.Fatalf("expected 1 slave after endpoint dedupe, got %d", len(st.Slaves))
	}
	if st.Slaves[0].SlaveID != "slave-2" {
		t.Fatalf("expected deduped slave id slave-2, got %s", st.Slaves[0].SlaveID)
	}

	removed, err := store.RemoveSlave("slave-2")
	if err != nil {
		t.Fatalf("RemoveSlave error: %v", err)
	}
	if !removed {
		t.Fatalf("expected RemoveSlave to remove existing entry")
	}

	st = store.Snapshot()
	if len(st.Slaves) != 0 {
		t.Fatalf("expected no slaves after remove, got %d", len(st.Slaves))
	}

	removed, err = store.RemoveSlave("missing")
	if err != nil {
		t.Fatalf("RemoveSlave missing error: %v", err)
	}
	if removed {
		t.Fatalf("expected RemoveSlave(missing) to return false")
	}
}
