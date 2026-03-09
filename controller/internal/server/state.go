package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type SlaveRegistration struct {
	SlaveID           string    `json:"slave_id"`
	SlaveURL          string    `json:"slave_url"`
	ControllerID      string    `json:"controller_id"`
	RegisteredAt      time.Time `json:"registered_at"`
	LastSyncedVersion int64     `json:"last_synced_version,omitempty"`
	LastSyncedEventID string    `json:"last_synced_event_id,omitempty"`
	LastSyncedAt      time.Time `json:"last_synced_at,omitempty"`
	LastSyncError     string    `json:"last_sync_error,omitempty"`
}

type ControllerState struct {
	CurrentToken               string              `json:"current_token"`
	TokenUpdatedAt             time.Time           `json:"token_updated_at"`
	Slaves                     []SlaveRegistration `json:"slaves"`
	CurrentVaultVersion        int64               `json:"current_vault_version"`
	LastControllersFingerprint string              `json:"last_controllers_fingerprint,omitempty"`
	LastVaultFingerprint       string              `json:"last_vault_fingerprint,omitempty"`
}

type StateStore struct {
	mu   sync.Mutex
	path string
	data ControllerState
}

func NewStateStore(path string) (*StateStore, error) {
	s := &StateStore{path: path, data: ControllerState{Slaves: []SlaveRegistration{}}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *StateStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st ControllerState
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.Slaves == nil {
		st.Slaves = []SlaveRegistration{}
	}
	s.data = st
	return nil
}

func (s *StateStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func (s *StateStore) Snapshot() ControllerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyState := s.data
	copyState.Slaves = append([]SlaveRegistration(nil), s.data.Slaves...)
	return copyState
}

func (s *StateStore) SetToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.CurrentToken = token
	s.data.TokenUpdatedAt = time.Now().UTC()
	return s.saveLocked()
}

func (s *StateStore) SetVersionFingerprint(version int64, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.CurrentVaultVersion = version
	s.data.LastControllersFingerprint = fingerprint
	return s.saveLocked()
}

func (s *StateStore) SetVaultVersionFingerprint(version int64, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.CurrentVaultVersion = version
	s.data.LastVaultFingerprint = fingerprint
	return s.saveLocked()
}

func (s *StateStore) UpsertSlave(entry SlaveRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := false
	for i := range s.data.Slaves {
		if s.data.Slaves[i].SlaveID == entry.SlaveID || s.data.Slaves[i].SlaveURL == entry.SlaveURL {
			s.data.Slaves[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		s.data.Slaves = append(s.data.Slaves, entry)
	}
	return s.saveLocked()
}

func (s *StateStore) RemoveSlave(slaveID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Slaves {
		if s.data.Slaves[i].SlaveID == slaveID {
			s.data.Slaves = append(s.data.Slaves[:i], s.data.Slaves[i+1:]...)
			return true, s.saveLocked()
		}
	}
	return false, nil
}

func (s *StateStore) MarkSlaveSynced(slaveID string, version int64, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Slaves {
		if s.data.Slaves[i].SlaveID == slaveID {
			s.data.Slaves[i].LastSyncedVersion = version
			s.data.Slaves[i].LastSyncedEventID = eventID
			s.data.Slaves[i].LastSyncedAt = time.Now().UTC()
			s.data.Slaves[i].LastSyncError = ""
			return s.saveLocked()
		}
	}
	return nil
}

func (s *StateStore) MarkSlaveSyncError(slaveID string, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Slaves {
		if s.data.Slaves[i].SlaveID == slaveID {
			s.data.Slaves[i].LastSyncError = msg
			return s.saveLocked()
		}
	}
	return nil
}
