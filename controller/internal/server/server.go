package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"pwdb-controller/internal/config"
	"pwdb-controller/internal/master"
)

type masterAPI interface {
	Bootstrap(controllerID string, masterKey string) (string, error)
	ListControllers(token string) ([]master.ControllerInfo, string, error)
	PairSlave(slaveID string, slaveURL string) error
	ExportSnapshot() (master.SnapshotExport, error)
	ApplySnapshotToSlave(slaveURL string, masterServerID string, masterURL string, snapshot master.SnapshotExport) error
	ApplyUpdateToSlave(slaveURL string, masterServerID string, eventID string, vaultVersion int64, payloadHash string) error
	AckUpdate(masterServerID string, slaveID string, eventID string, statusValue string) error
}

type Server struct {
	cfg    config.Config
	master masterAPI
	state  *StateStore

	syncRunMu sync.Mutex
	statusMu  sync.Mutex
	status    workerStatus
}

type workerStatus struct {
	LastAttemptAt       time.Time `json:"last_attempt_at"`
	LastSuccessAt       time.Time `json:"last_success_at"`
	LastError           string    `json:"last_error,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	NextAttemptAt       time.Time `json:"next_attempt_at"`
}

type syncResult struct {
	Attempted       int `json:"attempted"`
	Paired          int `json:"paired"`
	UpdatesSent     int `json:"updates_sent"`
	SkippedInactive int `json:"skipped_inactive"`
	SkippedUpToDate int `json:"skipped_up_to_date"`
	Failed          int `json:"failed"`
}

func New(cfg config.Config, m masterAPI, state *StateStore) *Server {
	return &Server{cfg: cfg, master: m, state: state}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/master/bootstrap", s.handleBootstrap)
	mux.HandleFunc("/v1/master/controllers", s.handleListControllers)
	mux.HandleFunc("/v1/slaves/register", s.handleRegisterSlave)
	mux.HandleFunc("/v1/slaves/unregister", s.handleUnregisterSlave)
	mux.HandleFunc("/v1/slaves/sync", s.handleSyncSlaves)
	mux.HandleFunc("/v1/slaves", s.handleListSlaves)
	return mux
}

func (s *Server) StartWorkerLoop() {
	base := time.Duration(s.cfg.SyncIntervalSec) * time.Second
	if base < time.Second {
		base = time.Second
	}
	go func() {
		failures := 0
		for {
			_, err := s.syncSlavesWithMaster()
			if err != nil {
				failures++
				log.Printf("worker: sync failed: %v", err)
			} else {
				failures = 0
			}
			wait := nextBackoff(base, failures)
			s.setNextAttempt(time.Now().Add(wait))
			time.Sleep(wait)
		}
	}()
}

func nextBackoff(base time.Duration, failures int) time.Duration {
	if failures <= 0 {
		return base
	}
	wait := base
	for i := 1; i < failures && i < 6; i++ {
		wait *= 2
	}
	maxWait := 5 * time.Minute
	if wait > maxWait {
		return maxWait
	}
	return wait
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.state.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"controller_id":      s.cfg.ControllerID,
		"listen_addr":        s.cfg.ListenAddr,
		"has_token":          strings.TrimSpace(st.CurrentToken) != "",
		"token_last_updated": st.TokenUpdatedAt,
		"registered_slaves":  len(st.Slaves),
		"sync_status":        s.getStatus(),
	})
}

type bootstrapInput struct {
	MasterKey string `json:"master_key"`
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in bootstrapInput
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.MasterKey) == "" {
		http.Error(w, "master_key is required", http.StatusBadRequest)
		return
	}
	token, err := s.master.Bootstrap(s.cfg.ControllerID, in.MasterKey)
	if err != nil {
		if master.IsPendingApproval(err) {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status":   "pending_approval",
				"approved": false,
			})
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := s.state.SetToken(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "authenticated",
		"next_token":    token,
		"controller_id": s.cfg.ControllerID,
	})
}

func (s *Server) currentToken() (string, error) {
	t := strings.TrimSpace(s.state.Snapshot().CurrentToken)
	if t == "" {
		return "", errors.New("controller token is empty, bootstrap first")
	}
	return t, nil
}

func (s *Server) handleListControllers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, err := s.currentToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	list, nextToken, err := s.master.ListControllers(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := s.state.SetToken(nextToken); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"controllers": list,
		"next_token":  nextToken,
	})
}

type registerSlaveInput struct {
	SlaveID      string `json:"slave_id"`
	SlaveURL     string `json:"slave_url"`
	ControllerID string `json:"controller_id"`
}

func (s *Server) handleRegisterSlave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in registerSlaveInput
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	in.SlaveID = strings.TrimSpace(in.SlaveID)
	in.SlaveURL = strings.TrimSpace(in.SlaveURL)
	in.ControllerID = strings.TrimSpace(in.ControllerID)
	if in.SlaveID == "" || in.SlaveURL == "" {
		http.Error(w, "slave_id and slave_url are required", http.StatusBadRequest)
		return
	}
	normalizedSlaveURL, err := normalizeSlaveURL(in.SlaveURL, s.cfg.Slave.DefaultPort)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.SlaveURL = normalizedSlaveURL

	token, err := s.currentToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	controllers, nextToken, err := s.master.ListControllers(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := s.state.SetToken(nextToken); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if in.ControllerID == "" {
		preferred, ok := pickHighestWeightActiveController(controllers)
		if !ok {
			http.Error(w, "no active controllers available", http.StatusBadRequest)
			return
		}
		in.ControllerID = preferred.ID
	} else {
		allowed := false
		for _, c := range controllers {
			if c.ID == in.ControllerID && strings.EqualFold(strings.TrimSpace(c.Status), "active") {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, fmt.Sprintf("controller_id %q is not active in master list", in.ControllerID), http.StatusBadRequest)
			return
		}
	}
	if err := s.master.PairSlave(in.SlaveID, in.SlaveURL); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	entry := SlaveRegistration{
		SlaveID:      in.SlaveID,
		SlaveURL:     in.SlaveURL,
		ControllerID: in.ControllerID,
		RegisteredAt: time.Now().UTC(),
	}
	if err := s.state.UpsertSlave(entry); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "registered",
		"slave":  entry,
	})
}

type unregisterSlaveInput struct {
	SlaveID string `json:"slave_id"`
}

func (s *Server) handleUnregisterSlave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in unregisterSlaveInput
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	in.SlaveID = strings.TrimSpace(in.SlaveID)
	if in.SlaveID == "" {
		http.Error(w, "slave_id is required", http.StatusBadRequest)
		return
	}
	removed, err := s.state.RemoveSlave(in.SlaveID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"removed": removed,
	})
}

func (s *Server) handleSyncSlaves(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	res, err := s.syncSlavesWithMaster()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"status": "error",
			"error":  err.Error(),
			"result": res,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"result": res,
	})
}

func (s *Server) handleListSlaves(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.state.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"slaves": st.Slaves})
}

func (s *Server) syncSlavesWithMaster() (syncResult, error) {
	s.syncRunMu.Lock()
	defer s.syncRunMu.Unlock()

	start := time.Now().UTC()
	s.setAttempt(start)

	st := s.state.Snapshot()
	if strings.TrimSpace(st.CurrentToken) == "" {
		masterKey := strings.TrimSpace(s.cfg.Master.MasterKey)
		if masterKey != "" {
			token, err := s.master.Bootstrap(s.cfg.ControllerID, masterKey)
			if err != nil {
				if master.IsPendingApproval(err) {
					s.setPending("controller is pending master approval")
					return syncResult{}, nil
				}
				s.setFailure(err)
				return syncResult{}, err
			}
			if err := s.state.SetToken(token); err != nil {
				s.setFailure(err)
				return syncResult{}, err
			}
			st = s.state.Snapshot()
		}
	}
	if strings.TrimSpace(st.CurrentToken) == "" {
		err := errors.New("controller token is empty, bootstrap first")
		s.setFailure(err)
		return syncResult{}, err
	}
	if len(st.Slaves) == 0 {
		res := syncResult{}
		s.setSuccess()
		return res, nil
	}

	controllers, nextToken, err := s.master.ListControllers(st.CurrentToken)
	if err != nil {
		s.setFailure(err)
		return syncResult{}, err
	}
	if err := s.state.SetToken(nextToken); err != nil {
		log.Printf("worker: failed to persist rotated token: %v", err)
	}

	activeControllers := make(map[string]struct{}, len(controllers))
	controllerWeights := make(map[string]int, len(controllers))
	for _, c := range controllers {
		controllerWeights[strings.TrimSpace(c.ID)] = c.Weight
		if strings.EqualFold(strings.TrimSpace(c.Status), "active") {
			activeControllers[strings.TrimSpace(c.ID)] = struct{}{}
		}
	}

	slaves := append([]SlaveRegistration(nil), st.Slaves...)
	sort.SliceStable(slaves, func(i, j int) bool {
		wi := controllerWeights[strings.TrimSpace(slaves[i].ControllerID)]
		wj := controllerWeights[strings.TrimSpace(slaves[j].ControllerID)]
		if wi == wj {
			return slaves[i].RegisteredAt.Before(slaves[j].RegisteredAt)
		}
		return wi > wj
	})

	res := syncResult{}
	snapshot, err := s.master.ExportSnapshot()
	if err != nil {
		s.setFailure(err)
		return res, err
	}
	vaultFingerprint, err := snapshotContentFingerprint(snapshot.Snapshot)
	if err != nil {
		s.setFailure(err)
		return res, err
	}
	if st.LastVaultFingerprint != vaultFingerprint {
		version := snapshot.SnapshotVersion
		if version <= 0 {
			version = time.Now().UTC().Unix()
			if version <= st.CurrentVaultVersion {
				version = st.CurrentVaultVersion + 1
			}
		}
		if err := s.state.SetVaultVersionFingerprint(version, vaultFingerprint); err != nil {
			log.Printf("worker: failed to persist vault version/fingerprint: %v", err)
		}
		st = s.state.Snapshot()
	}

	var firstErr error
	eventID := fmt.Sprintf("snapshot-%d", st.CurrentVaultVersion)
	masterID := masterServerIDFromURL(s.cfg.Master.BaseURL)
	for _, slave := range slaves {
		res.Attempted++
		if _, ok := activeControllers[strings.TrimSpace(slave.ControllerID)]; !ok {
			res.SkippedInactive++
			continue
		}
		if err := s.master.PairSlave(slave.SlaveID, slave.SlaveURL); err != nil {
			res.Failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("pair relay failed for slave_id=%s: %w", slave.SlaveID, err)
			}
			_ = s.state.MarkSlaveSyncError(slave.SlaveID, err.Error())
			log.Printf("worker: pair relay failed for slave_id=%s: %v", slave.SlaveID, err)
			continue
		}
		res.Paired++

		if slave.LastSyncedVersion >= st.CurrentVaultVersion && st.CurrentVaultVersion > 0 {
			res.SkippedUpToDate++
			continue
		}

		if err := s.master.ApplySnapshotToSlave(slave.SlaveURL, masterID, s.cfg.Master.BaseURL, snapshot); err != nil {
			res.Failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("snapshot apply failed for slave_id=%s: %w", slave.SlaveID, err)
			}
			_ = s.state.MarkSlaveSyncError(slave.SlaveID, err.Error())
			log.Printf("worker: snapshot apply failed for slave_id=%s: %v", slave.SlaveID, err)
			continue
		}
		if err := s.master.AckUpdate(masterID, slave.SlaveID, eventID, "applied"); err != nil {
			res.Failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("update ack failed for slave_id=%s: %w", slave.SlaveID, err)
			}
			_ = s.state.MarkSlaveSyncError(slave.SlaveID, err.Error())
			log.Printf("worker: update ack failed for slave_id=%s: %v", slave.SlaveID, err)
			continue
		}
		res.UpdatesSent++
		_ = s.state.MarkSlaveSynced(slave.SlaveID, st.CurrentVaultVersion, eventID)
	}

	if firstErr != nil {
		s.setFailure(firstErr)
		return res, firstErr
	}
	s.setSuccess()
	return res, nil
}

func (s *Server) setAttempt(at time.Time) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.LastAttemptAt = at
}

func (s *Server) setSuccess() {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	now := time.Now().UTC()
	s.status.LastSuccessAt = now
	s.status.LastError = ""
	s.status.ConsecutiveFailures = 0
}

func (s *Server) setFailure(err error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.ConsecutiveFailures++
	s.status.LastError = err.Error()
}

func (s *Server) setPending(msg string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.LastError = msg
}

func (s *Server) setNextAttempt(at time.Time) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status.NextAttemptAt = at.UTC()
}

func (s *Server) getStatus() workerStatus {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	return s.status
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func snapshotContentFingerprint(snapshot json.RawMessage) (string, error) {
	if len(snapshot) == 0 {
		return "", nil
	}
	var payload map[string]any
	if err := json.Unmarshal(snapshot, &payload); err != nil {
		return "", err
	}
	delete(payload, "version")
	delete(payload, "created_at")
	normalized, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:]), nil
}

func controllersFingerprint(controllers []master.ControllerInfo) string {
	if len(controllers) == 0 {
		return ""
	}
	parts := make([]string, 0, len(controllers))
	for _, c := range controllers {
		parts = append(parts, strings.TrimSpace(c.ID)+":"+strings.ToLower(strings.TrimSpace(c.Status)))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func hashPayload(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func masterServerIDFromURL(baseURL string) string {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || strings.TrimSpace(u.Host) == "" {
		return "master"
	}
	return u.Host
}

func pickHighestWeightActiveController(controllers []master.ControllerInfo) (master.ControllerInfo, bool) {
	var best master.ControllerInfo
	found := false
	for _, c := range controllers {
		if !strings.EqualFold(strings.TrimSpace(c.Status), "active") {
			continue
		}
		if !found || c.Weight > best.Weight {
			best = c
			found = true
		}
	}
	return best, found
}

func normalizeSlaveURL(raw string, defaultPort int) (string, error) {
	val := strings.TrimSpace(raw)
	if val == "" {
		return "", fmt.Errorf("slave_url is required")
	}
	if !strings.Contains(val, "://") {
		val = "http://" + val
	}
	u, err := url.Parse(val)
	if err != nil {
		return "", fmt.Errorf("invalid slave_url: %w", err)
	}
	if strings.TrimSpace(u.Hostname()) == "" {
		return "", fmt.Errorf("invalid slave_url: host is required")
	}
	if defaultPort > 0 && strings.TrimSpace(u.Port()) == "" {
		u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(defaultPort))
	}
	return strings.TrimRight(u.String(), "/"), nil
}
