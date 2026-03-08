package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/rand"
	"encoding/hex"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"password-manager-go/internal/crypto"
	"password-manager-go/internal/db"
	"password-manager-go/internal/importer"
	"password-manager-go/internal/models"
)

type ctxKey int

const userCtxKey ctxKey = 1

const (
	defaultPageSize      = 10
	defaultUnlockMinutes = 5
	controllerHealthcheckInterval = 30 * time.Second
	controllerHealthcheckTimeout  = 5 * time.Second
	serviceRestartTriggerDelay    = 500 * time.Millisecond
)

type uiSettings struct {
	PageSize      int
	UnlockMinutes int
	Firewall      bool
	APIKey        string
}

type controllerPairRequest struct {
	SlaveServerID string `json:"slave_server_id"`
	SlaveEndpoint string `json:"slave_endpoint"`
}

type controllerSnapshotApplyRequest struct {
	MasterServerID string `json:"master_server_id"`
	MasterURL      string `json:"master_url"`
	SnapshotVersion int64 `json:"snapshot_version"`
}

type controllerUpdateApplyRequest struct {
	MasterServerID string `json:"master_server_id"`
	EventID        string `json:"event_id"`
	VaultVersion   int64  `json:"vault_version"`
	PayloadHash    string `json:"payload_hash"`
}

type controllerUpdateAckRequest struct {
	MasterServerID string `json:"master_server_id"`
	SlaveServerID  string `json:"slave_server_id"`
	EventID        string `json:"event_id"`
	Status         string `json:"status"`
}

type controllerBootstrapAuthRequest struct {
	ControllerID string `json:"controller_id"`
	MasterKey    string `json:"master_key"`
}

type controllerRotateAuthRequest struct {
	ControllerID string `json:"controller_id"`
}

type controllerAuthTokenResponse struct {
	NextToken string `json:"next_token,omitempty"`
	Status    string `json:"status"`
	Approved  bool   `json:"approved"`
}

type Server struct {
	templateDir string
	store       *db.Store
	crypto      *crypto.Service
	unlock      *unlockManager
	controllerHTTPClient *http.Client
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

func NewServer(templates *template.Template, store *db.Store, cryptoSvc *crypto.Service) *Server {
	srv := &Server{
		templateDir: "templates",
		store:       store,
		crypto:      cryptoSvc,
		unlock:      newUnlockManager(),
		controllerHTTPClient: &http.Client{
			Timeout: controllerHealthcheckTimeout,
		},
	}
	srv.startControllerLinkHealthcheckLoop()
	return srv
}

func serviceRestartCommandParts() ([]string, error) {
	command := strings.TrimSpace(os.Getenv("UI_SERVICE_RESTART_COMMAND"))
	if command == "" {
		return nil, errors.New("ui service restart command is not configured")
	}
	args := strings.TrimSpace(os.Getenv("UI_SERVICE_RESTART_ARGS"))
	parts := []string{command}
	if args != "" {
		parts = append(parts, strings.Fields(args)...)
	}
	return parts, nil
}

func isUIServiceRestartEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("UI_SERVICE_RESTART_ENABLED")))
	if v != "1" && v != "true" && v != "yes" && v != "on" {
		return false
	}
	_, err := serviceRestartCommandParts()
	return err == nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	staticFS := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		} else if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		}
		staticFS.ServeHTTP(w, r)
	})))
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/setup", s.handleSetup)
	mux.HandleFunc("/controller/auth/bootstrap", s.handleControllerAuthBootstrap)
	mux.HandleFunc("/controller/auth/rotate", s.handleControllerAuthRotate)
	mux.HandleFunc("/controller/controllers", s.handleControllerListControllers)
	mux.HandleFunc("/controller/health", s.handleControllerHealth)
	mux.HandleFunc("/controller/pair", s.handleControllerPair)
	mux.HandleFunc("/controller/snapshot/apply", s.handleControllerSnapshotApply)
	mux.HandleFunc("/controller/update/apply", s.handleControllerUpdateApply)
	mux.HandleFunc("/controller/update/ack", s.handleControllerUpdateAck)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/passwords", s.handlePasswords)
	mux.HandleFunc("/passwords/new", s.handlePasswordForm)
	mux.HandleFunc("/passwords/edit", s.handlePasswordEdit)
	mux.HandleFunc("/passwords/update-password", s.handlePasswordUpdatePassword)
	mux.HandleFunc("/passwords/delete", s.handlePasswordDelete)
	mux.HandleFunc("/passwords/view", s.handlePasswordView)
	mux.HandleFunc("/passwords/share", s.handlePasswordShare)
	mux.HandleFunc("/passwords/share-link", s.handlePasswordShareLink)
	mux.HandleFunc("/notes", s.handleNotes)
	mux.HandleFunc("/notes/new", s.handleNoteForm)
	mux.HandleFunc("/notes/edit", s.handleNoteEdit)
	mux.HandleFunc("/notes/delete", s.handleNoteDelete)
	mux.HandleFunc("/notes/view", s.handleNoteView)
	mux.HandleFunc("/notes/share", s.handleNoteShare)
	mux.HandleFunc("/groups", s.handleGroups)
	mux.HandleFunc("/groups/view", s.handleGroupDetail)
	mux.HandleFunc("/tags", s.handleTags)
	mux.HandleFunc("/tags/view", s.handleTagDetail)
	mux.HandleFunc("/settings", s.handleSettings)
	mux.HandleFunc("/share/password", s.handleSharedPassword)
	mux.HandleFunc("/import/1password", s.handleImport1Password)
	mux.HandleFunc("/import/issues", s.handleImportIssues)
	mux.HandleFunc("/auth/biometric-unlock", s.handleBiometricUnlock)
	mux.HandleFunc("/auth/biometric-token", s.handleBiometricToken)
	mux.HandleFunc("/unlock", s.handleUnlockPage)
	mux.HandleFunc("/lock", s.handleLock)
	mux.HandleFunc("/account", s.handleAccount)
	mux.HandleFunc("/account/update", s.handleAccountUpdate)
	mux.HandleFunc("/admin", s.handleAdmin)
	mux.HandleFunc("/admin/backup", s.handleAdminBackup)
	mux.HandleFunc("/admin/restore", s.handleAdminRestore)
	mux.HandleFunc("/admin/rebuild", s.handleAdminRebuild)
	mux.HandleFunc("/admin/users", s.handleAdminCreateUser)
	mux.HandleFunc("/admin/users/create", s.handleAdminUsersCreatePage)
	mux.HandleFunc("/admin/users/list", s.handleAdminUsersListPage)
	mux.HandleFunc("/admin/users/update", s.handleAdminUpdateUser)
	mux.HandleFunc("/admin/controllers/status", s.handleAdminSetControllerStatus)
	mux.HandleFunc("/admin/controller-links/cleanup", s.handleAdminCleanupControllerLinks)
	mux.HandleFunc("/admin/service/restart", s.handleAdminServiceRestart)
	mux.HandleFunc("/admin/records/clear-tags", s.handleAdminClearRecordTags)
	mux.HandleFunc("/admin/records/clear-groups", s.handleAdminClearRecordGroups)
	mux.HandleFunc("/admin/tags/clear-all", s.handleAdminClearAllTags)
	mux.HandleFunc("/admin/groups/clear-all", s.handleAdminClearAllGroups)
	return s.authMiddleware(mux)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	stats, err := s.store.GetStats(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "index.html", map[string]any{
		"Title": "Dashboard",
		"Stats": stats,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		count, err := s.store.CountUsers(r.Context())
		if err == nil && count == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		s.renderWithUnlock(w, r, "login.html", map[string]any{
			"Title": "Login",
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		user, err := s.store.GetUserByEmail(r.Context(), email)
		if err != nil || !crypto.VerifyPassword(password, user.PasswordHash) {
			s.renderWithUnlock(w, r, "login.html", map[string]any{
				"Title": "Login",
				"Error": "Invalid credentials",
			})
			return
		}
		if user.Status != "active" {
			if err := s.store.SetUserStatus(r.Context(), user.ID, "active"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			user.Status = "active"
		}
		sessionID := uuid.New().String()
		expiresAt := time.Now().Add(7 * 24 * time.Hour)
		if err := s.store.CreateSession(r.Context(), models.Session{
			ID:        sessionID,
			UserID:    user.ID,
			ExpiresAt: expiresAt,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "pm_session",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   isSecureRequest(r),
			MaxAge:   int((7 * 24 * time.Hour).Seconds()),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie("pm_session"); err == nil {
		_ = s.store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "pm_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.CountUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.renderWithUnlock(w, r, "setup.html", map[string]any{
			"Title": "Create Admin",
			"ServerMode": "AS-M",
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		loginPassword := r.FormValue("login_password")
		masterPassword := r.FormValue("master_password")
		serverMode := strings.ToUpper(strings.TrimSpace(r.FormValue("server_mode")))
		linkedMasterID := strings.TrimSpace(r.FormValue("linked_master_id"))
		linkedMasterURL := strings.TrimSpace(r.FormValue("linked_master_url"))
		if loginPassword == "" || masterPassword == "" {
			http.Error(w, "both passwords required", http.StatusBadRequest)
			return
		}
		if email == "" {
			http.Error(w, "email required", http.StatusBadRequest)
			return
		}
		if loginPassword == masterPassword {
			http.Error(w, "login and master passwords must differ", http.StatusBadRequest)
			return
		}
		switch serverMode {
		case "AS-M":
			linkedMasterID = ""
			linkedMasterURL = ""
		case "AS-S":
			if linkedMasterURL == "" {
				http.Error(w, "linked master URL required for AS-S mode", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "invalid server mode", http.StatusBadRequest)
			return
		}
		loginHash, err := crypto.HashPassword(loginPassword)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		masterHash, err := crypto.HashPassword(masterPassword)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		syncStatus := "standalone"
		if serverMode == "AS-S" {
			syncStatus = "await_updates"
		}
		if err := s.store.SetServerProfile(r.Context(), models.ServerProfile{
			ServerMode:      serverMode,
			SyncStatus:      syncStatus,
			LinkedMasterID:  linkedMasterID,
			LinkedMasterURL: linkedMasterURL,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		adminID := uuid.New().String()
		if err := s.store.CreateUser(r.Context(), models.User{
			ID:                 adminID,
			Email:              email,
			Status:             "active",
			PasswordHash:       loginHash,
			MasterPasswordHash: masterHash,
			IsAdmin:            true,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = s.store.AssignUnownedToUser(r.Context(), adminID)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func decodeJSONBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) authorizeController(w http.ResponseWriter, r *http.Request) bool {
	expected := strings.TrimSpace(os.Getenv("CONTROLLER_SHARED_TOKEN"))
	if expected == "" {
		http.Error(w, "controller auth is not configured", http.StatusServiceUnavailable)
		return false
	}
	got := strings.TrimSpace(r.Header.Get("X-Controller-Token"))
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func hashControllerToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func bearerTokenFromRequest(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(raw, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(raw, prefix))
}

func (s *Server) handleControllerAuthBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req controllerBootstrapAuthRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	req.ControllerID = strings.TrimSpace(req.ControllerID)
	req.MasterKey = strings.TrimSpace(req.MasterKey)
	if req.ControllerID == "" || req.MasterKey == "" {
		http.Error(w, "controller_id and master_key are required", http.StatusBadRequest)
		return
	}
	expectedMasterKey := strings.TrimSpace(os.Getenv("CONTROLLER_MASTER_KEY"))
	if expectedMasterKey == "" {
		http.Error(w, "controller master key is not configured", http.StatusServiceUnavailable)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.MasterKey), []byte(expectedMasterKey)) != 1 {
		http.Error(w, "invalid master key", http.StatusUnauthorized)
		return
	}
	status, err := s.store.UpsertControllerRegistry(r.Context(), req.ControllerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if status != "active" {
		writeJSON(w, http.StatusAccepted, controllerAuthTokenResponse{
			Status:   "pending_approval",
			Approved: false,
		})
		return
	}
	nextToken, err := randomToken()
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	if err := s.store.IssueControllerTokenByID(r.Context(), req.ControllerID, hashControllerToken(nextToken)); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, controllerAuthTokenResponse{
		NextToken: nextToken,
		Status:    "approved",
		Approved:  true,
	})
}

func (s *Server) handleControllerAuthRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerTokenFromRequest(r)
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	var req controllerRotateAuthRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	req.ControllerID = strings.TrimSpace(req.ControllerID)
	if req.ControllerID == "" {
		http.Error(w, "controller_id is required", http.StatusBadRequest)
		return
	}
	nextToken, err := randomToken()
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	if err := s.store.RotateControllerTokenByID(r.Context(), req.ControllerID, hashControllerToken(token), hashControllerToken(nextToken)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, controllerAuthTokenResponse{
		NextToken: nextToken,
		Status:    "approved",
		Approved:  true,
	})
}

func (s *Server) handleControllerListControllers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerTokenFromRequest(r)
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	nextToken, err := randomToken()
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	if _, err := s.store.RotateControllerTokenByHash(r.Context(), hashControllerToken(token), hashControllerToken(nextToken)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	registry, err := s.store.ListControllerRegistry(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var controllers []map[string]string
	for _, entry := range registry {
		controllers = append(controllers, map[string]string{
			"id":     entry.ControllerID,
			"name":   entry.ControllerID,
			"status": entry.Status,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"controllers": controllers,
		"next_token":  nextToken,
	})
}

func (s *Server) handleControllerHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorizeController(w, r) {
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-S" {
		http.Error(w, "health endpoint is allowed only on AS-S", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"server_mode": profile.ServerMode,
		"sync_status": profile.SyncStatus,
		"checked_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleControllerPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorizeController(w, r) {
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-M" {
		http.Error(w, "pairing is allowed only on AS-M", http.StatusConflict)
		return
	}
	var req controllerPairRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	if err := s.store.UpsertControllerLink(r.Context(), req.SlaveServerID, req.SlaveEndpoint); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "paired",
		"master_mode":     profile.ServerMode,
		"slave_server_id": strings.TrimSpace(req.SlaveServerID),
	})
}

func (s *Server) startControllerLinkHealthcheckLoop() {
	go func() {
		// Run once on startup, then periodically.
		s.runControllerLinkHealthcheck()
		ticker := time.NewTicker(controllerHealthcheckInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.runControllerLinkHealthcheck()
		}
	}()
}

func (s *Server) runControllerLinkHealthcheck() {
	ctx, cancel := context.WithTimeout(context.Background(), controllerHealthcheckTimeout)
	profile, err := s.store.GetServerProfile(ctx)
	cancel()
	if err != nil || profile.ServerMode != "AS-M" {
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), controllerHealthcheckTimeout)
	links, err := s.store.ListControllerLinks(ctx)
	cancel()
	if err != nil || len(links) == 0 {
		return
	}
	token := strings.TrimSpace(os.Getenv("CONTROLLER_SHARED_TOKEN"))
	if token == "" {
		return
	}
	for _, link := range links {
		slaveID := strings.TrimSpace(link.SlaveServerID)
		endpoint := strings.TrimSpace(link.SlaveEndpoint)
		if slaveID == "" || endpoint == "" {
			continue
		}
		healthURL := strings.TrimRight(endpoint, "/") + "/controller/health"
		req, err := http.NewRequest(http.MethodGet, healthURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-Controller-Token", token)
		resp, err := s.controllerHTTPClient.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), controllerHealthcheckTimeout)
		_ = s.store.TouchControllerLinkHandshake(ctx, slaveID, "active")
		cancel()
	}
}

func (s *Server) handleControllerSnapshotApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorizeController(w, r) {
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-S" {
		http.Error(w, "snapshot apply is allowed only on AS-S", http.StatusConflict)
		return
	}
	var req controllerSnapshotApplyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	if req.SnapshotVersion <= 0 || strings.TrimSpace(req.MasterURL) == "" {
		http.Error(w, "master_url and snapshot_version are required", http.StatusBadRequest)
		return
	}
	if err := s.store.SetServerProfile(r.Context(), models.ServerProfile{
		ServerMode:      profile.ServerMode,
		SyncStatus:      "await_updates",
		LinkedMasterID:  strings.TrimSpace(req.MasterServerID),
		LinkedMasterURL: strings.TrimSpace(req.MasterURL),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "snapshot_applied",
		"sync_status":      "await_updates",
		"snapshot_version": req.SnapshotVersion,
	})
}

func (s *Server) handleControllerUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorizeController(w, r) {
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-S" {
		http.Error(w, "update apply is allowed only on AS-S", http.StatusConflict)
		return
	}
	var req controllerUpdateApplyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	inserted, err := s.store.InsertControllerUpdateEvent(
		r.Context(),
		req.EventID,
		req.MasterServerID,
		req.VaultVersion,
		req.PayloadHash,
		"applied",
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "accepted",
		"event_id":      strings.TrimSpace(req.EventID),
		"vault_version": req.VaultVersion,
		"duplicate":     !inserted,
	})
}

func (s *Server) handleControllerUpdateAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorizeController(w, r) {
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-M" {
		http.Error(w, "update ack is allowed only on AS-M", http.StatusConflict)
		return
	}
	var req controllerUpdateAckRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.EventID) == "" {
		http.Error(w, "event_id is required", http.StatusBadRequest)
		return
	}
	linkStatus := "active"
	if v := strings.ToLower(strings.TrimSpace(req.Status)); v == "error" || v == "failed" {
		linkStatus = "disabled"
	}
	if strings.TrimSpace(req.SlaveServerID) != "" {
		if err := s.store.TouchControllerLinkHandshake(r.Context(), req.SlaveServerID, linkStatus); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ack_received",
		"event_id": strings.TrimSpace(req.EventID),
	})
}

func (s *Server) handlePasswords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	searchField, searchText := parseFieldSearch(r, "all")
	if !s.isUnlocked(r) {
		s.renderWithUnlock(w, r, "passwords.html", map[string]any{
			"Title":  "Passwords",
			"Locked": true,
			"Search": map[string]string{
				"Field": searchField,
				"Q":     searchText,
			},
		})
		return
	}
	items, err := s.store.ListPasswords(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var viewItems []map[string]string
	for _, item := range items {
		sharedLabel := ""
		if item.UserID != user.ID && item.OwnerEmail != "" {
			sharedLabel = "Shared by " + item.OwnerEmail
		}
		viewItems = append(viewItems, map[string]string{
			"ID":          item.ID,
			"Title":       item.Title,
			"Username":    item.Username,
			"URL":         item.URL,
			"Tags":        strings.Join(item.Tags, ", "),
			"Groups":      strings.Join(item.Groups, ", "),
			"SharedLabel": sharedLabel,
			"CanManage":   fmt.Sprintf("%t", item.UserID == user.ID),
		})
	}
	viewItems = filterPasswordRows(viewItems, searchField, searchText)
	page := parsePage(r, 1)
	pageSize := s.readUISettings(r).PageSize
	start, end, pager := paginateWindow(len(viewItems), page, pageSize)
	if pager["HasPrev"].(bool) {
		pager["PrevURL"] = buildPageURL("/passwords", searchField, searchText, pager["PrevPage"].(int))
	}
	if pager["HasNext"].(bool) {
		pager["NextURL"] = buildPageURL("/passwords", searchField, searchText, pager["NextPage"].(int))
	}
	viewItems = viewItems[start:end]
	s.renderWithUnlock(w, r, "passwords.html", map[string]any{
		"Title": "Passwords",
		"Items": viewItems,
		"Pager": pager,
		"Search": map[string]string{
			"Field": searchField,
			"Q":     searchText,
		},
	})
}

func (s *Server) handlePasswordForm(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		tags, err := s.store.ListTags(r.Context(), user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		groups, err := s.store.ListGroups(r.Context(), user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var tagNames []string
		for _, tag := range tags {
			tagNames = append(tagNames, tag.Name)
		}
		var groupNames []string
		for _, group := range groups {
			groupNames = append(groupNames, group.Name)
		}
		s.renderWithUnlock(w, r, "password_form.html", map[string]any{
			"Title":      "New Password",
			"Item":       models.PasswordEntry{},
			"TagsText":   "",
			"GroupsText": "",
			"TagsList":   tagNames,
			"GroupsList": groupNames,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		entry := models.PasswordEntry{
			UserID:   user.ID,
			Title:    strings.TrimSpace(r.FormValue("title")),
			Username: strings.TrimSpace(r.FormValue("username")),
			Password: r.FormValue("password"),
			URL:      strings.TrimSpace(r.FormValue("url")),
			Notes:    strings.TrimSpace(r.FormValue("notes")),
			Tags:     splitComma(r.FormValue("tags")),
			Groups:   splitComma(r.FormValue("groups")),
		}
		if err := s.store.UpsertPassword(r.Context(), s.crypto, entry); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/passwords", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePasswordEdit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.isUnlocked(r) {
			http.Error(w, "locked", http.StatusForbidden)
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
		if err != nil || entry.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		tags, err := s.store.ListTags(r.Context(), user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		groups, err := s.store.ListGroups(r.Context(), user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var tagNames []string
		for _, tag := range tags {
			tagNames = append(tagNames, tag.Name)
		}
		var groupNames []string
		for _, group := range groups {
			groupNames = append(groupNames, group.Name)
		}
		s.renderWithUnlock(w, r, "password_form.html", map[string]any{
			"Title":      "Edit Password",
			"Item":       entry,
			"TagsText":   strings.Join(entry.Tags, ", "),
			"GroupsText": strings.Join(entry.Groups, ", "),
			"TagsList":   tagNames,
			"GroupsList": groupNames,
		})
	case http.MethodPost:
		if !s.isUnlocked(r) {
			http.Error(w, "locked", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		entry := models.PasswordEntry{
			ID:       r.FormValue("id"),
			UserID:   user.ID,
			Title:    strings.TrimSpace(r.FormValue("title")),
			Username: strings.TrimSpace(r.FormValue("username")),
			Password: r.FormValue("password"),
			URL:      strings.TrimSpace(r.FormValue("url")),
			Notes:    strings.TrimSpace(r.FormValue("notes")),
			Tags:     splitComma(r.FormValue("tags")),
			Groups:   splitComma(r.FormValue("groups")),
		}
		if err := s.store.UpdatePassword(r.Context(), s.crypto, entry); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/passwords", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePasswordUpdatePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "locked", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	newPassword := r.FormValue("password")
	if strings.TrimSpace(newPassword) == "" {
		http.Error(w, "missing password", http.StatusBadRequest)
		return
	}
	entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if entry.UserID != user.ID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	entry.Password = newPassword
	if err := s.store.UpdatePassword(r.Context(), s.crypto, entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/passwords/view?id="+id, http.StatusSeeOther)
}

func (s *Server) handlePasswordDelete(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
		if err != nil || entry.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderWithUnlock(w, r, "delete_confirm.html", map[string]any{
			"Title":      "Delete Password",
			"ItemID":     entry.ID,
			"ItemName":   entry.Title,
			"DeletePath": "/passwords/delete",
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		if !s.isUnlocked(r) {
			http.Error(w, "unlock required", http.StatusUnauthorized)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err := s.store.DeletePassword(r.Context(), user.ID, id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/passwords", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	searchField, searchText := parseFieldSearch(r, "all")
	if !s.isUnlocked(r) {
		s.renderWithUnlock(w, r, "notes.html", map[string]any{
			"Title":  "Secure Notes",
			"Locked": true,
			"Search": map[string]string{
				"Field": searchField,
				"Q":     searchText,
			},
		})
		return
	}
	items, err := s.store.ListNotes(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var viewItems []map[string]string
	for _, item := range items {
		sharedLabel := ""
		if item.UserID != user.ID && item.OwnerEmail != "" {
			sharedLabel = "Shared by " + item.OwnerEmail
		}
		viewItems = append(viewItems, map[string]string{
			"ID":          item.ID,
			"Title":       item.Title,
			"Updated":     item.UpdatedAt.Format(time.RFC3339),
			"Tags":        strings.Join(item.Tags, ", "),
			"Groups":      strings.Join(item.Groups, ", "),
			"SharedLabel": sharedLabel,
			"CanManage":   fmt.Sprintf("%t", item.UserID == user.ID),
		})
	}
	viewItems = filterNoteRows(viewItems, searchField, searchText)
	page := parsePage(r, 1)
	pageSize := s.readUISettings(r).PageSize
	start, end, pager := paginateWindow(len(viewItems), page, pageSize)
	if pager["HasPrev"].(bool) {
		pager["PrevURL"] = buildPageURL("/notes", searchField, searchText, pager["PrevPage"].(int))
	}
	if pager["HasNext"].(bool) {
		pager["NextURL"] = buildPageURL("/notes", searchField, searchText, pager["NextPage"].(int))
	}
	viewItems = viewItems[start:end]
	s.renderWithUnlock(w, r, "notes.html", map[string]any{
		"Title": "Secure Notes",
		"Items": viewItems,
		"Pager": pager,
		"Search": map[string]string{
			"Field": searchField,
			"Q":     searchText,
		},
	})
}

func (s *Server) handleNoteForm(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		tags, err := s.store.ListTags(r.Context(), user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		groups, err := s.store.ListGroups(r.Context(), user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var tagNames []string
		for _, tag := range tags {
			tagNames = append(tagNames, tag.Name)
		}
		var groupNames []string
		for _, group := range groups {
			groupNames = append(groupNames, group.Name)
		}
		s.renderWithUnlock(w, r, "note_form.html", map[string]any{
			"Title":      "New Note",
			"Item":       models.SecureNote{},
			"TagsText":   "",
			"GroupsText": "",
			"TagsList":   tagNames,
			"GroupsList": groupNames,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		note := models.SecureNote{
			UserID: user.ID,
			Title:  strings.TrimSpace(r.FormValue("title")),
			Body:   strings.TrimSpace(r.FormValue("body")),
			Tags:   splitComma(r.FormValue("tags")),
			Groups: splitComma(r.FormValue("groups")),
		}
		if err := s.store.InsertSecureNote(r.Context(), s.crypto, note); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNoteEdit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.isUnlocked(r) {
			http.Error(w, "locked", http.StatusForbidden)
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		note, err := s.store.GetNote(r.Context(), s.crypto, id, user.ID)
		if err != nil || note.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		tags, err := s.store.ListTags(r.Context(), user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		groups, err := s.store.ListGroups(r.Context(), user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var tagNames []string
		for _, tag := range tags {
			tagNames = append(tagNames, tag.Name)
		}
		var groupNames []string
		for _, group := range groups {
			groupNames = append(groupNames, group.Name)
		}
		s.renderWithUnlock(w, r, "note_form.html", map[string]any{
			"Title":      "Edit Note",
			"Item":       note,
			"TagsText":   strings.Join(note.Tags, ", "),
			"GroupsText": strings.Join(note.Groups, ", "),
			"TagsList":   tagNames,
			"GroupsList": groupNames,
		})
	case http.MethodPost:
		if !s.isUnlocked(r) {
			http.Error(w, "locked", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		note := models.SecureNote{
			ID:     r.FormValue("id"),
			UserID: user.ID,
			Title:  strings.TrimSpace(r.FormValue("title")),
			Body:   strings.TrimSpace(r.FormValue("body")),
			Tags:   splitComma(r.FormValue("tags")),
			Groups: splitComma(r.FormValue("groups")),
		}
		if err := s.store.UpdateNote(r.Context(), s.crypto, note); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNoteDelete(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		note, err := s.store.GetNote(r.Context(), s.crypto, id, user.ID)
		if err != nil || note.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderWithUnlock(w, r, "delete_confirm.html", map[string]any{
			"Title":      "Delete Secure Note",
			"ItemID":     note.ID,
			"ItemName":   note.Title,
			"DeletePath": "/notes/delete",
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		if !s.isUnlocked(r) {
			http.Error(w, "unlock required", http.StatusUnauthorized)
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err := s.store.DeleteNote(r.Context(), user.ID, id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNoteView(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		note, err := s.store.GetNote(r.Context(), s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderNoteView(w, r, user, note, s.isUnlocked(r), "")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if !s.isUnlocked(r) {
			http.Error(w, "unlock required", http.StatusUnauthorized)
			return
		}
		note, err := s.store.GetNote(r.Context(), s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderNoteView(w, r, user, note, true, "")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePasswordView(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderPasswordView(w, r, user, entry, s.isUnlocked(r), "", "")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if !s.isUnlocked(r) {
			http.Error(w, "unlock required", http.StatusUnauthorized)
			return
		}
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderPasswordView(w, r, user, entry, true, "", "")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderPasswordView(w http.ResponseWriter, r *http.Request, user models.User, entry models.PasswordEntry, showSecret bool, message string, shareLink string) {
	canManage := entry.UserID == user.ID
	data := map[string]any{
		"Title":        "View Password",
		"ItemID":       entry.ID,
		"ItemName":     entry.Title,
		"Username":     entry.Username,
		"URL":          entry.URL,
		"TagsText":     strings.Join(entry.Tags, ", "),
		"GroupsText":   strings.Join(entry.Groups, ", "),
		"ImportSource": entry.ImportSource,
		"ImportRaw":    entry.ImportRaw,
		"ImportRawB64": base64.StdEncoding.EncodeToString([]byte(entry.ImportRaw)),
		"OwnerEmail":   entry.OwnerEmail,
		"CanManage":    canManage,
	}
	if showSecret {
		data["Password"] = entry.Password
		data["Notes"] = entry.Notes
	}
	if message != "" {
		data["Message"] = message
	}
	if shareLink != "" {
		data["ShareLink"] = shareLink
	}
	if canManage {
		if shareTargets, err := s.store.ListActiveUsersExcept(r.Context(), user.ID); err == nil {
			data["ShareTargets"] = shareTargets
		}
		if sharedWith, err := s.store.ListPasswordShareEmails(r.Context(), entry.ID); err == nil {
			data["SharedWith"] = sharedWith
		}
	}
	s.renderWithUnlock(w, r, "password_view.html", data)
}

func (s *Server) renderNoteView(w http.ResponseWriter, r *http.Request, user models.User, note models.SecureNote, showSecret bool, message string) {
	canManage := note.UserID == user.ID
	data := map[string]any{
		"Title":      "View Secure Note",
		"ItemID":     note.ID,
		"ItemName":   note.Title,
		"TagsText":   strings.Join(note.Tags, ", "),
		"GroupsText": strings.Join(note.Groups, ", "),
		"OwnerEmail": note.OwnerEmail,
		"CanManage":  canManage,
	}
	if showSecret {
		data["Body"] = note.Body
	}
	if message != "" {
		data["Message"] = message
	}
	if canManage {
		if shareTargets, err := s.store.ListActiveUsersExcept(r.Context(), user.ID); err == nil {
			data["ShareTargets"] = shareTargets
		}
		if sharedWith, err := s.store.ListNoteShareEmails(r.Context(), note.ID); err == nil {
			data["SharedWith"] = sharedWith
		}
	}
	s.renderWithUnlock(w, r, "note_view.html", data)
}

func (s *Server) handlePasswordShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
	if err != nil || entry.UserID != user.ID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	targetEmail := strings.TrimSpace(r.FormValue("share_email"))
	if targetEmail == "" {
		s.renderPasswordView(w, r, user, entry, true, "Select a user to share with.", "")
		return
	}
	if err := s.store.SharePasswordWithUser(r.Context(), user.ID, id, targetEmail); err != nil {
		s.renderPasswordView(w, r, user, entry, true, err.Error(), "")
		return
	}
	updated, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderPasswordView(w, r, user, updated, true, "Password shared.", "")
}

func (s *Server) handlePasswordShareLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
	if err != nil || entry.UserID != user.ID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	expiresMinutes, err := strconv.Atoi(strings.TrimSpace(r.FormValue("expires_minutes")))
	if err != nil || expiresMinutes < 1 || expiresMinutes > 10080 {
		s.renderPasswordView(w, r, user, entry, true, "Expiration must be between 1 and 10080 minutes.", "")
		return
	}
	token, err := randomToken()
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().Add(time.Duration(expiresMinutes) * time.Minute)
	if err := s.store.CreatePasswordShareLink(r.Context(), token, entry.ID, user.ID, expiresAt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scheme := "http"
	if isSecureRequest(r) {
		scheme = "https"
	}
	shareLink := fmt.Sprintf("%s://%s/share/password?token=%s", scheme, r.Host, urlQueryEscape(token))
	msg := fmt.Sprintf("Share URL created. Expires at %s.", expiresAt.Format(time.RFC3339))
	updated, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderPasswordView(w, r, user, updated, true, msg, shareLink)
}

func (s *Server) handleSharedPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	link, err := s.store.GetPasswordShareLinkByToken(r.Context(), token)
	if err != nil {
		http.Error(w, "link is invalid or expired", http.StatusNotFound)
		return
	}
	entry, err := s.store.GetPasswordForShare(r.Context(), s.crypto, link.EntryID)
	if err != nil {
		http.Error(w, "link is invalid or expired", http.StatusNotFound)
		return
	}
	s.render(w, "shared_password.html", map[string]any{
		"Title":      "Shared Password",
		"ItemName":   entry.Title,
		"Username":   entry.Username,
		"Password":   entry.Password,
		"URL":        entry.URL,
		"Notes":      entry.Notes,
		"OwnerEmail": entry.OwnerEmail,
		"ExpiresAt":  link.ExpiresAt,
	})
}

func (s *Server) handleNoteShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	note, err := s.store.GetNote(r.Context(), s.crypto, id, user.ID)
	if err != nil || note.UserID != user.ID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	targetEmail := strings.TrimSpace(r.FormValue("share_email"))
	if targetEmail == "" {
		s.renderNoteView(w, r, user, note, true, "Select a user to share with.")
		return
	}
	if err := s.store.ShareNoteWithUser(r.Context(), user.ID, id, targetEmail); err != nil {
		s.renderNoteView(w, r, user, note, true, err.Error())
		return
	}
	updated, err := s.store.GetNote(r.Context(), s.crypto, id, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderNoteView(w, r, user, updated, true, "Secure note shared.")
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderWithUnlock(w, r, "account.html", map[string]any{
		"Title": "Account",
		"User":  user,
	})
}

func (s *Server) handleAccountUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	currentLogin := r.FormValue("current_login_password")
	currentMaster := r.FormValue("current_master_password")
	newLogin := r.FormValue("new_login_password")
	newMaster := r.FormValue("new_master_password")
	if strings.TrimSpace(newLogin) == "" && strings.TrimSpace(newMaster) == "" {
		s.renderWithUnlock(w, r, "account.html", map[string]any{
			"Title": "Account",
			"User":  user,
			"Error": "Provide a new login password, a new master password, or both.",
		})
		return
	}
	if strings.TrimSpace(newLogin) != "" && !crypto.VerifyPassword(currentLogin, user.PasswordHash) {
		s.renderWithUnlock(w, r, "account.html", map[string]any{
			"Title": "Account",
			"User":  user,
			"Error": "Current login password is invalid.",
		})
		return
	}
	if strings.TrimSpace(newMaster) != "" && !crypto.VerifyPassword(currentMaster, user.MasterPasswordHash) {
		s.renderWithUnlock(w, r, "account.html", map[string]any{
			"Title": "Account",
			"User":  user,
			"Error": "Current master password is invalid.",
		})
		return
	}
	if strings.TrimSpace(newLogin) != "" && strings.TrimSpace(newMaster) != "" && newLogin == newMaster {
		s.renderWithUnlock(w, r, "account.html", map[string]any{
			"Title": "Account",
			"User":  user,
			"Error": "Login and master passwords must differ.",
		})
		return
	}
	var loginHash *string
	if strings.TrimSpace(newLogin) != "" {
		hash, err := crypto.HashPassword(newLogin)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		loginHash = &hash
	}
	var masterHash *string
	if strings.TrimSpace(newMaster) != "" {
		hash, err := crypto.HashPassword(newMaster)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		masterHash = &hash
	}
	if err := s.store.UpdateUserCredentials(r.Context(), user.ID, loginHash, masterHash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	updatedUser, err := s.store.GetUserByID(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "account.html", map[string]any{
		"Title":   "Account",
		"User":    updatedUser,
		"Message": "Credentials updated.",
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	settings := s.readUISettings(r)
	switch r.Method {
	case http.MethodGet:
		s.renderWithUnlock(w, r, "settings.html", map[string]any{
			"Title":    "Settings",
			"Settings": settings,
			"User":     user,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		pageSize, err := strconv.Atoi(strings.TrimSpace(r.FormValue("page_size")))
		if err != nil || pageSize < 5 || pageSize > 200 {
			pageSize = settings.PageSize
		}
		unlockMinutes, err := strconv.Atoi(strings.TrimSpace(r.FormValue("unlock_minutes")))
		if err != nil || unlockMinutes < 1 || unlockMinutes > 120 {
			unlockMinutes = settings.UnlockMinutes
		}
		firewallEnabled := r.FormValue("firewall_enabled") == "on"
		apiKey := strings.TrimSpace(r.FormValue("api_key"))
		nextSettings := uiSettings{
			PageSize:      pageSize,
			UnlockMinutes: unlockMinutes,
			Firewall:      firewallEnabled,
			APIKey:        apiKey,
		}
		s.writeUISettings(w, r, nextSettings)
		s.renderWithUnlock(w, r, "settings.html", map[string]any{
			"Title":    "Settings",
			"Settings": nextSettings,
			"User":     user,
			"Message":  "Settings saved.",
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBiometricUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	next := r.FormValue("next")
	if next == "" {
		next = "/"
	}
	if !strings.HasPrefix(next, "/") {
		next = "/"
	}

	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if token := r.FormValue("token"); token != "" {
		if !s.unlock.ConsumePreauth(token) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
	} else {
		master := r.FormValue("master_password")
		if !crypto.VerifyPassword(master, user.MasterPasswordHash) {
			http.Error(w, "master password is invalid", http.StatusUnauthorized)
			return
		}
	}
	settings := s.readUISettings(r)
	unlockMinutes := settings.UnlockMinutes
	if raw := strings.TrimSpace(r.FormValue("unlock_minutes")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 && parsed <= 120 {
			unlockMinutes = parsed
		}
	}
	cookieToken, err := s.unlock.Issue(user.ID, time.Duration(unlockMinutes)*time.Minute)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "pm_unlock",
		Value:    cookieToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
		MaxAge:   unlockMinutes * 60,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleBiometricToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	master := r.FormValue("master_password")
	user, err := s.store.GetUserByEmail(r.Context(), email)
	if err != nil || !crypto.VerifyPassword(master, user.MasterPasswordHash) {
		http.Error(w, "master password is invalid", http.StatusUnauthorized)
		return
	}
	token, err := s.unlock.IssuePreauth(15 * time.Second)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":"%s","expires_in":15}`, token)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	searchField, searchText := parseFieldSearch(r, "name")
	if !s.isUnlocked(r) {
		s.renderWithUnlock(w, r, "groups.html", map[string]any{
			"Title":  "Groups",
			"Locked": true,
			"Search": map[string]string{
				"Field": searchField,
				"Q":     searchText,
			},
		})
		return
	}
	items, err := s.store.ListGroups(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var viewItems []map[string]any
	for _, g := range items {
		viewItems = append(viewItems, map[string]any{
			"Name": g.Name,
			"Count": g.Count,
			"URL":  "/groups/view?name=" + urlQueryEscape(g.Name),
		})
	}
	viewItems = filterCollectionRows(viewItems, searchField, searchText)
	page := parsePage(r, 1)
	pageSize := s.readUISettings(r).PageSize
	start, end, pager := paginateWindow(len(viewItems), page, pageSize)
	if pager["HasPrev"].(bool) {
		pager["PrevURL"] = buildPageURL("/groups", searchField, searchText, pager["PrevPage"].(int))
	}
	if pager["HasNext"].(bool) {
		pager["NextURL"] = buildPageURL("/groups", searchField, searchText, pager["NextPage"].(int))
	}
	viewItems = viewItems[start:end]
	s.renderWithUnlock(w, r, "groups.html", map[string]any{
		"Title": "Groups",
		"Items": viewItems,
		"Pager": pager,
		"Search": map[string]string{
			"Field": searchField,
			"Q":     searchText,
		},
	})
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	searchField, searchText := parseFieldSearch(r, "name")
	if !s.isUnlocked(r) {
		s.renderWithUnlock(w, r, "tags.html", map[string]any{
			"Title":  "Tags",
			"Locked": true,
			"Search": map[string]string{
				"Field": searchField,
				"Q":     searchText,
			},
		})
		return
	}
	items, err := s.store.ListTags(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var viewItems []map[string]any
	for _, t := range items {
		viewItems = append(viewItems, map[string]any{
			"Name": t.Name,
			"Count": t.Count,
			"URL":  "/tags/view?name=" + urlQueryEscape(t.Name),
		})
	}
	viewItems = filterCollectionRows(viewItems, searchField, searchText)
	page := parsePage(r, 1)
	pageSize := s.readUISettings(r).PageSize
	start, end, pager := paginateWindow(len(viewItems), page, pageSize)
	if pager["HasPrev"].(bool) {
		pager["PrevURL"] = buildPageURL("/tags", searchField, searchText, pager["PrevPage"].(int))
	}
	if pager["HasNext"].(bool) {
		pager["NextURL"] = buildPageURL("/tags", searchField, searchText, pager["NextPage"].(int))
	}
	viewItems = viewItems[start:end]
	s.renderWithUnlock(w, r, "tags.html", map[string]any{
		"Title": "Tags",
		"Items": viewItems,
		"Pager": pager,
		"Search": map[string]string{
			"Field": searchField,
			"Q":     searchText,
		},
	})
}

func (s *Server) handleGroupDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	passwords, err := s.store.ListPasswordsByGroupName(r.Context(), user.ID, name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	notes, err := s.store.ListNotesByGroupName(r.Context(), user.ID, name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "collection_detail.html", map[string]any{
		"Title":     "Group",
		"Kind":      "Group",
		"Name":      name,
		"Passwords": passwords,
		"Notes":     notes,
	})
}

func (s *Server) handleTagDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	passwords, err := s.store.ListPasswordsByTagName(r.Context(), user.ID, name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	notes, err := s.store.ListNotesByTagName(r.Context(), user.ID, name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "collection_detail.html", map[string]any{
		"Title":     "Tag",
		"Kind":      "Tag",
		"Name":      name,
		"Passwords": passwords,
		"Notes":     notes,
	})
}

type adminBackup struct {
	Version   int                    `json:"version"`
	CreatedAt time.Time              `json:"created_at"`
	Passwords []models.PasswordEntry `json:"passwords"`
	Notes     []models.SecureNote    `json:"notes"`
}

type adminControllerLinkView struct {
	SlaveServerID   string
	SlaveEndpoint   string
	Status          string
	LastHandshakeAt time.Time
	Health          string
}

type adminControllerRegistryView struct {
	ControllerID   string
	Status         string
	TokenUpdatedAt string
	LastSeenAt     string
	CreatedAt      string
	UpdatedAt      string
}

func formatAdminTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	return ts.Format("2006-01-02 15:04:05")
}

func (s *Server) adminPageData(ctx context.Context, message string) (map[string]any, error) {
	data := map[string]any{
		"Title":                 "Admin",
		"ServiceRestartEnabled": isUIServiceRestartEnabled(),
	}
	if message != "" {
		data["Message"] = message
	}
	if profile, err := s.store.GetServerProfile(ctx); err == nil {
		data["AdminServerProfile"] = profile
		if profile.ServerMode == "AS-M" {
			if links, err := s.store.ListControllerLinks(ctx); err == nil {
				now := time.Now()
				var viewLinks []adminControllerLinkView
				for _, link := range links {
					health := "active"
					if link.Status != "active" {
						health = "offline"
					} else {
						age := now.Sub(link.LastHandshakeAt)
						if age > 5*time.Minute {
							health = "offline"
						} else if age > 90*time.Second {
							health = "stale"
						}
					}
					viewLinks = append(viewLinks, adminControllerLinkView{
						SlaveServerID:   link.SlaveServerID,
						SlaveEndpoint:   link.SlaveEndpoint,
						Status:          link.Status,
						LastHandshakeAt: link.LastHandshakeAt,
						Health:          health,
					})
				}
				data["ControllerLinks"] = viewLinks
			}
			if registry, err := s.store.ListControllerRegistry(ctx); err == nil {
				var viewRegistry []adminControllerRegistryView
				for _, entry := range registry {
					viewRegistry = append(viewRegistry, adminControllerRegistryView{
						ControllerID:   entry.ControllerID,
						Status:         entry.Status,
						TokenUpdatedAt: formatAdminTimestamp(entry.TokenUpdatedAt),
						LastSeenAt:     formatAdminTimestamp(entry.LastSeenAt),
						CreatedAt:      formatAdminTimestamp(entry.CreatedAt),
						UpdatedAt:      formatAdminTimestamp(entry.UpdatedAt),
					})
				}
				data["ControllerRegistry"] = viewRegistry
			}
		}
		if profile.ServerMode == "AS-S" {
			if events, err := s.store.ListControllerUpdateEvents(ctx, 50); err == nil {
				latestByVersion := make(map[int64]models.ControllerUpdateEvent)
				for _, e := range events {
					cur, ok := latestByVersion[e.VaultVersion]
					if !ok || e.CreatedAt.After(cur.CreatedAt) {
						latestByVersion[e.VaultVersion] = e
					}
				}
				filtered := make([]models.ControllerUpdateEvent, 0, len(latestByVersion))
				for _, e := range latestByVersion {
					filtered = append(filtered, e)
				}
				sort.Slice(filtered, func(i, j int) bool {
					if filtered[i].VaultVersion == filtered[j].VaultVersion {
						return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
					}
					return filtered[i].VaultVersion > filtered[j].VaultVersion
				})
				data["ControllerUpdateEvents"] = filtered
				data["ControllerUpdateEventsRaw"] = events
				data["ControllerUpdateEventsRawCount"] = len(events)
				data["ControllerUpdateEventsLatestCount"] = len(filtered)
			}
		}
	}
	return data, nil
}

func (s *Server) renderAdminPage(w http.ResponseWriter, r *http.Request, message string) {
	data, err := s.adminPageData(r.Context(), message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "admin.html", data)
}

func (s *Server) renderAdminUsersCreatePage(w http.ResponseWriter, r *http.Request, message string) {
	data := map[string]any{
		"Title": "Admin - Users - Create",
	}
	if message != "" {
		data["Message"] = message
	}
	s.renderWithUnlock(w, r, "admin_users_create.html", data)
}

func (s *Server) renderAdminUsersListPage(w http.ResponseWriter, r *http.Request, message string) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Title": "Admin - Users - List",
		"Users": users,
	}
	if message != "" {
		data["Message"] = message
	}
	s.renderWithUnlock(w, r, "admin_users_list.html", data)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.renderAdminPage(w, r, "")
}

func (s *Server) handleAdminUsersCreatePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.renderAdminUsersCreatePage(w, r, "")
}

func (s *Server) handleAdminUsersListPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.renderAdminUsersListPage(w, r, "")
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	loginPassword := r.FormValue("login_password")
	masterPassword := r.FormValue("master_password")
	if loginPassword == "" || masterPassword == "" {
		http.Error(w, "both passwords required", http.StatusBadRequest)
		return
	}
	if loginPassword == masterPassword {
		http.Error(w, "login and master passwords must differ", http.StatusBadRequest)
		return
	}
	loginHash, err := crypto.HashPassword(loginPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	masterHash, err := crypto.HashPassword(masterPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.CreateUser(r.Context(), models.User{
		Email:              email,
		Status:             "pending",
		PasswordHash:       loginHash,
		MasterPasswordHash: masterHash,
		IsAdmin:            false,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderAdminUsersCreatePage(w, r, "User created.")
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	targetID := r.FormValue("user_id")
	loginPassword := r.FormValue("login_password")
	masterPassword := r.FormValue("master_password")
	if targetID == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}
	if loginPassword == "" || masterPassword == "" {
		http.Error(w, "both passwords required", http.StatusBadRequest)
		return
	}
	if loginPassword == masterPassword {
		http.Error(w, "login and master passwords must differ", http.StatusBadRequest)
		return
	}
	loginHash, err := crypto.HashPassword(loginPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	masterHash, err := crypto.HashPassword(masterPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateUserCredentials(r.Context(), targetID, &loginHash, &masterHash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderAdminUsersListPage(w, r, "User updated.")
}

func (s *Server) handleAdminSetControllerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	controllerID := strings.TrimSpace(r.FormValue("controller_id"))
	status := strings.TrimSpace(r.FormValue("status"))
	if controllerID == "" || status == "" {
		http.Error(w, "controller_id and status are required", http.StatusBadRequest)
		return
	}
	if err := s.store.SetControllerRegistryStatus(r.Context(), controllerID, status); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if status == "active" {
		s.renderAdminPage(w, r, "Controller approved.")
		return
	}
	s.renderAdminPage(w, r, "Controller set to non-approved.")
}

func (s *Server) handleAdminCleanupControllerLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	removed, err := s.store.CleanupControllerLinkDuplicateEndpoints(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if removed == 0 {
		s.renderAdminPage(w, r, "Controller links cleanup complete. No duplicates found.")
		return
	}
	s.renderAdminPage(w, r, fmt.Sprintf("Controller links cleanup complete. Removed %d duplicate rows.", removed))
}

func (s *Server) handleAdminServiceRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !isUIServiceRestartEnabled() {
		http.Error(w, "service restart from UI is not enabled", http.StatusForbidden)
		return
	}
	parts, err := serviceRestartCommandParts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go func(args []string) {
		time.Sleep(serviceRestartTriggerDelay)
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("ui service restart failed: %v, output=%s", err, strings.TrimSpace(string(out)))
			return
		}
		log.Printf("ui service restart command executed: %s", strings.Join(args, " "))
	}(parts)
	s.renderAdminPage(w, r, "Service restart was requested.")
}

func (s *Server) handleAdminClearRecordTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	admin, ok := s.currentUser(r)
	if !ok || !admin.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	recordID := strings.TrimSpace(r.FormValue("record_id"))
	if recordID == "" {
		http.Error(w, "record id required", http.StatusBadRequest)
		return
	}
	affected, err := s.store.ClearTagsForRecord(r.Context(), recordID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.renderAdminPage(w, r, fmt.Sprintf("Cleared %d tag links for record %s.", affected, recordID))
}

func (s *Server) handleAdminClearRecordGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	admin, ok := s.currentUser(r)
	if !ok || !admin.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	recordID := strings.TrimSpace(r.FormValue("record_id"))
	if recordID == "" {
		http.Error(w, "record id required", http.StatusBadRequest)
		return
	}
	affected, err := s.store.ClearGroupsForRecord(r.Context(), recordID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.renderAdminPage(w, r, fmt.Sprintf("Cleared %d group links for record %s.", affected, recordID))
}

func (s *Server) handleAdminClearAllTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	admin, ok := s.currentUser(r)
	if !ok || !admin.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	affected, err := s.store.ClearAllTags(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderAdminPage(w, r, fmt.Sprintf("Cleared tags table. Removed %d tag rows.", affected))
}

func (s *Server) handleAdminClearAllGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	admin, ok := s.currentUser(r)
	if !ok || !admin.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	affected, err := s.store.ClearAllGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderAdminPage(w, r, fmt.Sprintf("Cleared groups table. Removed %d group rows.", affected))
}

func (s *Server) handleAdminBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	pwIDs, err := s.store.ListPasswordIDs(ctx, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var passwords []models.PasswordEntry
	for _, id := range pwIDs {
		entry, err := s.store.GetPassword(ctx, s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		passwords = append(passwords, entry)
	}
	noteIDs, err := s.store.ListNoteIDs(ctx, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var notes []models.SecureNote
	for _, id := range noteIDs {
		note, err := s.store.GetNote(ctx, s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		notes = append(notes, note)
	}
	backup := adminBackup{
		Version:   1,
		CreatedAt: time.Now(),
		Passwords: passwords,
		Notes:     notes,
	}
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("password-manager-backup-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Write(data)
}

func (s *Server) handleAdminRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	var backup adminBackup
	if err := json.NewDecoder(file).Decode(&backup); err != nil {
		http.Error(w, "invalid backup file", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	for _, entry := range backup.Passwords {
		entry.UserID = user.ID
		if err := s.store.UpsertPassword(ctx, s.crypto, entry); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	for _, note := range backup.Notes {
		note.UserID = user.ID
		if err := s.store.InsertSecureNote(ctx, s.crypto, note); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.renderAdminPage(w, r, fmt.Sprintf("Restored %d passwords and %d notes.", len(backup.Passwords), len(backup.Notes)))
}

func (s *Server) handleAdminRebuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isUnlocked(r) {
		http.Error(w, "unlock required", http.StatusUnauthorized)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	pwIDs, err := s.store.ListPasswordIDs(ctx, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	noteIDs, err := s.store.ListNoteIDs(ctx, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rebuilt := 0
	for _, id := range pwIDs {
		entry, err := s.store.GetPassword(ctx, s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if entry.ImportRaw == "" || entry.ImportSource != "1pif" {
			continue
		}
		updated, err := importer.RebuildFromRaw(ctx, s.store, s.crypto, entry.ImportRaw, user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if updated {
			rebuilt++
		}
	}
	for _, id := range noteIDs {
		note, err := s.store.GetNote(ctx, s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if note.ImportRaw == "" || note.ImportSource != "1pif" {
			continue
		}
		updated, err := importer.RebuildFromRaw(ctx, s.store, s.crypto, note.ImportRaw, user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if updated {
			rebuilt++
		}
	}
	s.renderAdminPage(w, r, fmt.Sprintf("Rebuilt %d items from import_raw.", rebuilt))
}

func (s *Server) handleImport1Password(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		user, ok := s.currentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		history, _ := s.store.ListImportRuns(r.Context(), user.ID, 20)
		s.renderWithUnlock(w, r, "import.html", map[string]any{
			"Title":   "Import from 1Password (.1pif)",
			"History": history,
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	runID := ""
	runID = uuid.New().String()
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	result, err := importer.ImportPIF(ctx, file, s.store, s.crypto, runID, user.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("import failed: %v", err), http.StatusBadRequest)
		return
	}
	run := models.ImportRun{
		ID:                runID,
		UserID:            user.ID,
		Filename:          header.Filename,
		FileSize:          header.Size,
		ImportedPasswords: result.Passwords,
		ImportedNotes:     result.Notes,
		ExistingCount:     result.Existing,
		NewCount:          result.New,
		SkippedCount:      result.Skipped,
	}
	_ = s.store.InsertImportRun(ctx, run)
	history, _ := s.store.ListImportRuns(r.Context(), user.ID, 20)
	s.renderWithUnlock(w, r, "import.html", map[string]any{
		"Title":   "Import from 1Password (.1pif)",
		"Message": fmt.Sprintf("Imported %d passwords, %d notes. Existing %d, new %d. Skipped %d items.", result.Passwords, result.Notes, result.Existing, result.New, result.Skipped),
		"History": history,
	})
}

func (s *Server) handleImportIssues(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	issues, err := s.store.ListImportIssues(r.Context(), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "import_issues.html", map[string]any{
		"Title":  "Import Issues",
		"Issues": issues,
	})
}

func (s *Server) render(w http.ResponseWriter, page string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if data == nil {
		data = map[string]any{}
	}
	tpl, err := template.ParseFiles(
		filepath.Join(s.templateDir, "layout.html"),
		filepath.Join(s.templateDir, page),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) renderWithUnlock(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Unlocked"] = s.isUnlocked(r)
	data["UnlockSeconds"] = s.unlockRemainingSeconds(r)
	data["RequestPath"] = r.URL.Path
	if profile, err := s.store.GetServerProfile(r.Context()); err == nil {
		data["ServerMode"] = profile.ServerMode
		switch profile.ServerMode {
		case "AS-M":
			data["ServerModeCode"] = "M"
			data["ServerModeClass"] = "text-bg-success"
		case "AS-S":
			data["ServerModeCode"] = "S"
			data["ServerModeClass"] = "text-bg-warning"
		}
	}
	if user, ok := s.currentUser(r); ok {
		data["CurrentUserEmail"] = user.Email
		data["IsAdmin"] = user.IsAdmin
	}
	s.render(w, page, data)
}

func (s *Server) handleUnlockPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.renderWithUnlock(w, r, "unlock.html", map[string]any{
		"Title": "Unlock",
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/controller/") || path == "/login" || path == "/setup" || path == "/auth/biometric-token" || path == "/share/password" {
			next.ServeHTTP(w, r)
			return
		}
		user, ok := s.loadUserFromSession(r)
		if !ok {
			count, err := s.store.CountUsers(r.Context())
			if err == nil && count == 0 {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) loadUserFromSession(r *http.Request) (models.User, bool) {
	c, err := r.Cookie("pm_session")
	if err != nil || c.Value == "" {
		return models.User{}, false
	}
	sess, err := s.store.GetSession(r.Context(), c.Value)
	if err != nil {
		return models.User{}, false
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.store.DeleteSession(r.Context(), sess.ID)
		return models.User{}, false
	}
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		return models.User{}, false
	}
	return user, true
}

func (s *Server) currentUser(r *http.Request) (models.User, bool) {
	user, ok := r.Context().Value(userCtxKey).(models.User)
	return user, ok
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "pm_unlock",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func splitComma(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	var out []string
	for _, p := range parts {
		trim := strings.TrimSpace(p)
		if trim == "" {
			continue
		}
		out = append(out, trim)
	}
	return out
}

func (s *Server) readUISettings(r *http.Request) uiSettings {
	settings := uiSettings{
		PageSize:      defaultPageSize,
		UnlockMinutes: defaultUnlockMinutes,
		Firewall:      false,
		APIKey:        "",
	}
	if c, err := r.Cookie("pm_page_size"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(c.Value)); err == nil && v >= 5 && v <= 200 {
			settings.PageSize = v
		}
	}
	if c, err := r.Cookie("pm_unlock_minutes"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(c.Value)); err == nil && v >= 1 && v <= 120 {
			settings.UnlockMinutes = v
		}
	}
	if c, err := r.Cookie("pm_firewall_enabled"); err == nil {
		settings.Firewall = strings.TrimSpace(strings.ToLower(c.Value)) == "1" || strings.TrimSpace(strings.ToLower(c.Value)) == "true"
	}
	if c, err := r.Cookie("pm_api_key"); err == nil {
		settings.APIKey = c.Value
	}
	return settings
}

func (s *Server) writeUISettings(w http.ResponseWriter, r *http.Request, settings uiSettings) {
	if settings.PageSize < 5 {
		settings.PageSize = 5
	}
	if settings.PageSize > 200 {
		settings.PageSize = 200
	}
	if settings.UnlockMinutes < 1 {
		settings.UnlockMinutes = 1
	}
	if settings.UnlockMinutes > 120 {
		settings.UnlockMinutes = 120
	}
	oneYear := int((365 * 24 * time.Hour).Seconds())
	http.SetCookie(w, &http.Cookie{
		Name:     "pm_page_size",
		Value:    strconv.Itoa(settings.PageSize),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
		MaxAge:   oneYear,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "pm_unlock_minutes",
		Value:    strconv.Itoa(settings.UnlockMinutes),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
		MaxAge:   oneYear,
	})
	firewall := "0"
	if settings.Firewall {
		firewall = "1"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "pm_firewall_enabled",
		Value:    firewall,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
		MaxAge:   oneYear,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "pm_api_key",
		Value:    settings.APIKey,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
		MaxAge:   oneYear,
	})
}

func parsePage(r *http.Request, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get("page"))
	if raw == "" {
		return fallback
	}
	page, err := strconv.Atoi(raw)
	if err != nil || page < 1 {
		return fallback
	}
	return page
}

func parseFieldSearch(r *http.Request, defaultField string) (string, string) {
	field := strings.TrimSpace(r.URL.Query().Get("field"))
	if field == "" {
		field = defaultField
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	return strings.ToLower(field), q
}

func paginateWindow(total int, page int, pageSize int) (start int, end int, pager map[string]any) {
	if pageSize <= 0 {
		pageSize = 10
	}
	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	if page > totalPages {
		page = totalPages
	}
	if page < 1 {
		page = 1
	}
	start = (page - 1) * pageSize
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end = start + pageSize
	if end > total {
		end = total
	}
	pager = map[string]any{
		"Page":       page,
		"PageSize":   pageSize,
		"TotalItems": total,
		"TotalPages": totalPages,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
	}
	return start, end, pager
}

func buildPageURL(path string, field string, q string, page int) string {
	values := url.Values{}
	values.Set("page", strconv.Itoa(page))
	if strings.TrimSpace(field) != "" {
		values.Set("field", field)
	}
	if strings.TrimSpace(q) != "" {
		values.Set("q", q)
	}
	return path + "?" + values.Encode()
}

func containsFold(haystack string, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func filterPasswordRows(items []map[string]string, field string, q string) []map[string]string {
	if strings.TrimSpace(q) == "" {
		return items
	}
	var out []map[string]string
	for _, item := range items {
		status := "shared"
		if item["CanManage"] == "true" {
			status = "owned"
		}
		var match bool
		switch field {
		case "title":
			match = containsFold(item["Title"], q)
		case "username":
			match = containsFold(item["Username"], q)
		case "tags":
			match = containsFold(item["Tags"], q)
		case "groups":
			match = containsFold(item["Groups"], q)
		case "shared":
			match = containsFold(item["SharedLabel"], q)
		case "status":
			match = containsFold(status, q)
		default:
			match = containsFold(item["Title"], q) ||
				containsFold(item["Username"], q) ||
				containsFold(item["Tags"], q) ||
				containsFold(item["Groups"], q) ||
				containsFold(item["SharedLabel"], q) ||
				containsFold(status, q)
		}
		if match {
			out = append(out, item)
		}
	}
	return out
}

func filterNoteRows(items []map[string]string, field string, q string) []map[string]string {
	if strings.TrimSpace(q) == "" {
		return items
	}
	var out []map[string]string
	for _, item := range items {
		status := "shared"
		if item["CanManage"] == "true" {
			status = "owned"
		}
		var match bool
		switch field {
		case "title":
			match = containsFold(item["Title"], q)
		case "tags":
			match = containsFold(item["Tags"], q)
		case "groups":
			match = containsFold(item["Groups"], q)
		case "updated":
			match = containsFold(item["Updated"], q)
		case "shared":
			match = containsFold(item["SharedLabel"], q)
		case "status":
			match = containsFold(status, q)
		default:
			match = containsFold(item["Title"], q) ||
				containsFold(item["Tags"], q) ||
				containsFold(item["Groups"], q) ||
				containsFold(item["Updated"], q) ||
				containsFold(item["SharedLabel"], q) ||
				containsFold(status, q)
		}
		if match {
			out = append(out, item)
		}
	}
	return out
}

func filterCollectionRows(items []map[string]any, field string, q string) []map[string]any {
	if strings.TrimSpace(q) == "" {
		return items
	}
	var out []map[string]any
	for _, item := range items {
		name := fmt.Sprint(item["Name"])
		count := fmt.Sprint(item["Count"])
		var match bool
		switch field {
		case "count":
			match = containsFold(count, q)
		default:
			match = containsFold(name, q) || containsFold(count, q)
		}
		if match {
			out = append(out, item)
		}
	}
	return out
}

func urlQueryEscape(value string) string {
	return url.QueryEscape(value)
}

func (s *Server) isUnlocked(r *http.Request) bool {
	c, err := r.Cookie("pm_unlock")
	if err != nil {
		return false
	}
	user, ok := s.currentUser(r)
	if !ok {
		return false
	}
	return s.unlock.Valid(c.Value, user.ID)
}

func (s *Server) unlockRemainingSeconds(r *http.Request) int {
	c, err := r.Cookie("pm_unlock")
	if err != nil {
		return 0
	}
	user, ok := s.currentUser(r)
	if !ok {
		return 0
	}
	return s.unlock.RemainingSeconds(c.Value, user.ID)
}

type unlockManager struct {
	mu      sync.Mutex
	tokens  map[string]unlockToken
	preauth map[string]time.Time
}

type unlockToken struct {
	UserID    string
	ExpiresAt time.Time
}

func newUnlockManager() *unlockManager {
	return &unlockManager{
		tokens:  make(map[string]unlockToken),
		preauth: make(map[string]time.Time),
	}
}

func (u *unlockManager) Issue(userID string, ttl time.Duration) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	u.tokens[token] = unlockToken{
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttl),
	}
	return token, nil
}

func (u *unlockManager) Valid(token string, userID string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	entry, ok := u.tokens[token]
	if !ok {
		return false
	}
	if entry.UserID != userID {
		return false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(u.tokens, token)
		return false
	}
	return true
}

func (u *unlockManager) RemainingSeconds(token string, userID string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	entry, ok := u.tokens[token]
	if !ok {
		return 0
	}
	if entry.UserID != userID {
		return 0
	}
	rem := int(time.Until(entry.ExpiresAt).Seconds())
	if rem < 0 {
		return 0
	}
	return rem
}

func (u *unlockManager) IssuePreauth(ttl time.Duration) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	u.preauth[token] = time.Now().Add(ttl)
	return token, nil
}

func (u *unlockManager) ConsumePreauth(token string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	exp, ok := u.preauth[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(u.preauth, token)
		return false
	}
	delete(u.preauth, token)
	return true
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
