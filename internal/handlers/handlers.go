package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	defaultPageSize               = 10
	defaultUnlockMinutes          = 5
	defaultAppVersion             = "4.0.9"
	defaultBuildAuthor            = "unknown"
	defaultBuildLastUpdate        = "unknown"
	controllerHealthcheckInterval = 30 * time.Second
	controllerHealthcheckTimeout  = 5 * time.Second
	serviceRestartTriggerDelay    = 500 * time.Millisecond
	requestLogCapacity            = 500
	requestLogAdminLimit          = 20
	loginBlockThreshold           = 3
	loginBlockMaxMinutes          = 15
	adminProbeBlockMinutes        = 5
	trustedAdminSubnetCIDR        = "10.8.0.0/24"
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
	MasterServerID  string                    `json:"master_server_id"`
	MasterURL       string                    `json:"master_url"`
	SnapshotVersion int64                     `json:"snapshot_version"`
	PayloadHash     string                    `json:"payload_hash"`
	Snapshot        controllerSnapshotPayload `json:"snapshot"`
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

type controllerEncryptedSyncBundle struct {
	BundleID      string `json:"bundle_id"`
	UserID        string `json:"user_id"`
	UserEmail     string `json:"user_email"`
	BundleType    string `json:"bundle_type"`
	PayloadHash   string `json:"payload_hash"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

type controllerSyncBundlesApplyRequest struct {
	MasterServerID string                        `json:"master_server_id"`
	MasterURL      string                        `json:"master_url"`
	UserID         string                        `json:"user_id"`
	Bundle         controllerEncryptedSyncBundle `json:"bundle"`
}

type controllerSyncBundleExportRequest struct {
	UserID string `json:"user_id"`
}

type controllerSnapshotUser struct {
	ID                 string    `json:"id"`
	Email              string    `json:"email"`
	Status             string    `json:"status"`
	PasswordHash       string    `json:"password_hash"`
	MasterPasswordHash string    `json:"master_password_hash"`
	IsAdmin            bool      `json:"is_admin"`
	CreatedAt          time.Time `json:"created_at"`
}

type controllerSnapshotShare struct {
	ItemID      string `json:"item_id"`
	TargetEmail string `json:"target_email"`
}

type controllerSnapshotPayload struct {
	Version        int64                     `json:"version"`
	CreatedAt      time.Time                 `json:"created_at"`
	Users          []controllerSnapshotUser  `json:"users"`
	Passwords      []models.PasswordEntry    `json:"passwords"`
	Notes          []models.SecureNote       `json:"notes"`
	PasswordShares []controllerSnapshotShare `json:"password_shares"`
	NoteShares     []controllerSnapshotShare `json:"note_shares"`
}

type controllerSyncUserBundle struct {
	Version        int64                     `json:"version"`
	CreatedAt      time.Time                 `json:"created_at"`
	UserID         string                    `json:"user_id"`
	UserEmail      string                    `json:"user_email"`
	Passwords      []models.PasswordEntry    `json:"passwords"`
	Notes          []models.SecureNote       `json:"notes"`
	PasswordShares []controllerSnapshotShare `json:"password_shares"`
	NoteShares     []controllerSnapshotShare `json:"note_shares"`
}

type pendingSyncBundlePreview struct {
	BundleID            string
	MasterServerID      string
	MasterServerURL     string
	CreatedAt           time.Time
	UserID              string
	UserEmail           string
	PasswordsCount      int
	NotesCount          int
	PasswordSharesCount int
	NoteSharesCount     int
	PasswordTitles      []string
	NoteTitles          []string
}

type controllerBootstrapAuthRequest struct {
	ControllerID string `json:"controller_id"`
	MasterKey    string `json:"master_key"`
}

type controllerRotateAuthRequest struct {
	ControllerID string `json:"controller_id"`
}

type controllerSlaveGrantRequest struct {
	SlaveEndpoint string `json:"slave_endpoint"`
}

type controllerSlaveGrantVerifyRequest struct {
	GrantToken string `json:"grant_token"`
}

type controllerAuthTokenResponse struct {
	NextToken string `json:"next_token,omitempty"`
	Status    string `json:"status"`
	Approved  bool   `json:"approved"`
}

type buildMetadata struct {
	Version    string `json:"version"`
	Author     string `json:"author"`
	LastUpdate string `json:"last_update"`
	RepoURL    string `json:"repo_url"`
}

type breadcrumbItem struct {
	Label  string
	Href   string
	Active bool
}

type Server struct {
	templateDir          string
	store                *db.Store
	crypto               *crypto.Service
	unlock               *unlockManager
	controllerHTTPClient *http.Client
	requestLogMu         sync.Mutex
	requestLogs          []requestLogEntry
	loginGuardMu         sync.Mutex
	loginGuardByIP       map[string]loginGuardState
	adminProbeMu         sync.Mutex
	adminProbeBlockedIPs map[string]time.Time
}

type requestLogEntry struct {
	At         time.Time
	Method     string
	Path       string
	RemoteIP   string
	StatusCode int
	DurationMS int64
}

type adminGuardBlockedIPView struct {
	IP           string
	BlockedUntil string
	BlockedFor   string
}

type requestLogStatusRecorder struct {
	http.ResponseWriter
	statusCode int
}

type loginGuardState struct {
	Failures     int
	BlockedUntil time.Time
	LastSeen     time.Time
}

func (r *requestLogStatusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
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
		requestLogs:          make([]requestLogEntry, 0, requestLogCapacity),
		loginGuardByIP:       make(map[string]loginGuardState),
		adminProbeBlockedIPs: make(map[string]time.Time),
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
	mux.HandleFunc("/controller/auth/slave-grant", s.handleControllerAuthSlaveGrant)
	mux.HandleFunc("/controller/auth/verify-slave-grant", s.handleControllerAuthVerifySlaveGrant)
	mux.HandleFunc("/controller/controllers", s.handleControllerListControllers)
	mux.HandleFunc("/controller/health", s.handleControllerHealth)
	mux.HandleFunc("/controller/pair", s.handleControllerPair)
	mux.HandleFunc("/controller/links/status", s.handleControllerLinksStatus)
	mux.HandleFunc("/controller/snapshot/export", s.handleControllerSnapshotExport)
	mux.HandleFunc("/controller/snapshot/apply", s.handleControllerSnapshotApply)
	mux.HandleFunc("/controller/sync-bundles/export", s.handleControllerSyncBundlesExport)
	mux.HandleFunc("/controller/sync-bundles/apply", s.handleControllerSyncBundlesApply)
	mux.HandleFunc("/controller/update/apply", s.handleControllerUpdateApply)
	mux.HandleFunc("/controller/update/ack", s.handleControllerUpdateAck)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/passwords", s.handlePasswords)
	mux.HandleFunc("/passwords/new", s.handlePasswordForm)
	mux.HandleFunc("/passwords/edit", s.handlePasswordEdit)
	mux.HandleFunc("/passwords/update-password", s.handlePasswordUpdatePassword)
	mux.HandleFunc("/passwords/update-title", s.handlePasswordUpdateTitle)
	mux.HandleFunc("/passwords/update-collections", s.handlePasswordUpdateCollections)
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
	mux.HandleFunc("/messages", s.handleMessagesPage)
	mux.HandleFunc("/messages/send", s.handleMessageSend)
	mux.HandleFunc("/messages/read", s.handleMessageRead)
	mux.HandleFunc("/sync/pending/review", s.handlePendingSyncReview)
	mux.HandleFunc("/sync/pending/confirm", s.handlePendingSyncConfirm)
	mux.HandleFunc("/groups", s.handleGroups)
	mux.HandleFunc("/groups/edit", s.handleGroupEdit)
	mux.HandleFunc("/groups/remove", s.handleGroupRemove)
	mux.HandleFunc("/groups/view", s.handleGroupDetail)
	mux.HandleFunc("/tags", s.handleTags)
	mux.HandleFunc("/tags/edit", s.handleTagEdit)
	mux.HandleFunc("/tags/remove", s.handleTagRemove)
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
	mux.HandleFunc("/admin/about", s.handleAdminAboutPage)
	mux.HandleFunc("/admin/guard", s.handleAdminGuardPage)
	mux.HandleFunc("/admin/guard/block", s.handleAdminGuardBlock)
	mux.HandleFunc("/admin/guard/unblock", s.handleAdminGuardUnblock)
	mux.HandleFunc("/admin/users/update", s.handleAdminUpdateUser)
	mux.HandleFunc("/admin/users/role", s.handleAdminUpdateUserRole)
	mux.HandleFunc("/admin/controllers/status", s.handleAdminSetControllerStatus)
	mux.HandleFunc("/admin/controllers/weight", s.handleAdminSetControllerWeight)
	mux.HandleFunc("/admin/controllers/cleanup-stale", s.handleAdminCleanupStaleControllers)
	mux.HandleFunc("/admin/controller-links/cleanup", s.handleAdminCleanupControllerLinks)
	mux.HandleFunc("/admin/request-logs", s.handleAdminRequestLogs)
	mux.HandleFunc("/admin/controller-links/status", s.handleAdminControllerLinksStatus)
	mux.HandleFunc("/admin/service/restart", s.handleAdminServiceRestart)
	mux.HandleFunc("/admin/records/clear-tags", s.handleAdminClearRecordTags)
	mux.HandleFunc("/admin/records/clear-groups", s.handleAdminClearRecordGroups)
	mux.HandleFunc("/admin/tags/clear-all", s.handleAdminClearAllTags)
	mux.HandleFunc("/admin/groups/clear-all", s.handleAdminClearAllGroups)
	return s.requestLogMiddleware(s.authMiddleware(mux))
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
		clientIP := clientIPFromRequest(r)
		if blockedFor := s.loginBlockedFor(clientIP); blockedFor > 0 {
			s.renderWithUnlock(w, r, "login.html", map[string]any{
				"Title": "Login",
				"Error": "you are wrong, don't repeat it",
			})
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		user, err := s.store.GetUserByEmail(r.Context(), email)
		if err != nil || !crypto.VerifyPassword(password, user.PasswordHash) {
			blockedFor := s.recordLoginFailure(clientIP)
			errMsg := "Invalid credentials"
			if blockedFor > 0 {
				errMsg = "you are wrong, don't repeat it"
			}
			s.renderWithUnlock(w, r, "login.html", map[string]any{
				"Title": "Login",
				"Error": errMsg,
			})
			return
		}
		s.clearLoginFailures(clientIP)
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
			"Title":      "Create Admin",
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
		if err := s.ensureUserSyncKey(r.Context(), adminID, masterPassword); err != nil {
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

func (s *Server) authorizeRotatingController(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	token := bearerTokenFromRequest(r)
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return "", "", false
	}
	nextToken, err := randomToken()
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return "", "", false
	}
	controllerID, err := s.store.RotateControllerTokenByHash(r.Context(), hashControllerToken(token), hashControllerToken(nextToken))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return "", "", false
	}
	return controllerID, nextToken, true
}

func (s *Server) verifyControllerSlaveGrant(ctx context.Context, masterBaseURL string, grantToken string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(masterBaseURL), "/")
	grantToken = strings.TrimSpace(grantToken)
	if base == "" {
		return "", errors.New("master URL is not configured")
	}
	if grantToken == "" {
		return "", errors.New("missing controller grant")
	}
	body, err := json.Marshal(controllerSlaveGrantVerifyRequest{GrantToken: grantToken})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/controller/auth/verify-slave-grant", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.controllerHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("controller grant verification failed: %s", strings.TrimSpace(string(msg)))
	}
	var payload struct {
		ControllerID string `json:"controller_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.ControllerID) == "" {
		return "", errors.New("controller grant verification returned empty controller_id")
	}
	return strings.TrimSpace(payload.ControllerID), nil
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
	var controllers []map[string]any
	for _, entry := range registry {
		controllers = append(controllers, map[string]any{
			"id":     entry.ControllerID,
			"name":   entry.ControllerID,
			"status": entry.Status,
			"weight": entry.Weight,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"controllers": controllers,
		"next_token":  nextToken,
	})
}

func (s *Server) handleControllerAuthSlaveGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	controllerID, nextToken, ok := s.authorizeRotatingController(w, r)
	if !ok {
		return
	}
	var req controllerSlaveGrantRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	req.SlaveEndpoint = strings.TrimSpace(req.SlaveEndpoint)
	if req.SlaveEndpoint == "" {
		http.Error(w, "slave_endpoint is required", http.StatusBadRequest)
		return
	}
	grantToken, err := randomToken()
	if err != nil {
		http.Error(w, "failed to issue slave grant", http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().UTC().Add(30 * time.Second)
	if err := s.store.IssueControllerSlaveGrant(r.Context(), controllerID, req.SlaveEndpoint, hashControllerToken(grantToken), expiresAt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "grant_issued",
		"controller_id":  controllerID,
		"slave_endpoint": req.SlaveEndpoint,
		"grant_token":    grantToken,
		"expires_at":     expiresAt.Format(time.RFC3339),
		"next_token":     nextToken,
	})
}

func (s *Server) handleControllerAuthVerifySlaveGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req controllerSlaveGrantVerifyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	req.GrantToken = strings.TrimSpace(req.GrantToken)
	if req.GrantToken == "" {
		http.Error(w, "grant_token is required", http.StatusBadRequest)
		return
	}
	controllerID, slaveEndpoint, expiresAt, err := s.store.ConsumeControllerSlaveGrant(r.Context(), hashControllerToken(req.GrantToken))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "approved",
		"controller_id":  controllerID,
		"slave_endpoint": slaveEndpoint,
		"expires_at":     expiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleControllerHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	controllerID, nextToken, ok := s.authorizeRotatingController(w, r)
	if !ok {
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
		"controller_id":   controllerID,
		"next_token":      nextToken,
	})
}

func (s *Server) handleControllerLinksStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-M" {
		http.Error(w, "link status is allowed only on AS-M", http.StatusConflict)
		return
	}
	links, err := s.store.ListControllerLinks(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	active := 0
	stale := 0
	offline := 0
	latestHandshakeAt := time.Time{}
	for _, link := range links {
		health := classifyControllerLinkHealth(link.Status, link.LastHandshakeAt, now)
		switch health {
		case "active":
			active++
		case "stale":
			stale++
		default:
			offline++
		}
		if link.LastHandshakeAt.After(latestHandshakeAt) {
			latestHandshakeAt = link.LastHandshakeAt
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"master_mode": profile.ServerMode,
		"summary": map[string]any{
			"total_links":         len(links),
			"active_links":        active,
			"stale_links":         stale,
			"offline_links":       offline,
			"latest_handshake_at": formatAdminTimestamp(latestHandshakeAt),
		},
		"checked_at": now.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleAdminControllerLinksStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-M" {
		http.Error(w, "link status is allowed only on AS-M", http.StatusConflict)
		return
	}
	links, err := s.store.ListControllerLinks(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	type row struct {
		SlaveServerID   string `json:"slave_server_id"`
		SlaveEndpoint   string `json:"slave_endpoint"`
		Status          string `json:"status"`
		Health          string `json:"health"`
		LastHandshakeAt string `json:"last_handshake_at"`
	}
	rows := make([]row, 0, len(links))
	for _, link := range links {
		rows = append(rows, row{
			SlaveServerID:   link.SlaveServerID,
			SlaveEndpoint:   link.SlaveEndpoint,
			Status:          link.Status,
			Health:          classifyControllerLinkHealth(link.Status, link.LastHandshakeAt, now),
			LastHandshakeAt: formatAdminTimestamp(link.LastHandshakeAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"master_mode": profile.ServerMode,
		"links":       rows,
		"checked_at":  now.UTC().Format(time.RFC3339),
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

func snapshotHash(payload controllerSnapshotPayload) (string, error) {
	serialized, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(serialized)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Server) buildControllerSnapshot(ctx context.Context) (controllerSnapshotPayload, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return controllerSnapshotPayload{}, err
	}
	snapshot := controllerSnapshotPayload{
		Version:        time.Now().UTC().Unix(),
		CreatedAt:      time.Now().UTC(),
		Users:          make([]controllerSnapshotUser, 0, len(users)),
		Passwords:      []models.PasswordEntry{},
		Notes:          []models.SecureNote{},
		PasswordShares: []controllerSnapshotShare{},
		NoteShares:     []controllerSnapshotShare{},
	}
	for _, user := range users {
		fullUser, err := s.store.GetUserByID(ctx, user.ID)
		if err != nil {
			return controllerSnapshotPayload{}, err
		}
		snapshot.Users = append(snapshot.Users, controllerSnapshotUser{
			ID:                 fullUser.ID,
			Email:              fullUser.Email,
			Status:             fullUser.Status,
			PasswordHash:       fullUser.PasswordHash,
			MasterPasswordHash: fullUser.MasterPasswordHash,
			IsAdmin:            fullUser.IsAdmin,
			CreatedAt:          fullUser.CreatedAt,
		})
		pwIDs, err := s.store.ListPasswordIDs(ctx, fullUser.ID)
		if err != nil {
			return controllerSnapshotPayload{}, err
		}
		for _, id := range pwIDs {
			entry, err := s.store.GetPassword(ctx, s.crypto, id, fullUser.ID)
			if err != nil {
				return controllerSnapshotPayload{}, err
			}
			snapshot.Passwords = append(snapshot.Passwords, entry)
			shareEmails, err := s.store.ListPasswordShareEmails(ctx, entry.ID)
			if err != nil {
				return controllerSnapshotPayload{}, err
			}
			for _, email := range shareEmails {
				snapshot.PasswordShares = append(snapshot.PasswordShares, controllerSnapshotShare{
					ItemID:      entry.ID,
					TargetEmail: strings.TrimSpace(email),
				})
			}
		}
		noteIDs, err := s.store.ListNoteIDs(ctx, fullUser.ID)
		if err != nil {
			return controllerSnapshotPayload{}, err
		}
		for _, id := range noteIDs {
			note, err := s.store.GetNote(ctx, s.crypto, id, fullUser.ID)
			if err != nil {
				return controllerSnapshotPayload{}, err
			}
			snapshot.Notes = append(snapshot.Notes, note)
			shareEmails, err := s.store.ListNoteShareEmails(ctx, note.ID)
			if err != nil {
				return controllerSnapshotPayload{}, err
			}
			for _, email := range shareEmails {
				snapshot.NoteShares = append(snapshot.NoteShares, controllerSnapshotShare{
					ItemID:      note.ID,
					TargetEmail: strings.TrimSpace(email),
				})
			}
		}
	}
	return snapshot, nil
}

func (s *Server) applyControllerSnapshot(ctx context.Context, snapshot controllerSnapshotPayload) (map[string]int, error) {
	applied := map[string]int{
		"users":           0,
		"passwords":       0,
		"notes":           0,
		"password_shares": 0,
		"note_shares":     0,
	}
	userIDMap := make(map[string]string, len(snapshot.Users))
	for _, user := range snapshot.Users {
		targetUserID := user.ID
		if existing, err := s.store.GetUserByEmail(ctx, strings.TrimSpace(user.Email)); err == nil {
			targetUserID = existing.ID
		}
		if err := s.store.UpsertUserReplica(ctx, models.User{
			ID:                 targetUserID,
			Email:              user.Email,
			Status:             user.Status,
			PasswordHash:       user.PasswordHash,
			MasterPasswordHash: user.MasterPasswordHash,
			IsAdmin:            user.IsAdmin,
		}); err != nil {
			return nil, err
		}
		userIDMap[user.ID] = targetUserID
		applied["users"]++
	}
	for _, entry := range snapshot.Passwords {
		if mappedID, ok := userIDMap[entry.UserID]; ok {
			entry.UserID = mappedID
		}
		if err := s.store.UpsertPassword(ctx, s.crypto, entry); err != nil {
			return nil, err
		}
		applied["passwords"]++
	}
	for _, note := range snapshot.Notes {
		if mappedID, ok := userIDMap[note.UserID]; ok {
			note.UserID = mappedID
		}
		if err := s.store.InsertSecureNote(ctx, s.crypto, note); err != nil {
			return nil, err
		}
		applied["notes"]++
	}
	for _, share := range snapshot.PasswordShares {
		target, err := s.store.GetUserByEmail(ctx, strings.TrimSpace(share.TargetEmail))
		if err != nil {
			continue
		}
		if err := s.store.UpsertPasswordShareByIDs(ctx, share.ItemID, target.ID); err != nil {
			return nil, err
		}
		applied["password_shares"]++
	}
	for _, share := range snapshot.NoteShares {
		target, err := s.store.GetUserByEmail(ctx, strings.TrimSpace(share.TargetEmail))
		if err != nil {
			continue
		}
		if err := s.store.UpsertNoteShareByIDs(ctx, share.ItemID, target.ID); err != nil {
			return nil, err
		}
		applied["note_shares"]++
	}
	return applied, nil
}

func (s *Server) ensureUserSyncKey(ctx context.Context, userID string, masterPassword string) error {
	if strings.TrimSpace(masterPassword) == "" {
		return errors.New("master password is required")
	}
	if _, _, _, err := s.store.GetUserSyncKey(ctx, userID); err == nil {
		return nil
	}
	key, err := crypto.GenerateRandomKey(32)
	if err != nil {
		return err
	}
	keyEncoded := base64.RawStdEncoding.EncodeToString(key)
	serverWrapped, err := s.crypto.Encrypt(keyEncoded)
	if err != nil {
		return err
	}
	masterWrapped, err := crypto.WrapKeyWithPassword(masterPassword, key)
	if err != nil {
		return err
	}
	return s.store.UpsertUserSyncKey(ctx, userID, serverWrapped, masterWrapped, crypto.KeyFingerprint(key))
}

func (s *Server) rewrapUserSyncKey(ctx context.Context, userID string, masterPassword string) error {
	if strings.TrimSpace(masterPassword) == "" {
		return errors.New("master password is required")
	}
	serverWrapped, _, _, err := s.store.GetUserSyncKey(ctx, userID)
	if err != nil {
		return s.ensureUserSyncKey(ctx, userID, masterPassword)
	}
	keyEncoded, err := s.crypto.Decrypt(serverWrapped)
	if err != nil {
		return err
	}
	key, err := base64.RawStdEncoding.DecodeString(keyEncoded)
	if err != nil {
		return err
	}
	masterWrapped, err := crypto.WrapKeyWithPassword(masterPassword, key)
	if err != nil {
		return err
	}
	return s.store.UpsertUserSyncKey(ctx, userID, serverWrapped, masterWrapped, crypto.KeyFingerprint(key))
}

func (s *Server) buildUserSyncBundle(ctx context.Context, userID string) (controllerSyncUserBundle, error) {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return controllerSyncUserBundle{}, err
	}
	passwordIDs, err := s.store.ListPasswordIDs(ctx, user.ID)
	if err != nil {
		return controllerSyncUserBundle{}, err
	}
	noteIDs, err := s.store.ListNoteIDs(ctx, user.ID)
	if err != nil {
		return controllerSyncUserBundle{}, err
	}
	bundle := controllerSyncUserBundle{
		Version:        time.Now().UTC().Unix(),
		CreatedAt:      time.Now().UTC(),
		UserID:         user.ID,
		UserEmail:      user.Email,
		Passwords:      make([]models.PasswordEntry, 0, len(passwordIDs)),
		Notes:          make([]models.SecureNote, 0, len(noteIDs)),
		PasswordShares: []controllerSnapshotShare{},
		NoteShares:     []controllerSnapshotShare{},
	}
	for _, id := range passwordIDs {
		entry, err := s.store.GetPassword(ctx, s.crypto, id, user.ID)
		if err != nil {
			return controllerSyncUserBundle{}, err
		}
		bundle.Passwords = append(bundle.Passwords, entry)
		shareEmails, err := s.store.ListPasswordShareEmails(ctx, entry.ID)
		if err != nil {
			return controllerSyncUserBundle{}, err
		}
		for _, email := range shareEmails {
			bundle.PasswordShares = append(bundle.PasswordShares, controllerSnapshotShare{
				ItemID:      entry.ID,
				TargetEmail: strings.TrimSpace(email),
			})
		}
	}
	for _, id := range noteIDs {
		note, err := s.store.GetNote(ctx, s.crypto, id, user.ID)
		if err != nil {
			return controllerSyncUserBundle{}, err
		}
		bundle.Notes = append(bundle.Notes, note)
		shareEmails, err := s.store.ListNoteShareEmails(ctx, note.ID)
		if err != nil {
			return controllerSyncUserBundle{}, err
		}
		for _, email := range shareEmails {
			bundle.NoteShares = append(bundle.NoteShares, controllerSnapshotShare{
				ItemID:      note.ID,
				TargetEmail: strings.TrimSpace(email),
			})
		}
	}
	return bundle, nil
}

func (s *Server) buildEncryptedUserSyncBundle(ctx context.Context, userID string) (controllerEncryptedSyncBundle, error) {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return controllerEncryptedSyncBundle{}, err
	}
	serverWrapped, _, _, err := s.store.GetUserSyncKey(ctx, user.ID)
	if err != nil {
		return controllerEncryptedSyncBundle{}, err
	}
	keyEncoded, err := s.crypto.Decrypt(serverWrapped)
	if err != nil {
		return controllerEncryptedSyncBundle{}, err
	}
	key, err := base64.RawStdEncoding.DecodeString(keyEncoded)
	if err != nil {
		return controllerEncryptedSyncBundle{}, err
	}
	payload, err := s.buildUserSyncBundle(ctx, user.ID)
	if err != nil {
		return controllerEncryptedSyncBundle{}, err
	}
	serialized, err := json.Marshal(payload)
	if err != nil {
		return controllerEncryptedSyncBundle{}, err
	}
	ciphertext, err := crypto.EncryptWithKey(key, serialized)
	if err != nil {
		return controllerEncryptedSyncBundle{}, err
	}
	sum := sha256.Sum256(serialized)
	return controllerEncryptedSyncBundle{
		BundleID:      uuid.New().String(),
		UserID:        user.ID,
		UserEmail:     user.Email,
		BundleType:    "user_snapshot",
		PayloadHash:   hex.EncodeToString(sum[:]),
		CiphertextB64: base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func (s *Server) applyPendingUserSyncBundle(ctx context.Context, userID string, bundle controllerSyncUserBundle) (map[string]int, error) {
	if strings.TrimSpace(bundle.UserID) == "" || bundle.UserID != strings.TrimSpace(userID) {
		return nil, errors.New("bundle user mismatch")
	}
	applied := map[string]int{
		"passwords":       0,
		"notes":           0,
		"password_shares": 0,
		"note_shares":     0,
	}
	for _, entry := range bundle.Passwords {
		entry.UserID = userID
		if err := s.store.UpsertPassword(ctx, s.crypto, entry); err != nil {
			return nil, err
		}
		applied["passwords"]++
	}
	for _, note := range bundle.Notes {
		note.UserID = userID
		if err := s.store.InsertSecureNote(ctx, s.crypto, note); err != nil {
			return nil, err
		}
		applied["notes"]++
	}
	for _, share := range bundle.PasswordShares {
		target, err := s.store.GetUserByEmail(ctx, strings.TrimSpace(share.TargetEmail))
		if err != nil {
			continue
		}
		if err := s.store.UpsertPasswordShareByIDs(ctx, share.ItemID, target.ID); err != nil {
			return nil, err
		}
		applied["password_shares"]++
	}
	for _, share := range bundle.NoteShares {
		target, err := s.store.GetUserByEmail(ctx, strings.TrimSpace(share.TargetEmail))
		if err != nil {
			continue
		}
		if err := s.store.UpsertNoteShareByIDs(ctx, share.ItemID, target.ID); err != nil {
			return nil, err
		}
		applied["note_shares"]++
	}
	return applied, nil
}

func (s *Server) decryptPendingSyncBundle(ctx context.Context, user models.User, bundleID string, masterPassword string) (models.PendingSyncBundle, controllerSyncUserBundle, error) {
	if strings.TrimSpace(bundleID) == "" || strings.TrimSpace(masterPassword) == "" {
		return models.PendingSyncBundle{}, controllerSyncUserBundle{}, errors.New("bundle ID and master password are required")
	}
	if !crypto.VerifyPassword(masterPassword, user.MasterPasswordHash) {
		return models.PendingSyncBundle{}, controllerSyncUserBundle{}, errors.New("master password is invalid")
	}
	if err := s.ensureUserSyncKey(ctx, user.ID, masterPassword); err != nil {
		return models.PendingSyncBundle{}, controllerSyncUserBundle{}, err
	}
	_, masterWrapped, _, err := s.store.GetUserSyncKey(ctx, user.ID)
	if err != nil {
		return models.PendingSyncBundle{}, controllerSyncUserBundle{}, err
	}
	key, err := crypto.UnwrapKeyWithPassword(masterPassword, masterWrapped)
	if err != nil {
		return models.PendingSyncBundle{}, controllerSyncUserBundle{}, errors.New("failed to unlock sync key")
	}
	item, ciphertext, err := s.store.GetPendingSyncBundleForUser(ctx, user.ID, bundleID)
	if err != nil {
		return models.PendingSyncBundle{}, controllerSyncUserBundle{}, err
	}
	if item.Status != "pending" {
		return models.PendingSyncBundle{}, controllerSyncUserBundle{}, errors.New("sync bundle is no longer pending")
	}
	plaintext, err := crypto.DecryptWithKey(key, ciphertext)
	if err != nil {
		return item, controllerSyncUserBundle{}, errors.New("failed to decrypt sync bundle")
	}
	var bundle controllerSyncUserBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return item, controllerSyncUserBundle{}, errors.New("invalid sync bundle payload")
	}
	if strings.TrimSpace(bundle.UserID) != user.ID {
		return item, controllerSyncUserBundle{}, errors.New("bundle user mismatch")
	}
	return item, bundle, nil
}

func buildPendingSyncBundlePreview(item models.PendingSyncBundle, bundle controllerSyncUserBundle) pendingSyncBundlePreview {
	preview := pendingSyncBundlePreview{
		BundleID:            item.ID,
		MasterServerID:      item.MasterServerID,
		MasterServerURL:     item.MasterServerURL,
		CreatedAt:           item.CreatedAt,
		UserID:              bundle.UserID,
		UserEmail:           bundle.UserEmail,
		PasswordsCount:      len(bundle.Passwords),
		NotesCount:          len(bundle.Notes),
		PasswordSharesCount: len(bundle.PasswordShares),
		NoteSharesCount:     len(bundle.NoteShares),
	}
	for i, entry := range bundle.Passwords {
		if i >= 10 {
			break
		}
		preview.PasswordTitles = append(preview.PasswordTitles, strings.TrimSpace(entry.Title))
	}
	for i, note := range bundle.Notes {
		if i >= 10 {
			break
		}
		preview.NoteTitles = append(preview.NoteTitles, strings.TrimSpace(note.Title))
	}
	return preview
}

func (s *Server) handleControllerSnapshotExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	controllerID, nextToken, ok := s.authorizeRotatingController(w, r)
	if !ok {
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-M" {
		http.Error(w, "snapshot export is allowed only on AS-M", http.StatusConflict)
		return
	}
	snapshot, err := s.buildControllerSnapshot(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := snapshotHash(snapshot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"controller_id":    controllerID,
		"next_token":       nextToken,
		"status":           "snapshot_exported",
		"snapshot_version": snapshot.Version,
		"payload_hash":     hash,
		"snapshot":         snapshot,
	})
}

func (s *Server) handleControllerSnapshotApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	masterBaseURL := strings.TrimSpace(profile.LinkedMasterURL)
	if masterBaseURL == "" {
		masterBaseURL = strings.TrimSpace(req.MasterURL)
	}
	if _, err := s.verifyControllerSlaveGrant(r.Context(), masterBaseURL, r.Header.Get("X-Controller-Grant")); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if req.SnapshotVersion <= 0 || strings.TrimSpace(req.MasterURL) == "" {
		http.Error(w, "master_url and snapshot_version are required", http.StatusBadRequest)
		return
	}
	applied := map[string]int{}
	if len(req.Snapshot.Users)+len(req.Snapshot.Passwords)+len(req.Snapshot.Notes) > 0 {
		if req.Snapshot.Version > 0 && req.Snapshot.Version != req.SnapshotVersion {
			http.Error(w, "snapshot version mismatch", http.StatusBadRequest)
			return
		}
		expectedHash := strings.TrimSpace(req.PayloadHash)
		if expectedHash != "" {
			calculatedHash, err := snapshotHash(req.Snapshot)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if !strings.EqualFold(expectedHash, calculatedHash) {
				http.Error(w, "invalid snapshot hash", http.StatusBadRequest)
				return
			}
		}
		var err error
		applied, err = s.applyControllerSnapshot(r.Context(), req.Snapshot)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
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
	eventID := fmt.Sprintf("snapshot-%d", req.SnapshotVersion)
	_, _ = s.store.InsertControllerUpdateEvent(
		r.Context(),
		eventID,
		strings.TrimSpace(req.MasterServerID),
		req.SnapshotVersion,
		strings.TrimSpace(req.PayloadHash),
		"applied",
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "snapshot_applied",
		"sync_status":      "await_updates",
		"snapshot_version": req.SnapshotVersion,
		"applied":          applied,
	})
}

func (s *Server) handleControllerSyncBundlesExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	controllerID, nextToken, ok := s.authorizeRotatingController(w, r)
	if !ok {
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-M" {
		http.Error(w, "sync bundle export is allowed only on AS-M", http.StatusConflict)
		return
	}
	var req controllerSyncBundleExportRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	if req.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), req.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(user.Status) != "active" {
		http.Error(w, "user is not active", http.StatusBadRequest)
		return
	}
	bundle, err := s.buildEncryptedUserSyncBundle(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "sync_bundle_exported",
		"user_id":       user.ID,
		"bundle":        bundle,
		"controller_id": controllerID,
		"next_token":    nextToken,
	})
}

func (s *Server) handleControllerSyncBundlesApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	profile, err := s.store.GetServerProfile(r.Context())
	if err != nil {
		http.Error(w, "server profile is not initialized", http.StatusConflict)
		return
	}
	if profile.ServerMode != "AS-S" {
		http.Error(w, "sync bundle apply is allowed only on AS-S", http.StatusConflict)
		return
	}
	var req controllerSyncBundlesApplyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	masterBaseURL := strings.TrimSpace(profile.LinkedMasterURL)
	if masterBaseURL == "" {
		masterBaseURL = strings.TrimSpace(req.MasterURL)
	}
	if _, err := s.verifyControllerSlaveGrant(r.Context(), masterBaseURL, r.Header.Get("X-Controller-Grant")); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	inserted := 0
	skipped := 0
	req.UserID = strings.TrimSpace(req.UserID)
	if req.UserID == "" {
		req.UserID = strings.TrimSpace(req.Bundle.UserID)
	}
	if req.UserID == "" || strings.TrimSpace(req.Bundle.PayloadHash) == "" || strings.TrimSpace(req.Bundle.CiphertextB64) == "" {
		http.Error(w, "user_id, bundle.payload_hash, and bundle.ciphertext_b64 are required", http.StatusBadRequest)
		return
	}
	if req.UserID != strings.TrimSpace(req.Bundle.UserID) {
		http.Error(w, "bundle user mismatch", http.StatusBadRequest)
		return
	}
	if _, err := s.store.GetUserByID(r.Context(), req.UserID); err != nil {
		http.Error(w, "target user not found on slave", http.StatusBadRequest)
		return
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(req.Bundle.CiphertextB64))
	if err != nil {
		http.Error(w, "invalid bundle ciphertext", http.StatusBadRequest)
		return
	}
	ok, err := s.store.InsertPendingSyncBundle(r.Context(), models.PendingSyncBundle{
		ID:              req.Bundle.BundleID,
		UserID:          req.UserID,
		MasterServerID:  req.MasterServerID,
		MasterServerURL: req.MasterURL,
		BundleType:      req.Bundle.BundleType,
		PayloadHash:     req.Bundle.PayloadHash,
	}, ciphertext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if ok {
		inserted++
	} else {
		skipped++
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
		"status":   "sync_bundles_pending_confirmation",
		"inserted": inserted,
		"skipped":  skipped,
	})
}

func (s *Server) handleControllerUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	if _, err := s.verifyControllerSlaveGrant(r.Context(), profile.LinkedMasterURL, r.Header.Get("X-Controller-Grant")); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
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
	controllerID, nextToken, ok := s.authorizeRotatingController(w, r)
	if !ok {
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
		"status":        "ack_received",
		"event_id":      strings.TrimSpace(req.EventID),
		"controller_id": controllerID,
		"next_token":    nextToken,
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
		sharedBy := ""
		sharedByName := ""
		sharedAt := ""
		sharedAtISO := ""
		if item.UserID != user.ID && item.OwnerEmail != "" {
			sharedLabel = "Shared by " + item.OwnerEmail
			sharedBy = item.OwnerEmail
			sharedByName = strings.TrimSpace(strings.Split(item.OwnerEmail, "@")[0])
			if sharedByName == "" {
				sharedByName = item.OwnerEmail
			}
			if !item.SharedAt.IsZero() {
				sharedAt = item.SharedAt.Format("2006-01-02 15:04:05")
				sharedAtISO = item.SharedAt.Format(time.RFC3339)
			}
		}
		viewItems = append(viewItems, map[string]string{
			"ID":           item.ID,
			"Title":        item.Title,
			"Username":     item.Username,
			"URL":          item.URL,
			"Tags":         strings.Join(item.Tags, ", "),
			"Groups":       strings.Join(item.Groups, ", "),
			"SharedLabel":  sharedLabel,
			"SharedBy":     sharedBy,
			"SharedByName": sharedByName,
			"SharedAt":     sharedAt,
			"SharedAtISO":  sharedAtISO,
			"CanManage":    fmt.Sprintf("%t", item.UserID == user.ID),
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

func (s *Server) handlePasswordUpdateTitle(w http.ResponseWriter, r *http.Request) {
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
	id := strings.TrimSpace(r.FormValue("id"))
	title := strings.TrimSpace(r.FormValue("title"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := s.store.UpdatePasswordTitle(r.Context(), id, user.ID, title); err != nil {
		http.Redirect(w, r, "/passwords/view?id="+url.QueryEscape(id)+"&msg="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/passwords/view?id="+url.QueryEscape(id)+"&msg="+url.QueryEscape("Item name updated."), http.StatusSeeOther)
}

func (s *Server) handlePasswordUpdateCollections(w http.ResponseWriter, r *http.Request) {
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
	if err := s.store.UpdatePasswordCollections(
		r.Context(),
		id,
		user.ID,
		splitComma(r.FormValue("tags")),
		splitComma(r.FormValue("groups")),
	); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/passwords/view?id="+url.QueryEscape(id), http.StatusSeeOther)
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
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		canManage := entry.UserID == user.ID
		title := "Delete Password"
		actionLabel := "Delete"
		confirmText := "This action cannot be undone."
		if !canManage {
			title = "Unshare Password"
			actionLabel = "Unshare"
			confirmText = "This removes shared access only for your account."
		}
		s.renderWithUnlock(w, r, "delete_confirm.html", map[string]any{
			"Title":       title,
			"ItemID":      entry.ID,
			"ItemName":    entry.Title,
			"DeletePath":  "/passwords/delete",
			"ActionLabel": actionLabel,
			"ConfirmText": confirmText,
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
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if entry.UserID == user.ID {
			if err := s.store.DeletePassword(r.Context(), user.ID, id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			if err := s.store.UnsharePasswordForUser(r.Context(), id, user.ID); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
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
		message := strings.TrimSpace(r.URL.Query().Get("msg"))
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id, user.ID)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderPasswordView(w, r, user, entry, s.isUnlocked(r), message, "")
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
		if tags, err := s.store.ListTags(r.Context(), user.ID); err == nil {
			var tagNames []string
			for _, tag := range tags {
				tagNames = append(tagNames, tag.Name)
			}
			data["TagsList"] = tagNames
		}
		if groups, err := s.store.ListGroups(r.Context(), user.ID); err == nil {
			var groupNames []string
			for _, group := range groups {
				groupNames = append(groupNames, group.Name)
			}
			data["GroupsList"] = groupNames
		}
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

func (s *Server) handleMessagesPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	message := strings.TrimSpace(r.URL.Query().Get("msg"))
	inbox, err := s.store.ListInboxMessages(r.Context(), user.ID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sent, err := s.store.ListSentMessages(r.Context(), user.ID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pendingSyncs, err := s.store.ListPendingSyncBundles(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	targets, err := s.store.ListActiveUsersExcept(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "messages.html", map[string]any{
		"Title":          "Messages",
		"Message":        message,
		"Inbox":          inbox,
		"Sent":           sent,
		"PendingSyncs":   pendingSyncs,
		"Targets":        targets,
		"Locked":         !s.isUnlocked(r),
		"BodyMax":        300,
		"InboxLen":       len(inbox),
		"SentLen":        len(sent),
		"PendingSyncLen": len(pendingSyncs),
	})
}

func (s *Server) handleMessageSend(w http.ResponseWriter, r *http.Request) {
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
	toEmail := strings.TrimSpace(r.FormValue("to_email"))
	body := strings.TrimSpace(r.FormValue("body"))
	if err := s.store.SendInternalMessage(r.Context(), user.ID, toEmail, body); err != nil {
		http.Redirect(w, r, "/messages?msg="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/messages?msg="+url.QueryEscape("Message sent."), http.StatusSeeOther)
}

func (s *Server) handleMessageRead(w http.ResponseWriter, r *http.Request) {
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
	messageID := strings.TrimSpace(r.FormValue("id"))
	if messageID == "" {
		http.Redirect(w, r, "/messages", http.StatusSeeOther)
		return
	}
	_ = s.store.MarkMessageRead(r.Context(), user.ID, messageID)
	http.Redirect(w, r, "/messages", http.StatusSeeOther)
}

func (s *Server) renderPendingSyncReviewPage(w http.ResponseWriter, r *http.Request, bundle models.PendingSyncBundle, preview *pendingSyncBundlePreview, message string) {
	data := map[string]any{
		"Title":  "Pending Sync Review",
		"Bundle": bundle,
	}
	if preview != nil {
		data["Preview"] = preview
	}
	if message != "" {
		data["Message"] = message
	}
	s.renderWithUnlock(w, r, "sync_pending_review.html", data)
}

func (s *Server) handlePendingSyncReview(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		bundleID := strings.TrimSpace(r.URL.Query().Get("id"))
		if bundleID == "" {
			http.Redirect(w, r, "/messages?msg="+url.QueryEscape("Pending sync bundle ID is required."), http.StatusSeeOther)
			return
		}
		item, _, err := s.store.GetPendingSyncBundleForUser(r.Context(), user.ID, bundleID)
		if err != nil {
			http.Redirect(w, r, "/messages?msg="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		s.renderPendingSyncReviewPage(w, r, item, nil, strings.TrimSpace(r.URL.Query().Get("msg")))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		bundleID := strings.TrimSpace(r.FormValue("bundle_id"))
		masterPassword := r.FormValue("master_password")
		item, bundle, err := s.decryptPendingSyncBundle(r.Context(), user, bundleID, masterPassword)
		if err != nil {
			http.Redirect(w, r, "/sync/pending/review?id="+url.QueryEscape(bundleID)+"&msg="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		preview := buildPendingSyncBundlePreview(item, bundle)
		s.renderPendingSyncReviewPage(w, r, item, &preview, "Preview ready. Review the remote data, then confirm merge.")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePendingSyncConfirm(w http.ResponseWriter, r *http.Request) {
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
	bundleID := strings.TrimSpace(r.FormValue("bundle_id"))
	masterPassword := r.FormValue("master_password")
	item, bundle, err := s.decryptPendingSyncBundle(r.Context(), user, bundleID, masterPassword)
	if err != nil {
		http.Redirect(w, r, "/sync/pending/review?id="+url.QueryEscape(bundleID)+"&msg="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if _, err := s.applyPendingUserSyncBundle(r.Context(), user.ID, bundle); err != nil {
		_ = s.store.MarkPendingSyncBundleFailed(r.Context(), user.ID, bundleID, err.Error())
		http.Redirect(w, r, "/sync/pending/review?id="+url.QueryEscape(bundleID)+"&msg="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if err := s.store.MarkPendingSyncBundleApplied(r.Context(), user.ID, bundleID); err != nil {
		http.Redirect(w, r, "/sync/pending/review?id="+url.QueryEscape(bundleID)+"&msg="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/messages?msg="+url.QueryEscape(fmt.Sprintf("Sync bundle applied from %s.", item.MasterServerID)), http.StatusSeeOther)
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
	if strings.TrimSpace(newMaster) != "" {
		if err := s.rewrapUserSyncKey(r.Context(), user.ID, newMaster); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
	loadServerProfile := func() models.ServerProfile {
		profile, err := s.store.GetServerProfile(r.Context())
		if err != nil {
			return models.ServerProfile{
				ServerMode: "AS-M",
				SyncStatus: "standalone",
			}
		}
		if strings.TrimSpace(profile.ServerMode) == "" {
			profile.ServerMode = "AS-M"
		}
		if strings.TrimSpace(profile.SyncStatus) == "" {
			if profile.ServerMode == "AS-S" {
				profile.SyncStatus = "await_updates"
			} else {
				profile.SyncStatus = "standalone"
			}
		}
		return profile
	}
	renderSettings := func(profile models.ServerProfile, message string, errMsg string, popup bool) {
		data := map[string]any{
			"Title":         "Settings",
			"Settings":      settings,
			"User":          user,
			"ServerProfile": profile,
		}
		if message != "" {
			data["Message"] = message
		}
		if errMsg != "" {
			data["Error"] = errMsg
		}
		if popup {
			data["ModeChangePopup"] = true
		}
		s.renderWithUnlock(w, r, "settings.html", data)
	}
	switch r.Method {
	case http.MethodGet:
		renderSettings(loadServerProfile(), "", "", false)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		action := strings.TrimSpace(r.FormValue("action"))
		if action == "server_mode" {
			currentProfile := loadServerProfile()
			currentMode := strings.TrimSpace(strings.ToUpper(currentProfile.ServerMode))
			targetMode := strings.TrimSpace(strings.ToUpper(r.FormValue("server_mode")))
			linkedMasterURL := strings.TrimSpace(r.FormValue("linked_master_url"))
			linkedMasterID := strings.TrimSpace(r.FormValue("linked_master_id"))
			switch targetMode {
			case "AS-M":
				if err := s.store.SetServerProfile(r.Context(), models.ServerProfile{
					ServerMode:      "AS-M",
					SyncStatus:      "standalone",
					LinkedMasterID:  "",
					LinkedMasterURL: "",
				}); err != nil {
					renderSettings(currentProfile, "", err.Error(), true)
					return
				}
				renderSettings(models.ServerProfile{
					ServerMode: "AS-M",
					SyncStatus: "standalone",
				}, "Node mode changed to Master (AS-M).", "", false)
				return
			case "AS-S":
				if linkedMasterURL == "" {
					currentProfile.ServerMode = "AS-S"
					currentProfile.LinkedMasterID = linkedMasterID
					currentProfile.LinkedMasterURL = linkedMasterURL
					renderSettings(currentProfile, "", "Linked Master URL is required for Slave mode.", true)
					return
				}
				masterURL, err := url.ParseRequestURI(linkedMasterURL)
				if err != nil || masterURL.Scheme == "" || masterURL.Host == "" {
					currentProfile.ServerMode = "AS-S"
					currentProfile.LinkedMasterID = linkedMasterID
					currentProfile.LinkedMasterURL = linkedMasterURL
					renderSettings(currentProfile, "", "Linked Master URL must be a valid absolute URL (for example https://master.example.com).", true)
					return
				}
				// For Master -> Slave transitions, verify remote master availability first.
				if currentMode == "AS-M" {
					status := s.fetchRemoteMasterLinkStatus(linkedMasterURL)
					if !status.Reachable {
						reason := strings.TrimSpace(status.Error)
						if reason == "" {
							reason = "Master node is not reachable."
						}
						currentProfile.ServerMode = "AS-S"
						currentProfile.LinkedMasterID = linkedMasterID
						currentProfile.LinkedMasterURL = linkedMasterURL
						renderSettings(currentProfile, "", "Cannot switch to Slave mode: "+reason, true)
						return
					}
				}
				if err := s.store.SetServerProfile(r.Context(), models.ServerProfile{
					ServerMode:      "AS-S",
					SyncStatus:      "await_updates",
					LinkedMasterID:  linkedMasterID,
					LinkedMasterURL: linkedMasterURL,
				}); err != nil {
					currentProfile.ServerMode = "AS-S"
					currentProfile.LinkedMasterID = linkedMasterID
					currentProfile.LinkedMasterURL = linkedMasterURL
					renderSettings(currentProfile, "", err.Error(), true)
					return
				}
				renderSettings(models.ServerProfile{
					ServerMode:      "AS-S",
					SyncStatus:      "await_updates",
					LinkedMasterID:  linkedMasterID,
					LinkedMasterURL: linkedMasterURL,
				}, "Node mode changed to Slave (AS-S).", "", false)
				return
			default:
				renderSettings(currentProfile, "", "Invalid node mode.", true)
				return
			}
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
		settings = nextSettings
		renderSettings(loadServerProfile(), "Settings saved.", "", false)
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
		if err := s.ensureUserSyncKey(r.Context(), user.ID, master); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
			"ID":    g.ID,
			"Name":  g.Name,
			"Count": g.Count,
			"URL":   "/groups/view?name=" + urlQueryEscape(g.Name),
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
			"ID":    t.ID,
			"Name":  t.Name,
			"Count": t.Count,
			"URL":   "/tags/view?name=" + urlQueryEscape(t.Name),
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

func (s *Server) handleTagEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	tagID := strings.TrimSpace(r.FormValue("id"))
	newName := strings.TrimSpace(r.FormValue("new_name"))
	if tagID == "" || newName == "" {
		http.Error(w, "id and new name are required", http.StatusBadRequest)
		return
	}
	if err := s.store.RenameTagByID(r.Context(), user.ID, tagID, newName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/tags", http.StatusSeeOther)
}

func (s *Server) handleTagRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	tagID := strings.TrimSpace(r.FormValue("id"))
	if tagID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteTagByID(r.Context(), user.ID, tagID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/tags", http.StatusSeeOther)
}

func (s *Server) handleGroupEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	groupID := strings.TrimSpace(r.FormValue("id"))
	newName := strings.TrimSpace(r.FormValue("new_name"))
	if groupID == "" || newName == "" {
		http.Error(w, "id and new name are required", http.StatusBadRequest)
		return
	}
	if err := s.store.RenameGroupByID(r.Context(), user.ID, groupID, newName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (s *Server) handleGroupRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	groupID := strings.TrimSpace(r.FormValue("id"))
	if groupID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteGroupByID(r.Context(), user.ID, groupID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
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
	Weight         int
	TokenUpdatedAt string
	LastSeenAt     string
	LastSeenAtAbs  string
	CreatedAt      string
	UpdatedAt      string
	UpdatedAtAbs   string
}

type adminControllerUpdateEventView struct {
	EventID        string
	MasterServerID string
	VaultVersion   int64
	Status         string
	CreatedAt      time.Time
	EventType      string
	EventDetails   string
}

type adminRemoteMasterLinkStatus struct {
	Reachable         bool
	Error             string
	CheckedAt         string
	TotalLinks        int
	ActiveLinks       int
	StaleLinks        int
	OfflineLinks      int
	LatestHandshakeAt string
}

type adminRequestLogView struct {
	At         string `json:"at"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	RemoteIP   string `json:"remote_ip"`
	StatusCode int    `json:"status_code"`
	DurationMS int64  `json:"duration_ms"`
}

func formatAdminTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	return ts.Format("2006-01-02 15:04:05")
}

func formatMinutesAgo(ts time.Time, now time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	mins := int(now.Sub(ts).Minutes())
	if mins < 0 {
		mins = 0
	}
	return fmt.Sprintf("%d min ago", mins)
}

func classifyControllerLinkHealth(status string, lastHandshakeAt time.Time, now time.Time) string {
	if strings.TrimSpace(status) != "active" {
		return "offline"
	}
	age := now.Sub(lastHandshakeAt)
	if age > 5*time.Minute {
		return "offline"
	}
	if age > 90*time.Second {
		return "stale"
	}
	return "active"
}

func classifyControllerEvent(event models.ControllerUpdateEvent) (string, string) {
	eventID := strings.TrimSpace(strings.ToLower(event.EventID))
	switch {
	case strings.HasPrefix(eventID, "snapshot-"):
		return "snapshot", "full snapshot apply"
	case strings.HasPrefix(eventID, "evt-"):
		return "sync-event", "controller sync marker"
	default:
		if strings.TrimSpace(event.PayloadHash) != "" {
			return "sync-event", "payload hash present"
		}
		return "unknown", "event type not classified"
	}
}

func (s *Server) fetchRemoteMasterLinkStatus(masterBaseURL string) adminRemoteMasterLinkStatus {
	out := adminRemoteMasterLinkStatus{
		Reachable: false,
		CheckedAt: formatAdminTimestamp(time.Now()),
	}
	base := strings.TrimRight(strings.TrimSpace(masterBaseURL), "/")
	if base == "" {
		out.Error = "master URL is empty"
		return out
	}
	req, err := http.NewRequest(http.MethodGet, base+"/controller/links/status", nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	resp, err := s.controllerHTTPClient.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		out.Error = fmt.Sprintf("master returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
		return out
	}
	var payload struct {
		Summary struct {
			TotalLinks        int    `json:"total_links"`
			ActiveLinks       int    `json:"active_links"`
			StaleLinks        int    `json:"stale_links"`
			OfflineLinks      int    `json:"offline_links"`
			LatestHandshakeAt string `json:"latest_handshake_at"`
		} `json:"summary"`
		CheckedAt string `json:"checked_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		out.Error = err.Error()
		return out
	}
	out.Reachable = true
	out.CheckedAt = payload.CheckedAt
	out.TotalLinks = payload.Summary.TotalLinks
	out.ActiveLinks = payload.Summary.ActiveLinks
	out.StaleLinks = payload.Summary.StaleLinks
	out.OfflineLinks = payload.Summary.OfflineLinks
	out.LatestHandshakeAt = payload.Summary.LatestHandshakeAt
	return out
}

func (s *Server) adminPageData(ctx context.Context, message string) (map[string]any, error) {
	data := map[string]any{
		"Title":                 "Admin",
		"ServiceRestartEnabled": isUIServiceRestartEnabled(),
		"RequestLogs":           s.latestRequestLogs(requestLogAdminLimit),
		"RequestLogLimit":       requestLogAdminLimit,
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
					health := classifyControllerLinkHealth(link.Status, link.LastHandshakeAt, now)
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
				now := time.Now()
				var viewRegistry []adminControllerRegistryView
				for _, entry := range registry {
					viewRegistry = append(viewRegistry, adminControllerRegistryView{
						ControllerID:   entry.ControllerID,
						Status:         entry.Status,
						Weight:         entry.Weight,
						TokenUpdatedAt: formatAdminTimestamp(entry.TokenUpdatedAt),
						LastSeenAt:     formatMinutesAgo(entry.LastSeenAt, now),
						LastSeenAtAbs:  formatAdminTimestamp(entry.LastSeenAt),
						CreatedAt:      formatAdminTimestamp(entry.CreatedAt),
						UpdatedAt:      formatMinutesAgo(entry.UpdatedAt, now),
						UpdatedAtAbs:   formatAdminTimestamp(entry.UpdatedAt),
					})
				}
				data["ControllerRegistry"] = viewRegistry
			}
		}
		if profile.ServerMode == "AS-S" {
			data["RemoteMasterLinkStatus"] = s.fetchRemoteMasterLinkStatus(profile.LinkedMasterURL)
			if events, err := s.store.ListControllerUpdateEvents(ctx, 50); err == nil {
				rawView := make([]adminControllerUpdateEventView, 0, len(events))
				for _, e := range events {
					kind, details := classifyControllerEvent(e)
					rawView = append(rawView, adminControllerUpdateEventView{
						EventID:        e.EventID,
						MasterServerID: e.MasterServerID,
						VaultVersion:   e.VaultVersion,
						Status:         e.Status,
						CreatedAt:      e.CreatedAt,
						EventType:      kind,
						EventDetails:   details,
					})
				}
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
				latestView := make([]adminControllerUpdateEventView, 0, len(filtered))
				for _, e := range filtered {
					kind, details := classifyControllerEvent(e)
					latestView = append(latestView, adminControllerUpdateEventView{
						EventID:        e.EventID,
						MasterServerID: e.MasterServerID,
						VaultVersion:   e.VaultVersion,
						Status:         e.Status,
						CreatedAt:      e.CreatedAt,
						EventType:      kind,
						EventDetails:   details,
					})
				}
				data["ControllerUpdateEvents"] = latestView
				data["ControllerUpdateEventsRaw"] = rawView
				data["ControllerUpdateEventsRawCount"] = len(events)
				data["ControllerUpdateEventsLatestCount"] = len(latestView)
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

func redirectAdminWithMessage(w http.ResponseWriter, r *http.Request, message string) {
	target := "/admin"
	if strings.TrimSpace(message) != "" {
		target += "?msg=" + url.QueryEscape(message)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
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

func (s *Server) renderAdminGuardPage(w http.ResponseWriter, r *http.Request, message string) {
	data := map[string]any{
		"Title":       "Admin - Guard",
		"BlockedIPs":  s.listAdminBlockedIPs(),
		"TrustedCIDR": trustedAdminSubnetCIDR,
	}
	if message != "" {
		data["Message"] = message
	}
	s.renderWithUnlock(w, r, "admin_guard.html", data)
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
	s.renderAdminPage(w, r, strings.TrimSpace(r.URL.Query().Get("msg")))
}

func (s *Server) handleAdminRequestLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	pathFilter := strings.TrimSpace(r.URL.Query().Get("path"))
	writeJSON(w, http.StatusOK, map[string]any{
		"items":       s.latestRequestLogsFiltered(requestLogAdminLimit, pathFilter),
		"path_filter": pathFilter,
		"generatedAt": formatAdminTimestamp(time.Now()),
	})
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

func (s *Server) handleAdminAboutPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	version, author, lastUpdate, repoURL := s.loadBuildMetadata()
	s.renderWithUnlock(w, r, "admin_about.html", map[string]any{
		"Title":           "About",
		"BuildVersion":    version,
		"BuildAuthor":     author,
		"BuildLastUpdate": lastUpdate,
		"BuildRepoURL":    repoURL,
	})
}

func (s *Server) handleAdminGuardPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.currentUser(r)
	if !ok || !user.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.renderAdminGuardPage(w, r, strings.TrimSpace(r.URL.Query().Get("msg")))
}

func (s *Server) handleAdminGuardBlock(w http.ResponseWriter, r *http.Request) {
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
	clientIP := strings.TrimSpace(r.FormValue("client_ip"))
	if net.ParseIP(clientIP) == nil {
		http.Error(w, "valid IP is required", http.StatusBadRequest)
		return
	}
	minutes := adminProbeBlockMinutes
	if raw := strings.TrimSpace(r.FormValue("minutes")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			http.Error(w, "minutes must be a positive integer", http.StatusBadRequest)
			return
		}
		minutes = parsed
	}
	s.blockAdminAccess(clientIP, time.Duration(minutes)*time.Minute)
	http.Redirect(w, r, "/admin/guard?msg="+url.QueryEscape("IP blocked."), http.StatusSeeOther)
}

func (s *Server) handleAdminGuardUnblock(w http.ResponseWriter, r *http.Request) {
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
	clientIP := strings.TrimSpace(r.FormValue("client_ip"))
	if clientIP == "" {
		http.Error(w, "client_ip is required", http.StatusBadRequest)
		return
	}
	s.unblockAdminAccess(clientIP)
	http.Redirect(w, r, "/admin/guard?msg="+url.QueryEscape("IP unblocked."), http.StatusSeeOther)
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
	createdUser, err := s.store.GetUserByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.ensureUserSyncKey(r.Context(), createdUser.ID, masterPassword); err != nil {
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
	if err := s.rewrapUserSyncKey(r.Context(), targetID, masterPassword); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderAdminUsersListPage(w, r, "User updated.")
}

func (s *Server) handleAdminUpdateUserRole(w http.ResponseWriter, r *http.Request) {
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
	targetID := strings.TrimSpace(r.FormValue("user_id"))
	role := strings.ToLower(strings.TrimSpace(r.FormValue("role")))
	if targetID == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}
	var makeAdmin bool
	switch role {
	case "admin":
		makeAdmin = true
	case "user":
		makeAdmin = false
	default:
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	// Prevent locking yourself out of admin controls.
	if targetID == user.ID && !makeAdmin {
		s.renderAdminUsersListPage(w, r, "Cannot remove your own admin role.")
		return
	}
	if err := s.store.UpdateUserRole(r.Context(), targetID, makeAdmin); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if makeAdmin {
		s.renderAdminUsersListPage(w, r, "User role updated to Admin.")
		return
	}
	s.renderAdminUsersListPage(w, r, "User role updated to User.")
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
		redirectAdminWithMessage(w, r, "Controller approved.")
		return
	}
	redirectAdminWithMessage(w, r, "Controller set to non-approved.")
}

func (s *Server) handleAdminSetControllerWeight(w http.ResponseWriter, r *http.Request) {
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
	weightRaw := strings.TrimSpace(r.FormValue("weight"))
	if controllerID == "" || weightRaw == "" {
		http.Error(w, "controller_id and weight are required", http.StatusBadRequest)
		return
	}
	weight, err := strconv.Atoi(weightRaw)
	if err != nil || weight < 0 {
		http.Error(w, "weight must be an integer >= 0", http.StatusBadRequest)
		return
	}
	if err := s.store.SetControllerRegistryWeight(r.Context(), controllerID, weight); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	redirectAdminWithMessage(w, r, "Controller weight updated.")
}

func (s *Server) handleAdminCleanupStaleControllers(w http.ResponseWriter, r *http.Request) {
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
	ageMinutes := 1440
	if v := strings.TrimSpace(r.FormValue("age_minutes")); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed <= 0 {
			http.Error(w, "age_minutes must be a positive integer", http.StatusBadRequest)
			return
		}
		ageMinutes = parsed
	}
	cutoff := time.Now().Add(-time.Duration(ageMinutes) * time.Minute)
	updated, err := s.store.CleanupStaleControllerRegistry(r.Context(), cutoff)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if updated == 0 {
		redirectAdminWithMessage(w, r, "Stale controller cleanup complete. No controllers matched threshold.")
		return
	}
	redirectAdminWithMessage(w, r, fmt.Sprintf("Stale controller cleanup complete. Disabled %d controllers.", updated))
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
		redirectAdminWithMessage(w, r, "Controller links cleanup complete. No duplicates found.")
		return
	}
	redirectAdminWithMessage(w, r, fmt.Sprintf("Controller links cleanup complete. Removed %d duplicate rows.", removed))
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
	settings := s.readUISettings(r)
	appVersion := strings.TrimSpace(os.Getenv("APP_VERSION"))
	if appVersion == "" {
		appVersion = defaultAppVersion
	}
	data["AppVersion"] = appVersion
	data["UnlockMinutesDefault"] = settings.UnlockMinutes
	data["Unlocked"] = s.isUnlocked(r)
	data["UnlockSeconds"] = s.unlockRemainingSeconds(r)
	data["RequestPath"] = r.URL.Path
	data["Breadcrumbs"] = buildBreadcrumbs(r.URL.Path)
	data["UnreadMessages"] = 0
	if profile, err := s.store.GetServerProfile(r.Context()); err == nil {
		if strings.TrimSpace(profile.AppVersion) != "" {
			data["AppVersion"] = strings.TrimSpace(profile.AppVersion)
		}
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
		if unread, err := s.store.CountUnreadMessages(r.Context(), user.ID); err == nil {
			data["UnreadMessages"] = unread
		}
	}
	buildVersion, buildAuthor, buildLastUpdate, buildRepoURL := s.loadBuildMetadata()
	data["BuildVersion"] = buildVersion
	data["BuildAuthor"] = buildAuthor
	data["BuildLastUpdate"] = buildLastUpdate
	data["BuildRepoURL"] = buildRepoURL
	s.render(w, page, data)
}

func (s *Server) loadBuildMetadata() (string, string, string, string) {
	buildVersion := strings.TrimSpace(os.Getenv("APP_VERSION"))
	if buildVersion == "" {
		buildVersion = defaultAppVersion
	}
	buildAuthor := defaultBuildAuthor
	buildLastUpdate := defaultBuildLastUpdate
	buildRepoURL := ""

	raw, err := os.ReadFile(filepath.Join("static", "version.json"))
	if err != nil {
		return buildVersion, buildAuthor, buildLastUpdate, buildRepoURL
	}
	var meta buildMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return buildVersion, buildAuthor, buildLastUpdate, buildRepoURL
	}
	if strings.TrimSpace(meta.Version) != "" {
		buildVersion = strings.TrimSpace(meta.Version)
	}
	if strings.TrimSpace(meta.Author) != "" {
		buildAuthor = strings.TrimSpace(meta.Author)
	}
	if strings.TrimSpace(meta.LastUpdate) != "" {
		buildLastUpdate = strings.TrimSpace(meta.LastUpdate)
	}
	if strings.TrimSpace(meta.RepoURL) != "" {
		buildRepoURL = strings.TrimSpace(meta.RepoURL)
	}
	return buildVersion, buildAuthor, buildLastUpdate, buildRepoURL
}

func buildBreadcrumbs(path string) []breadcrumbItem {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return []breadcrumbItem{
			{Label: "Dashboard", Href: "/", Active: true},
		}
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return []breadcrumbItem{
			{Label: "Dashboard", Href: "/", Active: true},
		}
	}

	segments := strings.Split(trimmed, "/")
	items := make([]breadcrumbItem, 0, len(segments)+1)
	items = append(items, breadcrumbItem{
		Label:  "Dashboard",
		Href:   "/",
		Active: false,
	})

	currentPath := ""
	for i, seg := range segments {
		currentPath += "/" + seg
		label := breadcrumbLabel(seg)
		active := i == len(segments)-1
		href := currentPath
		if active {
			href = ""
		}
		items = append(items, breadcrumbItem{
			Label:  label,
			Href:   href,
			Active: active,
		})
	}
	return items
}

func breadcrumbLabel(segment string) string {
	segment = strings.TrimSpace(strings.ToLower(segment))
	switch segment {
	case "":
		return "Dashboard"
	case "admin":
		return "Admin"
	case "users":
		return "Users"
	case "create":
		return "Create"
	case "list":
		return "List"
	case "about":
		return "About"
	case "guard":
		return "Guard"
	case "passwords":
		return "Passwords"
	case "notes":
		return "Secure Notes"
	case "groups":
		return "Groups"
	case "tags":
		return "Tags"
	case "settings":
		return "Settings"
	case "account":
		return "Profile"
	case "import":
		return "Import"
	case "messages":
		return "Messages"
	}
	segment = strings.ReplaceAll(segment, "-", " ")
	parts := strings.Fields(segment)
	for i, part := range parts {
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	if len(parts) == 0 {
		return "Item"
	}
	return strings.Join(parts, " ")
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

func (s *Server) requestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &requestLogStatusRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/admin/request-logs" {
			return
		}
		s.appendRequestLog(requestLogEntry{
			At:         start,
			Method:     r.Method,
			Path:       r.URL.RequestURI(),
			RemoteIP:   clientIPFromRequest(r),
			StatusCode: rec.statusCode,
			DurationMS: time.Since(start).Milliseconds(),
		})
	})
}

func (s *Server) appendRequestLog(item requestLogEntry) {
	s.requestLogMu.Lock()
	defer s.requestLogMu.Unlock()
	s.requestLogs = append(s.requestLogs, item)
	if len(s.requestLogs) > requestLogCapacity {
		s.requestLogs = s.requestLogs[len(s.requestLogs)-requestLogCapacity:]
	}
}

func (s *Server) latestRequestLogs(limit int) []adminRequestLogView {
	return s.latestRequestLogsFiltered(limit, "")
}

func (s *Server) latestRequestLogsFiltered(limit int, pathFilter string) []adminRequestLogView {
	if limit <= 0 {
		limit = requestLogAdminLimit
	}
	pathFilter = strings.TrimSpace(strings.ToLower(pathFilter))
	s.requestLogMu.Lock()
	defer s.requestLogMu.Unlock()
	if len(s.requestLogs) == 0 {
		return nil
	}
	out := make([]adminRequestLogView, 0, limit)
	for i := len(s.requestLogs) - 1; i >= 0 && len(out) < limit; i-- {
		item := s.requestLogs[i]
		if pathFilter != "" && !strings.Contains(strings.ToLower(item.Path), pathFilter) {
			continue
		}
		out = append(out, adminRequestLogView{
			At:         formatAdminTimestamp(item.At),
			Method:     item.Method,
			Path:       item.Path,
			RemoteIP:   item.RemoteIP,
			StatusCode: item.StatusCode,
			DurationMS: item.DurationMS,
		})
	}
	return out
}

func clientIPFromRequest(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if rip := strings.TrimSpace(r.Header.Get("X-Real-IP")); rip != "" {
		return rip
	}
	addr := strings.TrimSpace(r.RemoteAddr)
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

func (s *Server) loginBlockedFor(clientIP string) time.Duration {
	ip := strings.TrimSpace(clientIP)
	if ip == "" {
		return 0
	}
	now := time.Now()
	s.loginGuardMu.Lock()
	defer s.loginGuardMu.Unlock()
	state, ok := s.loginGuardByIP[ip]
	if !ok {
		return 0
	}
	if now.After(state.BlockedUntil) {
		return 0
	}
	return time.Until(state.BlockedUntil)
}

func (s *Server) recordLoginFailure(clientIP string) time.Duration {
	ip := strings.TrimSpace(clientIP)
	if ip == "" {
		return 0
	}
	now := time.Now()
	s.loginGuardMu.Lock()
	defer s.loginGuardMu.Unlock()
	state := s.loginGuardByIP[ip]
	state.Failures++
	state.LastSeen = now
	if state.Failures >= loginBlockThreshold {
		blockMinutes := state.Failures
		if blockMinutes > loginBlockMaxMinutes {
			blockMinutes = loginBlockMaxMinutes
		}
		state.BlockedUntil = now.Add(time.Duration(blockMinutes) * time.Minute)
	}
	s.loginGuardByIP[ip] = state
	if now.Before(state.BlockedUntil) {
		return time.Until(state.BlockedUntil)
	}
	return 0
}

func (s *Server) clearLoginFailures(clientIP string) {
	ip := strings.TrimSpace(clientIP)
	if ip == "" {
		return
	}
	s.loginGuardMu.Lock()
	defer s.loginGuardMu.Unlock()
	delete(s.loginGuardByIP, ip)
}

func (s *Server) blockAdminAccess(clientIP string, duration time.Duration) {
	ip := strings.TrimSpace(clientIP)
	if ip == "" || duration <= 0 {
		return
	}
	s.adminProbeMu.Lock()
	defer s.adminProbeMu.Unlock()
	s.adminProbeBlockedIPs[ip] = time.Now().Add(duration)
}

func (s *Server) adminBlockedFor(clientIP string) time.Duration {
	ip := strings.TrimSpace(clientIP)
	if ip == "" {
		return 0
	}
	now := time.Now()
	s.adminProbeMu.Lock()
	defer s.adminProbeMu.Unlock()
	until, ok := s.adminProbeBlockedIPs[ip]
	if !ok {
		return 0
	}
	if now.After(until) {
		delete(s.adminProbeBlockedIPs, ip)
		return 0
	}
	return time.Until(until)
}

func (s *Server) unblockAdminAccess(clientIP string) {
	ip := strings.TrimSpace(clientIP)
	if ip == "" {
		return
	}
	s.adminProbeMu.Lock()
	defer s.adminProbeMu.Unlock()
	delete(s.adminProbeBlockedIPs, ip)
}

func (s *Server) listAdminBlockedIPs() []adminGuardBlockedIPView {
	now := time.Now()
	s.adminProbeMu.Lock()
	defer s.adminProbeMu.Unlock()
	if len(s.adminProbeBlockedIPs) == 0 {
		return nil
	}
	items := make([]adminGuardBlockedIPView, 0, len(s.adminProbeBlockedIPs))
	for ip, until := range s.adminProbeBlockedIPs {
		if now.After(until) {
			delete(s.adminProbeBlockedIPs, ip)
			continue
		}
		items = append(items, adminGuardBlockedIPView{
			IP:           ip,
			BlockedUntil: formatAdminTimestamp(until),
			BlockedFor:   formatDurationRoundedMinute(time.Until(until)),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].IP < items[j].IP
	})
	return items
}

func isTrustedAdminSubnet(clientIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(trustedAdminSubnetCIDR)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func formatDurationRoundedMinute(d time.Duration) string {
	if d <= 0 {
		return "1 minute"
	}
	mins := int((d + time.Minute - 1) / time.Minute)
	if mins <= 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", mins)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		clientIP := clientIPFromRequest(r)
		if strings.HasPrefix(path, "/admin") {
			trustedSubnet := isTrustedAdminSubnet(clientIP)
			if !trustedSubnet {
				if blockedFor := s.adminBlockedFor(clientIP); blockedFor > 0 {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				// /admin only permits a small set of query parameters; treat anything else as suspicious probes.
				if path == "/admin" && strings.TrimSpace(r.URL.RawQuery) != "" {
					values := r.URL.Query()
					allowed := true
					for key := range values {
						if key != "msg" {
							allowed = false
							break
						}
					}
					if !allowed {
						s.blockAdminAccess(clientIP, time.Duration(adminProbeBlockMinutes)*time.Minute)
						http.Error(w, "forbidden", http.StatusForbidden)
						return
					}
				}
			}
		}
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
