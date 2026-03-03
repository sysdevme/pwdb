package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
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

type Server struct {
	templateDir string
	store     *db.Store
	crypto    *crypto.Service
	unlock    *unlockManager
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
	return &Server{
		templateDir: "templates",
		store:       store,
		crypto:      cryptoSvc,
		unlock:      newUnlockManager(),
	}
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
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/passwords", s.handlePasswords)
	mux.HandleFunc("/passwords/new", s.handlePasswordForm)
	mux.HandleFunc("/passwords/edit", s.handlePasswordEdit)
	mux.HandleFunc("/passwords/update-password", s.handlePasswordUpdatePassword)
	mux.HandleFunc("/passwords/delete", s.handlePasswordDelete)
	mux.HandleFunc("/passwords/view", s.handlePasswordView)
	mux.HandleFunc("/notes", s.handleNotes)
	mux.HandleFunc("/notes/new", s.handleNoteForm)
	mux.HandleFunc("/notes/edit", s.handleNoteEdit)
	mux.HandleFunc("/notes/delete", s.handleNoteDelete)
	mux.HandleFunc("/notes/view", s.handleNoteView)
	mux.HandleFunc("/groups", s.handleGroups)
	mux.HandleFunc("/tags", s.handleTags)
	mux.HandleFunc("/import/1password", s.handleImport1Password)
	mux.HandleFunc("/import/issues", s.handleImportIssues)
	mux.HandleFunc("/auth/biometric-unlock", s.handleBiometricUnlock)
	mux.HandleFunc("/auth/biometric-token", s.handleBiometricToken)
	mux.HandleFunc("/unlock", s.handleUnlockPage)
	mux.HandleFunc("/lock", s.handleLock)
	mux.HandleFunc("/admin", s.handleAdmin)
	mux.HandleFunc("/admin/backup", s.handleAdminBackup)
	mux.HandleFunc("/admin/restore", s.handleAdminRestore)
	mux.HandleFunc("/admin/rebuild", s.handleAdminRebuild)
	mux.HandleFunc("/admin/users", s.handleAdminCreateUser)
	mux.HandleFunc("/admin/users/update", s.handleAdminUpdateUser)
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
		})
	case http.MethodPost:
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
		adminID := uuid.New().String()
		if err := s.store.CreateUser(r.Context(), models.User{
			ID:           adminID,
			Email:        email,
			PasswordHash: loginHash,
			MasterPasswordHash: masterHash,
			IsAdmin:      true,
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
	items, err := s.store.ListPasswords(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var viewItems []map[string]string
	for _, item := range items {
		viewItems = append(viewItems, map[string]string{
			"ID":       item.ID,
			"Title":    item.Title,
			"Username": item.Username,
			"URL":      item.URL,
			"Tags":     strings.Join(item.Tags, ", "),
			"Groups":   strings.Join(item.Groups, ", "),
		})
	}
	s.renderWithUnlock(w, r, "passwords.html", map[string]any{
		"Title": "Passwords",
		"Items": viewItems,
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
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok || entry.UserID != user.ID {
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
	entry, err := s.store.GetPassword(r.Context(), s.crypto, id)
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
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok || entry.UserID != user.ID {
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
	items, err := s.store.ListNotes(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "notes.html", map[string]any{
		"Title": "Secure Notes",
		"Items": items,
	})
}

func (s *Server) handleNoteForm(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderWithUnlock(w, r, "note_form.html", map[string]any{
			"Title": "New Note",
			"Item":  models.SecureNote{},
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
			Title: strings.TrimSpace(r.FormValue("title")),
			Body:  strings.TrimSpace(r.FormValue("body")),
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
		note, err := s.store.GetNote(r.Context(), s.crypto, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok || note.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderWithUnlock(w, r, "note_form.html", map[string]any{
			"Title": "Edit Note",
			"Item":  note,
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
			ID:    r.FormValue("id"),
			UserID: user.ID,
			Title: strings.TrimSpace(r.FormValue("title")),
			Body:  strings.TrimSpace(r.FormValue("body")),
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
		note, err := s.store.GetNote(r.Context(), s.crypto, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok || note.UserID != user.ID {
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
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		note, err := s.store.GetNote(r.Context(), s.crypto, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok || note.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		data := map[string]any{
			"Title":    "View Secure Note",
			"ItemID":   note.ID,
			"ItemName": note.Title,
		}
		if s.isUnlocked(r) {
			data["Body"] = note.Body
		}
		s.renderWithUnlock(w, r, "note_view.html", data)
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
		note, err := s.store.GetNote(r.Context(), s.crypto, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok || note.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderWithUnlock(w, r, "note_view.html", map[string]any{
			"Title":    "View Secure Note",
			"ItemID":   note.ID,
			"ItemName": note.Title,
			"Body":     note.Body,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePasswordView(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok || entry.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		data := map[string]any{
			"Title":    "View Password",
			"ItemID":   entry.ID,
			"ItemName": entry.Title,
			"Username": entry.Username,
			"URL":      entry.URL,
			"Notes":    entry.Notes,
			"TagsText": strings.Join(entry.Tags, ", "),
			"GroupsText": strings.Join(entry.Groups, ", "),
			"ImportSource": entry.ImportSource,
			"ImportRaw": entry.ImportRaw,
			"ImportRawB64": base64.StdEncoding.EncodeToString([]byte(entry.ImportRaw)),
		}
		if s.isUnlocked(r) {
			data["Password"] = entry.Password
		}
		s.renderWithUnlock(w, r, "password_view.html", data)
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
		entry, err := s.store.GetPassword(r.Context(), s.crypto, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, ok := s.currentUser(r)
		if !ok || entry.UserID != user.ID {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.renderWithUnlock(w, r, "password_view.html", map[string]any{
			"Title":    "View Password",
			"ItemID":   entry.ID,
			"ItemName": entry.Title,
			"Username": entry.Username,
			"URL":      entry.URL,
			"Notes":    entry.Notes,
			"TagsText": strings.Join(entry.Tags, ", "),
			"GroupsText": strings.Join(entry.Groups, ", "),
			"Password": entry.Password,
			"ImportSource": entry.ImportSource,
			"ImportRaw": entry.ImportRaw,
			"ImportRawB64": base64.StdEncoding.EncodeToString([]byte(entry.ImportRaw)),
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
	cookieToken, err := s.unlock.Issue(user.ID, 5*time.Minute)
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
		MaxAge:   300,
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
	items, err := s.store.ListGroups(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var viewItems []map[string]any
	for _, g := range items {
		viewItems = append(viewItems, map[string]any{
			"Name":  g.Name,
			"Count": g.Count,
		})
	}
	s.renderWithUnlock(w, r, "groups.html", map[string]any{
		"Title": "Groups",
		"Items": viewItems,
	})
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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
			"Name":  t.Name,
			"Count": t.Count,
		})
	}
	s.renderWithUnlock(w, r, "tags.html", map[string]any{
		"Title": "Tags",
		"Items": viewItems,
	})
}

type adminBackup struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Passwords []models.PasswordEntry `json:"passwords"`
	Notes     []models.SecureNote `json:"notes"`
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
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "admin.html", map[string]any{
		"Title": "Admin",
		"Users": users,
	})
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
		Email:        email,
		PasswordHash: loginHash,
		MasterPasswordHash: masterHash,
		IsAdmin:      false,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "admin.html", map[string]any{
		"Title":   "Admin",
		"Message": "User created.",
		"Users": users,
	})
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
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderWithUnlock(w, r, "admin.html", map[string]any{
		"Title":   "Admin",
		"Message": "User updated.",
		"Users": users,
	})
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
		entry, err := s.store.GetPassword(ctx, s.crypto, id)
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
		note, err := s.store.GetNote(ctx, s.crypto, id)
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
	s.renderWithUnlock(w, r, "admin.html", map[string]any{
		"Title":   "Admin",
		"Message": fmt.Sprintf("Restored %d passwords and %d notes.", len(backup.Passwords), len(backup.Notes)),
	})
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
		entry, err := s.store.GetPassword(ctx, s.crypto, id)
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
		note, err := s.store.GetNote(ctx, s.crypto, id)
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
	s.renderWithUnlock(w, r, "admin.html", map[string]any{
		"Title":   "Admin",
		"Message": fmt.Sprintf("Rebuilt %d items from import_raw.", rebuilt),
	})
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
			"Title": "Import from 1Password (.1pif)",
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
		if strings.HasPrefix(path, "/static/") || path == "/login" || path == "/setup" || path == "/auth/biometric-token" {
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
	mu     sync.Mutex
	tokens map[string]unlockToken
	preauth map[string]time.Time
}

type unlockToken struct {
	UserID string
	ExpiresAt time.Time
}

func newUnlockManager() *unlockManager {
	return &unlockManager{
		tokens: make(map[string]unlockToken),
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
		UserID: userID,
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
