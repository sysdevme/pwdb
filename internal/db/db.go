package db

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"password-manager-go/internal/crypto"
	"password-manager-go/internal/models"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(ctx context.Context, databaseURL string) (*Store, error) {
	if databaseURL == "" {
		return nil, errors.New("DATABASE_URL not set")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func NewStoreFromEnv(ctx context.Context) (*Store, error) {
	return NewStore(ctx, os.Getenv("DATABASE_URL"))
}

func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.pool.Ping(ctx)
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

type Stats struct {
	Passwords    int
	Notes        int
	Groups       int
	Tags         int
	ImportIssues int
}

func (s *Store) GetStats(ctx context.Context, userID string) (Stats, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return Stats{}, err
	}
	var stats Stats
	err = s.pool.QueryRow(ctx, sqlGetStats, uid).Scan(&stats.Passwords, &stats.Notes, &stats.Groups, &stats.Tags, &stats.ImportIssues)
	return stats, err
}

func (s *Store) UpsertPassword(ctx context.Context, cryptoSvc *crypto.Service, entry models.PasswordEntry) error {
	if entry.Title == "" || entry.Password == "" {
		return errors.New("missing title or password")
	}
	id, err := parseOrNewUUID(entry.ID)
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(entry.UserID)
	if err != nil {
		return err
	}
	passEnc, err := cryptoSvc.Encrypt(entry.Password)
	if err != nil {
		return err
	}
	var notesEnc []byte
	if entry.Notes != "" {
		notesEnc, err = cryptoSvc.Encrypt(entry.Notes)
		if err != nil {
			return err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := upsertPasswordTx(ctx, tx, userID, id, entry, passEnc, notesEnc); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) ListPasswords(ctx context.Context, userID string) ([]models.PasswordEntry, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListPasswords, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.PasswordEntry
	for rows.Next() {
		var id uuid.UUID
		var ownerID uuid.UUID
		var ownerEmail string
		var title, username, url, tags, groups string
		var sharedAt *time.Time
		if err := rows.Scan(&id, &ownerID, &ownerEmail, &title, &username, &url, &sharedAt, &tags, &groups); err != nil {
			return nil, err
		}
		entry := models.PasswordEntry{
			ID:         id.String(),
			UserID:     ownerID.String(),
			OwnerEmail: ownerEmail,
			Title:      title,
			Username:   username,
			URL:        url,
			Tags:       splitTags(tags),
			Groups:     splitTags(groups),
		}
		if sharedAt != nil {
			entry.SharedAt = *sharedAt
		}
		items = append(items, entry)
	}
	return items, rows.Err()
}

func (s *Store) ListPasswordIDs(ctx context.Context, userID string) ([]string, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListPasswordIDs, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id.String())
	}
	return ids, rows.Err()
}

func (s *Store) GetPassword(ctx context.Context, cryptoSvc *crypto.Service, id string, userID string) (models.PasswordEntry, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	viewerID, err := uuid.Parse(userID)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	var entry models.PasswordEntry
	var ownerEmail string
	var passEnc, notesEnc []byte
	var tags string
	var groups string
	var importSource *string
	var importRaw []byte
	err = s.pool.QueryRow(ctx, sqlGetPassword, uid, viewerID).Scan(&entry.ID, &entry.UserID, &ownerEmail, &entry.Title, &entry.Username, &passEnc, &entry.URL, &notesEnc, &importSource, &importRaw, &tags, &groups)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	entry.OwnerEmail = ownerEmail
	password, err := cryptoSvc.Decrypt(passEnc)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	entry.Password = password
	if len(notesEnc) > 0 {
		notes, err := cryptoSvc.Decrypt(notesEnc)
		if err != nil {
			return models.PasswordEntry{}, err
		}
		entry.Notes = notes
	}
	entry.Tags = splitTags(tags)
	entry.Groups = splitTags(groups)
	if importSource != nil {
		entry.ImportSource = *importSource
	}
	if len(importRaw) > 0 {
		entry.ImportRaw = string(importRaw)
	}
	return entry, nil
}

func (s *Store) UpdatePassword(ctx context.Context, cryptoSvc *crypto.Service, entry models.PasswordEntry) error {
	if entry.ID == "" {
		return errors.New("missing id")
	}
	if entry.Title == "" || entry.Password == "" {
		return errors.New("missing title or password")
	}
	uid, err := uuid.Parse(entry.ID)
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(entry.UserID)
	if err != nil {
		return err
	}
	passEnc, err := cryptoSvc.Encrypt(entry.Password)
	if err != nil {
		return err
	}
	var notesEnc []byte
	if entry.Notes != "" {
		notesEnc, err = cryptoSvc.Encrypt(entry.Notes)
		if err != nil {
			return err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, sqlUpdatePassword, uid, entry.Title, entry.Username, passEnc, entry.URL, notesEnc, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("password not found")
	}
	if _, err := tx.Exec(ctx, sqlDeleteEntryTagsByEntryID, uid); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlDeleteGroupEntriesByEntryID, uid); err != nil {
		return err
	}
	for _, tagName := range normalizeTags(entry.Tags) {
		tagID, err := ensureTag(ctx, tx, userID, tagName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertEntryTag, uid, tagID); err != nil {
			return err
		}
	}
	for _, groupName := range normalizeTags(entry.Groups) {
		groupID, err := ensureGroup(ctx, tx, userID, groupName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertGroupEntry, groupID, uid); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) UpdatePasswordTitle(ctx context.Context, entryID, ownerUserID, title string) error {
	uid, err := uuid.Parse(entryID)
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(ownerUserID)
	if err != nil {
		return err
	}
	title = strings.TrimSpace(title)
	if title == "" {
		return errors.New("title is required")
	}
	tag, err := s.pool.Exec(ctx, sqlUpdatePasswordTitle, uid, title, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("password not found")
	}
	return nil
}

func (s *Store) UpdatePasswordCollections(ctx context.Context, entryID, ownerUserID string, tags, groups []string) error {
	uid, err := uuid.Parse(entryID)
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(ownerUserID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM password_entries WHERE id = $1 AND user_id = $2)`, uid, userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errors.New("password not found")
	}
	if _, err := tx.Exec(ctx, sqlDeleteEntryTagsByEntryID, uid); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlDeleteGroupEntriesByEntryID, uid); err != nil {
		return err
	}
	for _, tagName := range normalizeTags(tags) {
		tagID, err := ensureTag(ctx, tx, userID, tagName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertEntryTag, uid, tagID); err != nil {
			return err
		}
	}
	for _, groupName := range normalizeTags(groups) {
		groupID, err := ensureGroup(ctx, tx, userID, groupName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertGroupEntry, groupID, uid); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) DeletePassword(ctx context.Context, userID, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlDeletePassword, uid, userUUID)
	return err
}

func (s *Store) InsertSecureNote(ctx context.Context, cryptoSvc *crypto.Service, note models.SecureNote) error {
	if note.Title == "" || note.Body == "" {
		return errors.New("missing title or body")
	}
	id, err := parseOrNewUUID(note.ID)
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(note.UserID)
	if err != nil {
		return err
	}
	bodyEnc, err := cryptoSvc.Encrypt(note.Body)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := upsertNoteTx(ctx, tx, userID, id, note, bodyEnc); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListNotes(ctx context.Context, userID string) ([]models.SecureNote, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListNotes, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []models.SecureNote
	for rows.Next() {
		var id uuid.UUID
		var ownerID uuid.UUID
		var ownerEmail string
		var title, tags, groups string
		var updated time.Time
		if err := rows.Scan(&id, &ownerID, &ownerEmail, &title, &updated, &tags, &groups); err != nil {
			return nil, err
		}
		items = append(items, models.SecureNote{
			ID:         id.String(),
			UserID:     ownerID.String(),
			OwnerEmail: ownerEmail,
			Title:      title,
			Tags:       splitTags(tags),
			Groups:     splitTags(groups),
			UpdatedAt:  updated,
		})
	}
	return items, rows.Err()
}

func (s *Store) ListTags(ctx context.Context, userID string) ([]models.Tag, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListTags, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []models.Tag
	for rows.Next() {
		var id uuid.UUID
		var name string
		var count int
		if err := rows.Scan(&id, &name, &count); err != nil {
			return nil, err
		}
		items = append(items, models.Tag{ID: id.String(), Name: name, UserID: userID, Count: count})
	}
	return items, rows.Err()
}

func (s *Store) ListGroups(ctx context.Context, userID string) ([]models.Group, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListGroups, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []models.Group
	for rows.Next() {
		var id uuid.UUID
		var name string
		var count int
		if err := rows.Scan(&id, &name, &count); err != nil {
			return nil, err
		}
		items = append(items, models.Group{ID: id.String(), Name: name, UserID: userID, Count: count})
	}
	return items, rows.Err()
}

func (s *Store) ListNoteIDs(ctx context.Context, userID string) ([]string, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListNoteIDs, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id.String())
	}
	return ids, rows.Err()
}

func (s *Store) InsertImportRun(ctx context.Context, run models.ImportRun) error {
	id, err := parseOrNewUUID(run.ID)
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(run.UserID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlInsertImportRun, id, userID, run.Filename, run.FileSize, run.ImportedPasswords, run.ImportedNotes, run.ExistingCount, run.NewCount, run.SkippedCount)
	return err
}

func (s *Store) ListImportRuns(ctx context.Context, userID string, limit int) ([]models.ImportRun, error) {
	if limit <= 0 {
		limit = 20
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListImportRuns, uid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []models.ImportRun
	for rows.Next() {
		var run models.ImportRun
		var id uuid.UUID
		var userID uuid.UUID
		if err := rows.Scan(&id, &userID, &run.Filename, &run.FileSize, &run.ImportedPasswords, &run.ImportedNotes, &run.ExistingCount, &run.NewCount, &run.SkippedCount, &run.CreatedAt); err != nil {
			return nil, err
		}
		run.ID = id.String()
		run.UserID = userID.String()
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *Store) InsertImportIssue(ctx context.Context, issue models.ImportIssue) error {
	id, err := parseOrNewUUID(issue.ID)
	if err != nil {
		return err
	}
	var runID *uuid.UUID
	if issue.ImportRunID != "" {
		if parsed, err := uuid.Parse(issue.ImportRunID); err == nil {
			runID = &parsed
		}
	}
	_, err = s.pool.Exec(ctx, sqlInsertImportIssue, id, runID, issue.Source, nullIfEmpty(issue.TypeName), nullIfEmpty(issue.Title), nullIfEmpty(issue.ExternalUUID), issue.Reason, nullIfEmpty(issue.Raw))
	return err
}

func (s *Store) ListImportIssues(ctx context.Context, limit int) ([]models.ImportIssue, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, sqlListImportIssues, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var issues []models.ImportIssue
	for rows.Next() {
		var issue models.ImportIssue
		var id uuid.UUID
		var runID *uuid.UUID
		var raw *string
		if err := rows.Scan(&id, &runID, &issue.Source, &issue.TypeName, &issue.Title, &issue.ExternalUUID, &issue.Reason, &raw, &issue.CreatedAt); err != nil {
			return nil, err
		}
		issue.ID = id.String()
		if runID != nil {
			issue.ImportRunID = runID.String()
		}
		if raw != nil {
			issue.Raw = *raw
		}
		issues = append(issues, issue)
	}
	return issues, rows.Err()
}

func nullIfEmpty(value string) *string {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	return &v
}

func nullTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var count int
	if err := s.pool.QueryRow(ctx, sqlCountUsers).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func normalizeServerMode(raw string) (string, error) {
	mode := strings.TrimSpace(strings.ToUpper(raw))
	switch mode {
	case "AS-M", "AS-S":
		return mode, nil
	default:
		return "", errors.New("invalid server mode")
	}
}

func normalizeSyncStatus(raw string) (string, error) {
	status := strings.TrimSpace(strings.ToLower(raw))
	switch status {
	case "":
		return "standalone", nil
	case "standalone", "await_updates", "syncing", "error":
		return status, nil
	default:
		return "", errors.New("invalid sync status")
	}
}

func (s *Store) SetServerProfile(ctx context.Context, profile models.ServerProfile) error {
	mode, err := normalizeServerMode(profile.ServerMode)
	if err != nil {
		return err
	}
	status, err := normalizeSyncStatus(profile.SyncStatus)
	if err != nil {
		return err
	}
	appVersion := strings.TrimSpace(profile.AppVersion)
	if appVersion == "" {
		appVersion = strings.TrimSpace(os.Getenv("APP_VERSION"))
	}
	if appVersion == "" {
		appVersion = "4.1.0"
	}
	_, err = s.pool.Exec(
		ctx,
		sqlUpsertServerProfile,
		mode,
		status,
		nullIfEmpty(profile.LinkedMasterID),
		nullIfEmpty(profile.LinkedMasterURL),
		appVersion,
	)
	return err
}

func (s *Store) InitializeSetup(ctx context.Context, profile models.ServerProfile, user models.User, serverWrappedKey []byte, masterWrappedKey []byte, fingerprint string) error {
	mode, err := normalizeServerMode(profile.ServerMode)
	if err != nil {
		return err
	}
	status, err := normalizeSyncStatus(profile.SyncStatus)
	if err != nil {
		return err
	}
	appVersion := strings.TrimSpace(profile.AppVersion)
	if appVersion == "" {
		appVersion = strings.TrimSpace(os.Getenv("APP_VERSION"))
	}
	if appVersion == "" {
		appVersion = "4.1.0"
	}
	id, err := parseOrNewUUID(user.ID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(user.Email) == "" || strings.TrimSpace(user.PasswordHash) == "" || strings.TrimSpace(user.MasterPasswordHash) == "" {
		return errors.New("user email and password hashes are required")
	}
	if len(serverWrappedKey) == 0 || len(masterWrappedKey) == 0 || strings.TrimSpace(fingerprint) == "" {
		return errors.New("wrapped keys and fingerprint are required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var count int
	if err := tx.QueryRow(ctx, sqlCountUsers).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("setup is already complete")
	}

	statusValue := strings.TrimSpace(user.Status)
	if statusValue == "" {
		statusValue = "pending"
	}
	if _, err := tx.Exec(
		ctx,
		sqlUpsertServerProfile,
		mode,
		status,
		nullIfEmpty(profile.LinkedMasterID),
		nullIfEmpty(profile.LinkedMasterURL),
		appVersion,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlCreateUser, id, strings.TrimSpace(user.Email), user.PasswordHash, user.MasterPasswordHash, user.IsAdmin, statusValue); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlUpsertUserSyncKey, id, serverWrappedKey, masterWrappedKey, strings.TrimSpace(fingerprint)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlAssignPasswordsToUser, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlAssignNotesToUser, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlAssignTagsToUser, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlAssignGroupsToUser, id); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) GetServerProfile(ctx context.Context) (models.ServerProfile, error) {
	var profile models.ServerProfile
	var linkedMasterID *string
	var linkedMasterURL *string
	var appVersion *string
	err := s.pool.QueryRow(ctx, sqlGetServerProfile).Scan(
		&profile.ServerMode,
		&profile.SyncStatus,
		&linkedMasterID,
		&linkedMasterURL,
		&appVersion,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)
	if err != nil {
		return models.ServerProfile{}, err
	}
	if linkedMasterID != nil {
		profile.LinkedMasterID = *linkedMasterID
	}
	if linkedMasterURL != nil {
		profile.LinkedMasterURL = *linkedMasterURL
	}
	if appVersion != nil {
		profile.AppVersion = *appVersion
	}
	return profile, nil
}

func (s *Store) UpsertControllerLink(ctx context.Context, slaveServerID string, slaveEndpoint string) error {
	slaveServerID = strings.TrimSpace(slaveServerID)
	slaveEndpoint = strings.TrimSpace(slaveEndpoint)
	if slaveServerID == "" || slaveEndpoint == "" {
		return errors.New("slave_server_id and slave_endpoint are required")
	}
	_, err := s.pool.Exec(ctx, sqlUpsertControllerLink, uuid.New(), slaveServerID, slaveEndpoint)
	return err
}

func (s *Store) TouchControllerLinkHandshake(ctx context.Context, slaveServerID string, status string) error {
	slaveServerID = strings.TrimSpace(slaveServerID)
	status = strings.TrimSpace(strings.ToLower(status))
	if slaveServerID == "" {
		return errors.New("slave_server_id is required")
	}
	switch status {
	case "":
		status = "active"
	case "active", "disabled":
	default:
		return errors.New("invalid controller link status")
	}
	_, err := s.pool.Exec(ctx, sqlTouchControllerLinkHandshake, slaveServerID, status)
	return err
}

func (s *Store) ListControllerLinks(ctx context.Context) ([]models.ControllerLink, error) {
	rows, err := s.pool.Query(ctx, sqlListControllerLinks)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ControllerLink
	for rows.Next() {
		var item models.ControllerLink
		if err := rows.Scan(&item.SlaveServerID, &item.SlaveEndpoint, &item.Status, &item.LastHandshakeAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) CleanupControllerLinkDuplicateEndpoints(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, sqlCleanupControllerLinkDuplicateEndpoints)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) IssueControllerSlaveGrant(ctx context.Context, controllerID string, slaveEndpoint string, grantTokenHash string, expiresAt time.Time) error {
	controllerID = strings.TrimSpace(controllerID)
	slaveEndpoint = strings.TrimSpace(slaveEndpoint)
	grantTokenHash = strings.TrimSpace(grantTokenHash)
	if controllerID == "" || slaveEndpoint == "" || grantTokenHash == "" {
		return errors.New("controller_id, slave_endpoint and grant_token_hash are required")
	}
	if expiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	_, err := s.pool.Exec(ctx, sqlInsertControllerSlaveGrant, uuid.New(), controllerID, slaveEndpoint, grantTokenHash, expiresAt.UTC())
	return err
}

func (s *Store) ConsumeControllerSlaveGrant(ctx context.Context, grantTokenHash string) (string, string, time.Time, error) {
	grantTokenHash = strings.TrimSpace(grantTokenHash)
	if grantTokenHash == "" {
		return "", "", time.Time{}, errors.New("grant_token_hash is required")
	}
	var controllerID string
	var slaveEndpoint string
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, sqlConsumeControllerSlaveGrant, grantTokenHash).Scan(&controllerID, &slaveEndpoint, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", time.Time{}, errors.New("controller slave grant is invalid or expired")
		}
		return "", "", time.Time{}, err
	}
	return controllerID, slaveEndpoint, expiresAt, nil
}

func (s *Store) InsertControllerUpdateEvent(ctx context.Context, eventID string, masterServerID string, vaultVersion int64, payloadHash string, status string) (bool, error) {
	eventID = strings.TrimSpace(eventID)
	masterServerID = strings.TrimSpace(masterServerID)
	payloadHash = strings.TrimSpace(payloadHash)
	status = strings.TrimSpace(strings.ToLower(status))
	if eventID == "" || masterServerID == "" {
		return false, errors.New("event_id and master_server_id are required")
	}
	if vaultVersion <= 0 {
		return false, errors.New("vault_version must be positive")
	}
	switch status {
	case "":
		status = "applied"
	case "applied", "acked", "error":
	default:
		return false, errors.New("invalid event status")
	}
	tag, err := s.pool.Exec(ctx, sqlInsertControllerUpdateEvent, eventID, masterServerID, vaultVersion, nullIfEmpty(payloadHash), status)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) ListControllerUpdateEvents(ctx context.Context, limit int) ([]models.ControllerUpdateEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, sqlListControllerUpdateEvents, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ControllerUpdateEvent
	for rows.Next() {
		var item models.ControllerUpdateEvent
		var payloadHash *string
		if err := rows.Scan(&item.EventID, &item.MasterServerID, &item.VaultVersion, &payloadHash, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if payloadHash != nil {
			item.PayloadHash = *payloadHash
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) UpsertControllerRegistry(ctx context.Context, controllerID string) (string, error) {
	controllerID = strings.TrimSpace(controllerID)
	if controllerID == "" {
		return "", errors.New("controller_id is required")
	}
	var status string
	if err := s.pool.QueryRow(ctx, sqlUpsertControllerRegistry, controllerID).Scan(&status); err != nil {
		return "", err
	}
	return status, nil
}

func (s *Store) IssueControllerTokenByID(ctx context.Context, controllerID string, nextTokenHash string) error {
	controllerID = strings.TrimSpace(controllerID)
	nextTokenHash = strings.TrimSpace(nextTokenHash)
	if controllerID == "" || nextTokenHash == "" {
		return errors.New("controller_id and next_token_hash are required")
	}
	tag, err := s.pool.Exec(ctx, sqlIssueControllerTokenByID, controllerID, nextTokenHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("controller is not approved")
	}
	return nil
}

func (s *Store) RotateControllerTokenByID(ctx context.Context, controllerID string, currentTokenHash string, nextTokenHash string) error {
	controllerID = strings.TrimSpace(controllerID)
	currentTokenHash = strings.TrimSpace(currentTokenHash)
	nextTokenHash = strings.TrimSpace(nextTokenHash)
	if controllerID == "" || currentTokenHash == "" || nextTokenHash == "" {
		return errors.New("controller_id, current_token_hash and next_token_hash are required")
	}
	tag, err := s.pool.Exec(ctx, sqlRotateControllerTokenByID, controllerID, currentTokenHash, nextTokenHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("controller token is invalid or controller is inactive")
	}
	return nil
}

func (s *Store) RotateControllerTokenByHash(ctx context.Context, currentTokenHash string, nextTokenHash string) (string, error) {
	currentTokenHash = strings.TrimSpace(currentTokenHash)
	nextTokenHash = strings.TrimSpace(nextTokenHash)
	if currentTokenHash == "" || nextTokenHash == "" {
		return "", errors.New("current_token_hash and next_token_hash are required")
	}
	var controllerID string
	err := s.pool.QueryRow(ctx, sqlRotateControllerTokenByHash, currentTokenHash, nextTokenHash).Scan(&controllerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("controller token is invalid or controller is inactive")
		}
		return "", err
	}
	return controllerID, nil
}

func (s *Store) ListControllerRegistry(ctx context.Context) ([]models.ControllerRegistryEntry, error) {
	rows, err := s.pool.Query(ctx, sqlListControllerRegistry)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ControllerRegistryEntry
	for rows.Next() {
		var item models.ControllerRegistryEntry
		var tokenUpdatedAt *time.Time
		var lastSeenAt *time.Time
		if err := rows.Scan(&item.ControllerID, &item.Status, &item.Weight, &tokenUpdatedAt, &lastSeenAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if tokenUpdatedAt != nil {
			item.TokenUpdatedAt = *tokenUpdatedAt
		}
		if lastSeenAt != nil {
			item.LastSeenAt = *lastSeenAt
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) SetControllerRegistryStatus(ctx context.Context, controllerID string, status string) error {
	controllerID = strings.TrimSpace(controllerID)
	status = strings.TrimSpace(status)
	if controllerID == "" || status == "" {
		return errors.New("controller_id and status are required")
	}
	if status != "active" && status != "disabled" {
		return errors.New("invalid status")
	}
	tag, err := s.pool.Exec(ctx, sqlSetControllerRegistryStatus, controllerID, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("controller is not found")
	}
	return nil
}

func (s *Store) SetControllerRegistryWeight(ctx context.Context, controllerID string, weight int) error {
	controllerID = strings.TrimSpace(controllerID)
	if controllerID == "" {
		return errors.New("controller_id is required")
	}
	if weight < 0 {
		return errors.New("weight must be >= 0")
	}
	tag, err := s.pool.Exec(ctx, sqlSetControllerRegistryWeight, controllerID, weight)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("controller is not found")
	}
	return nil
}

func (s *Store) CleanupStaleControllerRegistry(ctx context.Context, staleBefore time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, sqlCleanupStaleControllerRegistry, staleBefore)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) CreateUser(ctx context.Context, user models.User) error {
	id, err := parseOrNewUUID(user.ID)
	if err != nil {
		return err
	}
	status := strings.TrimSpace(user.Status)
	if status == "" {
		status = "pending"
	}
	_, err = s.pool.Exec(ctx, sqlCreateUser, id, user.Email, user.PasswordHash, user.MasterPasswordHash, user.IsAdmin, status)
	return err
}

func (s *Store) UpsertUserReplica(ctx context.Context, user models.User) error {
	id, err := uuid.Parse(strings.TrimSpace(user.ID))
	if err != nil {
		return err
	}
	email := strings.TrimSpace(user.Email)
	if email == "" {
		return errors.New("email required")
	}
	status := strings.TrimSpace(strings.ToLower(user.Status))
	if status == "" {
		status = "active"
	}
	if status != "pending" && status != "active" {
		return errors.New("invalid status")
	}
	if strings.TrimSpace(user.PasswordHash) == "" || strings.TrimSpace(user.MasterPasswordHash) == "" {
		return errors.New("password hashes required")
	}
	_, err = s.pool.Exec(ctx, sqlUpsertUserReplica, id, email, user.PasswordHash, user.MasterPasswordHash, user.IsAdmin, status)
	return err
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	var user models.User
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, sqlGetUserByEmail, email).Scan(&id, &user.Email, &user.Status, &user.PasswordHash, &user.MasterPasswordHash, &user.IsAdmin, &user.CreatedAt)
	if err != nil {
		return models.User{}, err
	}
	user.ID = id.String()
	return user, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (models.User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return models.User{}, err
	}
	var user models.User
	var userID uuid.UUID
	err = s.pool.QueryRow(ctx, sqlGetUserByID, uid).Scan(&userID, &user.Email, &user.Status, &user.PasswordHash, &user.MasterPasswordHash, &user.IsAdmin, &user.CreatedAt)
	if err != nil {
		return models.User{}, err
	}
	user.ID = userID.String()
	return user, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]models.User, error) {
	rows, err := s.pool.Query(ctx, sqlListUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.User
	for rows.Next() {
		var user models.User
		var id uuid.UUID
		if err := rows.Scan(&id, &user.Email, &user.Status, &user.IsAdmin, &user.CreatedAt); err != nil {
			return nil, err
		}
		user.ID = id.String()
		out = append(out, user)
	}
	return out, rows.Err()
}

func (s *Store) ListActiveUsersExcept(ctx context.Context, userID string) ([]models.User, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListActiveUsersExcept, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.User
	for rows.Next() {
		var user models.User
		var id uuid.UUID
		if err := rows.Scan(&id, &user.Email, &user.Status, &user.IsAdmin, &user.CreatedAt); err != nil {
			return nil, err
		}
		user.ID = id.String()
		out = append(out, user)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUserCredentials(ctx context.Context, userID string, loginHash *string, masterHash *string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlUpdateUserCredentials, uid, loginHash, masterHash)
	return err
}

func (s *Store) UpdateUserRole(ctx context.Context, userID string, isAdmin bool) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, sqlUpdateUserRole, uid, isAdmin)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("user not found")
	}
	return nil
}

func (s *Store) SetUserStatus(ctx context.Context, userID string, status string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlSetUserStatus, uid, strings.TrimSpace(status))
	return err
}

func (s *Store) CreateSession(ctx context.Context, session models.Session) error {
	id, err := parseOrNewUUID(session.ID)
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(session.UserID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlCreateSession, id, userID, session.ExpiresAt)
	return err
}

func (s *Store) GetSession(ctx context.Context, sessionID string) (models.Session, error) {
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return models.Session{}, err
	}
	var sess models.Session
	var id uuid.UUID
	var userID uuid.UUID
	err = s.pool.QueryRow(ctx, sqlGetSession, sid).Scan(&id, &userID, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return models.Session{}, err
	}
	sess.ID = id.String()
	sess.UserID = userID.String()
	return sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlDeleteSession, sid)
	return err
}

func (s *Store) AssignUnownedToUser(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlAssignPasswordsToUser, uid)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlAssignNotesToUser, uid)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlAssignTagsToUser, uid)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlAssignGroupsToUser, uid)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) GetNote(ctx context.Context, cryptoSvc *crypto.Service, id string, userID string) (models.SecureNote, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return models.SecureNote{}, err
	}
	viewerID, err := uuid.Parse(userID)
	if err != nil {
		return models.SecureNote{}, err
	}
	var note models.SecureNote
	var ownerEmail string
	var bodyEnc []byte
	var importSource *string
	var importRaw []byte
	var tags string
	var groups string
	err = s.pool.QueryRow(ctx, sqlGetNote, uid, viewerID).Scan(&note.ID, &note.UserID, &ownerEmail, &note.Title, &bodyEnc, &note.CreatedAt, &note.UpdatedAt, &importSource, &importRaw, &tags, &groups)
	if err != nil {
		return models.SecureNote{}, err
	}
	note.OwnerEmail = ownerEmail
	body, err := cryptoSvc.Decrypt(bodyEnc)
	if err != nil {
		return models.SecureNote{}, err
	}
	note.Body = body
	note.Tags = splitTags(tags)
	note.Groups = splitTags(groups)
	if importSource != nil {
		note.ImportSource = *importSource
	}
	if len(importRaw) > 0 {
		note.ImportRaw = string(importRaw)
	}
	return note, nil
}

func (s *Store) UpdateNote(ctx context.Context, cryptoSvc *crypto.Service, note models.SecureNote) error {
	if note.ID == "" || note.Title == "" || note.Body == "" {
		return errors.New("missing id, title, or body")
	}
	uid, err := uuid.Parse(note.ID)
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(note.UserID)
	if err != nil {
		return err
	}
	bodyEnc, err := cryptoSvc.Encrypt(note.Body)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, sqlUpdateNote, uid, note.Title, bodyEnc, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("note not found")
	}
	if _, err := tx.Exec(ctx, sqlDeleteNoteTagsByNoteID, uid); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlDeleteNoteGroupEntriesByNoteID, uid); err != nil {
		return err
	}
	for _, tagName := range normalizeTags(note.Tags) {
		tagID, err := ensureTag(ctx, tx, userID, tagName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertNoteTag, uid, tagID); err != nil {
			return err
		}
	}
	for _, groupName := range normalizeTags(note.Groups) {
		groupID, err := ensureGroup(ctx, tx, userID, groupName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertNoteGroupEntry, groupID, uid); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteNote(ctx context.Context, userID, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlDeleteNote, uid, userUUID)
	return err
}

func (s *Store) ListPasswordsByTagName(ctx context.Context, userID, name string) ([]models.PasswordEntry, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListPasswordsByTagName, uid, strings.TrimSpace(name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []models.PasswordEntry
	for rows.Next() {
		var item models.PasswordEntry
		var id uuid.UUID
		var ownerID uuid.UUID
		if err := rows.Scan(&id, &ownerID, &item.OwnerEmail, &item.Title, &item.Username, &item.URL); err != nil {
			return nil, err
		}
		item.ID = id.String()
		item.UserID = ownerID.String()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListNotesByTagName(ctx context.Context, userID, name string) ([]models.SecureNote, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListNotesByTagName, uid, strings.TrimSpace(name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []models.SecureNote
	for rows.Next() {
		var item models.SecureNote
		var id uuid.UUID
		var ownerID uuid.UUID
		if err := rows.Scan(&id, &ownerID, &item.OwnerEmail, &item.Title, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.ID = id.String()
		item.UserID = ownerID.String()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListPasswordsByGroupName(ctx context.Context, userID, name string) ([]models.PasswordEntry, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListPasswordsByGroupName, uid, strings.TrimSpace(name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []models.PasswordEntry
	for rows.Next() {
		var item models.PasswordEntry
		var id uuid.UUID
		var ownerID uuid.UUID
		if err := rows.Scan(&id, &ownerID, &item.OwnerEmail, &item.Title, &item.Username, &item.URL); err != nil {
			return nil, err
		}
		item.ID = id.String()
		item.UserID = ownerID.String()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListNotesByGroupName(ctx context.Context, userID, name string) ([]models.SecureNote, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListNotesByGroupName, uid, strings.TrimSpace(name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []models.SecureNote
	for rows.Next() {
		var item models.SecureNote
		var id uuid.UUID
		var ownerID uuid.UUID
		if err := rows.Scan(&id, &ownerID, &item.OwnerEmail, &item.Title, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.ID = id.String()
		item.UserID = ownerID.String()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) SharePasswordWithUser(ctx context.Context, ownerUserID, entryID, targetEmail string) error {
	ownerID, err := uuid.Parse(ownerUserID)
	if err != nil {
		return err
	}
	entryUUID, err := uuid.Parse(entryID)
	if err != nil {
		return err
	}
	owns := false
	if err := s.pool.QueryRow(ctx, sqlCheckPasswordOwner, entryUUID, ownerID).Scan(&owns); err != nil {
		return err
	}
	if !owns {
		return errors.New("password not found")
	}
	target, err := s.GetActiveUserByEmail(ctx, targetEmail)
	if err != nil {
		return errors.New("active user not found")
	}
	if target.ID == ownerUserID {
		return errors.New("cannot share with yourself")
	}
	targetID, err := uuid.Parse(target.ID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlInsertPasswordShare, entryUUID, targetID)
	return err
}

func (s *Store) UnsharePasswordForUser(ctx context.Context, entryID, userID string) error {
	entryUUID, err := uuid.Parse(entryID)
	if err != nil {
		return err
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, sqlDeletePasswordShareForUser, entryUUID, userUUID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("shared access not found")
	}
	return nil
}

func (s *Store) UpsertPasswordShareByIDs(ctx context.Context, entryID, userID string) error {
	entryUUID, err := uuid.Parse(strings.TrimSpace(entryID))
	if err != nil {
		return err
	}
	userUUID, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlInsertPasswordShare, entryUUID, userUUID)
	return err
}

func (s *Store) ShareNoteWithUser(ctx context.Context, ownerUserID, noteID, targetEmail string) error {
	ownerID, err := uuid.Parse(ownerUserID)
	if err != nil {
		return err
	}
	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return err
	}
	owns := false
	if err := s.pool.QueryRow(ctx, sqlCheckNoteOwner, noteUUID, ownerID).Scan(&owns); err != nil {
		return err
	}
	if !owns {
		return errors.New("note not found")
	}
	target, err := s.GetActiveUserByEmail(ctx, targetEmail)
	if err != nil {
		return errors.New("active user not found")
	}
	if target.ID == ownerUserID {
		return errors.New("cannot share with yourself")
	}
	targetID, err := uuid.Parse(target.ID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlInsertNoteShare, noteUUID, targetID)
	return err
}

func (s *Store) UpsertNoteShareByIDs(ctx context.Context, noteID, userID string) error {
	noteUUID, err := uuid.Parse(strings.TrimSpace(noteID))
	if err != nil {
		return err
	}
	userUUID, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlInsertNoteShare, noteUUID, userUUID)
	return err
}

func (s *Store) ListPasswordShareEmails(ctx context.Context, entryID string) ([]string, error) {
	uid, err := uuid.Parse(entryID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListPasswordShareEmails, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		out = append(out, email)
	}
	return out, rows.Err()
}

func (s *Store) ListNoteShareEmails(ctx context.Context, noteID string) ([]string, error) {
	uid, err := uuid.Parse(noteID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListNoteShareEmails, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		out = append(out, email)
	}
	return out, rows.Err()
}

func (s *Store) GetActiveUserByEmail(ctx context.Context, email string) (models.User, error) {
	var user models.User
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, sqlGetActiveUserByEmail, strings.TrimSpace(email)).Scan(&id, &user.Email, &user.Status, &user.PasswordHash, &user.MasterPasswordHash, &user.IsAdmin, &user.CreatedAt)
	if err != nil {
		return models.User{}, err
	}
	user.ID = id.String()
	return user, nil
}

func (s *Store) SendInternalMessage(ctx context.Context, fromUserID string, toEmail string, body string) error {
	fromUUID, err := uuid.Parse(fromUserID)
	if err != nil {
		return err
	}
	trimmedBody := strings.TrimSpace(body)
	if trimmedBody == "" {
		return errors.New("message body is required")
	}
	if len(trimmedBody) > 300 {
		return errors.New("message must be 300 characters or less")
	}
	var toUUID uuid.UUID
	if err := s.pool.QueryRow(ctx, sqlFindActiveUserIDByEmail, strings.TrimSpace(toEmail)).Scan(&toUUID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("active recipient not found")
		}
		return err
	}
	if fromUUID == toUUID {
		return errors.New("cannot send message to yourself")
	}
	_, err = s.pool.Exec(ctx, sqlInsertInternalMessage, uuid.New(), fromUUID, toUUID, trimmedBody)
	return err
}

func (s *Store) ListInboxMessages(ctx context.Context, userID string, limit int) ([]models.InternalMessage, error) {
	if limit <= 0 {
		limit = 100
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListInboxMessages, userUUID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.InternalMessage
	for rows.Next() {
		var item models.InternalMessage
		var id, fromID, toID uuid.UUID
		var readAt *time.Time
		if err := rows.Scan(&id, &fromID, &item.FromEmail, &toID, &item.ToEmail, &item.Body, &readAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.ID = id.String()
		item.FromUserID = fromID.String()
		item.ToUserID = toID.String()
		if readAt != nil {
			item.ReadAt = *readAt
			item.IsRead = true
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListSentMessages(ctx context.Context, userID string, limit int) ([]models.InternalMessage, error) {
	if limit <= 0 {
		limit = 100
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListSentMessages, userUUID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.InternalMessage
	for rows.Next() {
		var item models.InternalMessage
		var id, fromID, toID uuid.UUID
		var readAt *time.Time
		if err := rows.Scan(&id, &fromID, &item.FromEmail, &toID, &item.ToEmail, &item.Body, &readAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.ID = id.String()
		item.FromUserID = fromID.String()
		item.ToUserID = toID.String()
		if readAt != nil {
			item.ReadAt = *readAt
			item.IsRead = true
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) MarkMessageRead(ctx context.Context, userID, messageID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	messageUUID, err := uuid.Parse(messageID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlMarkMessageRead, messageUUID, userUUID)
	return err
}

func (s *Store) CountUnreadMessages(ctx context.Context, userID string) (int, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return 0, err
	}
	var count int
	if err := s.pool.QueryRow(ctx, sqlCountUnreadMessages, userUUID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) UpsertUserSyncKey(ctx context.Context, userID string, serverWrappedKey []byte, masterWrappedKey []byte, fingerprint string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	if len(serverWrappedKey) == 0 || len(masterWrappedKey) == 0 || strings.TrimSpace(fingerprint) == "" {
		return errors.New("wrapped keys and fingerprint are required")
	}
	_, err = s.pool.Exec(ctx, sqlUpsertUserSyncKey, userUUID, serverWrappedKey, masterWrappedKey, strings.TrimSpace(fingerprint))
	return err
}

func (s *Store) GetUserSyncKey(ctx context.Context, userID string) ([]byte, []byte, string, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, nil, "", err
	}
	var serverWrapped []byte
	var masterWrapped []byte
	var fingerprint string
	var createdAt time.Time
	var updatedAt time.Time
	err = s.pool.QueryRow(ctx, sqlGetUserSyncKey, userUUID).Scan(&serverWrapped, &masterWrapped, &fingerprint, &createdAt, &updatedAt)
	if err != nil {
		return nil, nil, "", err
	}
	return serverWrapped, masterWrapped, fingerprint, nil
}

func (s *Store) InsertPendingSyncBundle(ctx context.Context, bundle models.PendingSyncBundle, ciphertext []byte) (bool, error) {
	id, err := parseOrNewUUID(bundle.ID)
	if err != nil {
		return false, err
	}
	userUUID, err := uuid.Parse(bundle.UserID)
	if err != nil {
		return false, err
	}
	if len(ciphertext) == 0 {
		return false, errors.New("ciphertext is required")
	}
	tag, err := s.pool.Exec(ctx, sqlInsertPendingSyncBundle, id, userUUID, strings.TrimSpace(bundle.MasterServerID), strings.TrimSpace(bundle.MasterServerURL), strings.TrimSpace(bundle.BundleType), strings.TrimSpace(bundle.PayloadHash), ciphertext)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) RestoreBackup(ctx context.Context, cryptoSvc *crypto.Service, userID string, passwords []models.PasswordEntry, notes []models.SecureNote) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, entry := range passwords {
		if entry.Title == "" || entry.Password == "" {
			return errors.New("backup contains password entry with missing title or password")
		}
		entryID, err := parseOrNewUUID(entry.ID)
		if err != nil {
			return err
		}
		passEnc, err := cryptoSvc.Encrypt(entry.Password)
		if err != nil {
			return err
		}
		var notesEnc []byte
		if entry.Notes != "" {
			notesEnc, err = cryptoSvc.Encrypt(entry.Notes)
			if err != nil {
				return err
			}
		}
		entry.UserID = userID
		if err := upsertPasswordTx(ctx, tx, userUUID, entryID, entry, passEnc, notesEnc); err != nil {
			return err
		}
	}

	for _, note := range notes {
		if note.Title == "" || note.Body == "" {
			return errors.New("backup contains secure note with missing title or body")
		}
		noteID, err := parseOrNewUUID(note.ID)
		if err != nil {
			return err
		}
		bodyEnc, err := cryptoSvc.Encrypt(note.Body)
		if err != nil {
			return err
		}
		note.UserID = userID
		if err := upsertNoteTx(ctx, tx, userUUID, noteID, note, bodyEnc); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *Store) ListPendingSyncBundles(ctx context.Context, userID string) ([]models.PendingSyncBundle, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, sqlListPendingSyncBundles, userUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.PendingSyncBundle
	for rows.Next() {
		var item models.PendingSyncBundle
		var id uuid.UUID
		var uid uuid.UUID
		var appliedAt *time.Time
		if err := rows.Scan(&id, &uid, &item.MasterServerID, &item.MasterServerURL, &item.BundleType, &item.PayloadHash, &item.Status, &item.Error, &item.CreatedAt, &appliedAt); err != nil {
			return nil, err
		}
		item.ID = id.String()
		item.UserID = uid.String()
		if appliedAt != nil {
			item.AppliedAt = *appliedAt
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetPendingSyncBundleForUser(ctx context.Context, userID string, bundleID string) (models.PendingSyncBundle, []byte, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return models.PendingSyncBundle{}, nil, err
	}
	idUUID, err := uuid.Parse(bundleID)
	if err != nil {
		return models.PendingSyncBundle{}, nil, err
	}
	var item models.PendingSyncBundle
	var id uuid.UUID
	var uid uuid.UUID
	var ciphertext []byte
	var appliedAt *time.Time
	err = s.pool.QueryRow(ctx, sqlGetPendingSyncBundleForUser, idUUID, userUUID).Scan(&id, &uid, &item.MasterServerID, &item.MasterServerURL, &item.BundleType, &item.PayloadHash, &ciphertext, &item.Status, &item.Error, &item.CreatedAt, &appliedAt)
	if err != nil {
		return models.PendingSyncBundle{}, nil, err
	}
	item.ID = id.String()
	item.UserID = uid.String()
	if appliedAt != nil {
		item.AppliedAt = *appliedAt
	}
	return item, ciphertext, nil
}

func (s *Store) MarkPendingSyncBundleApplied(ctx context.Context, userID string, bundleID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	idUUID, err := uuid.Parse(bundleID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlMarkPendingSyncBundleApplied, idUUID, userUUID)
	return err
}

func (s *Store) MarkPendingSyncBundleFailed(ctx context.Context, userID string, bundleID string, reason string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	idUUID, err := uuid.Parse(bundleID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlMarkPendingSyncBundleFailed, idUUID, userUUID, strings.TrimSpace(reason))
	return err
}

func (s *Store) CreatePasswordShareLink(ctx context.Context, token string, entryID string, createdBy string, expiresAt time.Time) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("token required")
	}
	entryUUID, err := uuid.Parse(entryID)
	if err != nil {
		return err
	}
	creatorUUID, err := uuid.Parse(createdBy)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlCreatePasswordShareLink, token, entryUUID, creatorUUID, expiresAt)
	return err
}

func (s *Store) GetPasswordShareLinkByToken(ctx context.Context, token string) (models.PasswordShareLink, error) {
	var link models.PasswordShareLink
	var entryID uuid.UUID
	var createdBy uuid.UUID
	err := s.pool.QueryRow(ctx, sqlGetPasswordShareLinkByToken, strings.TrimSpace(token)).Scan(&link.Token, &entryID, &createdBy, &link.CreatedAt, &link.ExpiresAt)
	if err != nil {
		return models.PasswordShareLink{}, err
	}
	link.EntryID = entryID.String()
	link.CreatedBy = createdBy.String()
	return link, nil
}

func (s *Store) GetPasswordForShare(ctx context.Context, cryptoSvc *crypto.Service, id string) (models.PasswordEntry, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	var entry models.PasswordEntry
	var ownerEmail string
	var passEnc []byte
	var notesEnc []byte
	var tags string
	var groups string
	err = s.pool.QueryRow(ctx, sqlGetPasswordForShare, uid).Scan(&entry.ID, &entry.UserID, &ownerEmail, &entry.Title, &entry.Username, &passEnc, &entry.URL, &notesEnc, &tags, &groups)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	entry.OwnerEmail = ownerEmail
	password, err := cryptoSvc.Decrypt(passEnc)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	entry.Password = password
	if len(notesEnc) > 0 {
		notes, err := cryptoSvc.Decrypt(notesEnc)
		if err != nil {
			return models.PasswordEntry{}, err
		}
		entry.Notes = notes
	}
	entry.Tags = splitTags(tags)
	entry.Groups = splitTags(groups)
	return entry, nil
}

func (s *Store) ClearTagsForRecord(ctx context.Context, recordID string) (int64, error) {
	uid, err := uuid.Parse(recordID)
	if err != nil {
		return 0, err
	}
	pwTag, err := s.pool.Exec(ctx, sqlClearPasswordTagsByRecordID, uid)
	if err != nil {
		return 0, err
	}
	noteTag, err := s.pool.Exec(ctx, sqlClearNoteTagsByRecordID, uid)
	if err != nil {
		return 0, err
	}
	return pwTag.RowsAffected() + noteTag.RowsAffected(), nil
}

func (s *Store) ClearGroupsForRecord(ctx context.Context, recordID string) (int64, error) {
	uid, err := uuid.Parse(recordID)
	if err != nil {
		return 0, err
	}
	pwGroup, err := s.pool.Exec(ctx, sqlClearPasswordGroupsByRecordID, uid)
	if err != nil {
		return 0, err
	}
	noteGroup, err := s.pool.Exec(ctx, sqlClearNoteGroupsByRecordID, uid)
	if err != nil {
		return 0, err
	}
	return pwGroup.RowsAffected() + noteGroup.RowsAffected(), nil
}

func (s *Store) ClearAllTags(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, sqlClearAllTags)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) ClearAllGroups(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, sqlClearAllGroups)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) RenameTagByID(ctx context.Context, userID, tagID, newName string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	tid, err := uuid.Parse(strings.TrimSpace(tagID))
	if err != nil {
		return err
	}
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return errors.New("new tag name is required")
	}
	tag, err := s.pool.Exec(ctx, sqlRenameTagByID, uid, tid, newName)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("tag not found")
	}
	return nil
}

func (s *Store) DeleteTagByID(ctx context.Context, userID, tagID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	tid, err := uuid.Parse(strings.TrimSpace(tagID))
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, sqlDeleteTagByID, uid, tid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("tag not found")
	}
	return nil
}

func (s *Store) RenameGroupByID(ctx context.Context, userID, groupID, newName string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	gid, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return err
	}
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return errors.New("new group name is required")
	}
	tag, err := s.pool.Exec(ctx, sqlRenameGroupByID, uid, gid, newName)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("group not found")
	}
	return nil
}

func (s *Store) DeleteGroupByID(ctx context.Context, userID, groupID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	gid, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, sqlDeleteGroupByID, uid, gid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("group not found")
	}
	return nil
}

func parseOrNewUUID(value string) (uuid.UUID, error) {
	if value == "" {
		return uuid.New(), nil
	}
	parsed, err := uuid.Parse(value)
	if err != nil {
		// 1Password UUIDs are not standard RFC4122; derive a stable UUID instead.
		return uuid.NewSHA1(uuid.NameSpaceOID, []byte(value)), nil
	}
	return parsed, nil
}

func upsertPasswordTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, id uuid.UUID, entry models.PasswordEntry, passEnc []byte, notesEnc []byte) error {
	createdAt := nullTime(entry.CreatedAt)
	updatedAt := nullTime(entry.UpdatedAt)
	importSource := nullIfEmpty(entry.ImportSource)
	importRaw := nullIfEmpty(entry.ImportRaw)
	if _, err := tx.Exec(ctx, sqlUpsertPassword, id, userID, entry.Title, entry.Username, passEnc, entry.URL, notesEnc, importSource, importRaw, createdAt, updatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlDeleteEntryTagsByEntryID, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlDeleteGroupEntriesByEntryID, id); err != nil {
		return err
	}
	for _, tagName := range normalizeTags(entry.Tags) {
		tagID, err := ensureTag(ctx, tx, userID, tagName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertEntryTag, id, tagID); err != nil {
			return err
		}
	}
	for _, groupName := range normalizeTags(entry.Groups) {
		groupID, err := ensureGroup(ctx, tx, userID, groupName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertGroupEntry, groupID, id); err != nil {
			return err
		}
	}
	return nil
}

func upsertNoteTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, id uuid.UUID, note models.SecureNote, bodyEnc []byte) error {
	createdAt := nullTime(note.CreatedAt)
	updatedAt := nullTime(note.UpdatedAt)
	importSource := nullIfEmpty(note.ImportSource)
	importRaw := nullIfEmpty(note.ImportRaw)
	if _, err := tx.Exec(ctx, sqlUpsertSecureNote, id, userID, note.Title, bodyEnc, importSource, importRaw, createdAt, updatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlDeleteNoteTagsByNoteID, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlDeleteNoteGroupEntriesByNoteID, id); err != nil {
		return err
	}
	for _, tagName := range normalizeTags(note.Tags) {
		tagID, err := ensureTag(ctx, tx, userID, tagName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertNoteTag, id, tagID); err != nil {
			return err
		}
	}
	for _, groupName := range normalizeTags(note.Groups) {
		groupID, err := ensureGroup(ctx, tx, userID, groupName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sqlInsertNoteGroupEntry, groupID, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ResolveExternalID(value string) (uuid.UUID, error) {
	return parseOrNewUUID(value)
}

func (s *Store) ExistsPassword(ctx context.Context, userID uuid.UUID, id uuid.UUID) (bool, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, sqlExistsPassword, id, userID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *Store) ExistsNote(ctx context.Context, userID uuid.UUID, id uuid.UUID) (bool, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, sqlExistsNote, id, userID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func ensureTag(ctx context.Context, tx pgx.Tx, userID uuid.UUID, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := tx.Exec(ctx, sqlEnsureTagInsert, id, userID, name)
	if err != nil {
		return uuid.UUID{}, err
	}
	var existing uuid.UUID
	if err := tx.QueryRow(ctx, sqlEnsureTagSelect, name, userID).Scan(&existing); err != nil {
		return uuid.UUID{}, err
	}
	return existing, nil
}

func ensureGroup(ctx context.Context, tx pgx.Tx, userID uuid.UUID, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := tx.Exec(ctx, sqlEnsureGroupInsert, id, userID, name)
	if err != nil {
		return uuid.UUID{}, err
	}
	var existing uuid.UUID
	if err := tx.QueryRow(ctx, sqlEnsureGroupSelect, name, userID).Scan(&existing); err != nil {
		return uuid.UUID{}, err
	}
	return existing, nil
}

func normalizeTags(tags []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range tags {
		trim := strings.TrimSpace(t)
		if trim == "" {
			continue
		}
		key := strings.ToLower(trim)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, trim)
	}
	return out
}

func splitTags(value string) []string {
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
