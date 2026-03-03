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

	createdAt := nullTime(entry.CreatedAt)
	updatedAt := nullTime(entry.UpdatedAt)
	importSource := nullIfEmpty(entry.ImportSource)
	importRaw := nullIfEmpty(entry.ImportRaw)
	_, err = tx.Exec(ctx, sqlUpsertPassword, id, userID, entry.Title, entry.Username, passEnc, entry.URL, notesEnc, importSource, importRaw, createdAt, updatedAt)
	if err != nil {
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
		var title, username, url, tags, groups string
		if err := rows.Scan(&id, &title, &username, &url, &tags, &groups); err != nil {
			return nil, err
		}
		items = append(items, models.PasswordEntry{
			ID:       id.String(),
			Title:    title,
			Username: username,
			URL:      url,
			Tags:     splitTags(tags),
			Groups:   splitTags(groups),
		})
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

func (s *Store) GetPassword(ctx context.Context, cryptoSvc *crypto.Service, id string) (models.PasswordEntry, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	var entry models.PasswordEntry
	var passEnc, notesEnc []byte
	var tags string
	var groups string
	var importSource *string
	var importRaw []byte
	err = s.pool.QueryRow(ctx, sqlGetPassword, uid).Scan(&entry.ID, &entry.UserID, &entry.Title, &entry.Username, &passEnc, &entry.URL, &notesEnc, &importSource, &importRaw, &tags, &groups)
	if err != nil {
		return models.PasswordEntry{}, err
	}
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

	_, err = tx.Exec(ctx, sqlUpdatePassword, uid, entry.Title, entry.Username, passEnc, entry.URL, notesEnc, userID)
	if err != nil {
		return err
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

	createdAt := nullTime(note.CreatedAt)
	updatedAt := nullTime(note.UpdatedAt)
	importSource := nullIfEmpty(note.ImportSource)
	importRaw := nullIfEmpty(note.ImportRaw)
	_, err = tx.Exec(ctx, sqlUpsertSecureNote, id, userID, note.Title, bodyEnc, importSource, importRaw, createdAt, updatedAt)
	if err != nil {
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
		var title, tags, groups string
		var updated time.Time
		if err := rows.Scan(&id, &title, &updated, &tags, &groups); err != nil {
			return nil, err
		}
		items = append(items, models.SecureNote{
			ID:        id.String(),
			Title:     title,
			Tags:      splitTags(tags),
			Groups:    splitTags(groups),
			UpdatedAt: updated,
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

func (s *Store) CreateUser(ctx context.Context, user models.User) error {
	id, err := parseOrNewUUID(user.ID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, sqlCreateUser, id, user.Email, user.PasswordHash, user.MasterPasswordHash, user.IsAdmin)
	return err
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	var user models.User
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, sqlGetUserByEmail, email).Scan(&id, &user.Email, &user.PasswordHash, &user.MasterPasswordHash, &user.IsAdmin, &user.CreatedAt)
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
	err = s.pool.QueryRow(ctx, sqlGetUserByID, uid).Scan(&userID, &user.Email, &user.PasswordHash, &user.MasterPasswordHash, &user.IsAdmin, &user.CreatedAt)
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
		if err := rows.Scan(&id, &user.Email, &user.IsAdmin, &user.CreatedAt); err != nil {
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

func (s *Store) GetNote(ctx context.Context, cryptoSvc *crypto.Service, id string) (models.SecureNote, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return models.SecureNote{}, err
	}
	var note models.SecureNote
	var bodyEnc []byte
	var importSource *string
	var importRaw []byte
	var tags string
	var groups string
	err = s.pool.QueryRow(ctx, sqlGetNote, uid).Scan(&note.ID, &note.UserID, &note.Title, &bodyEnc, &note.CreatedAt, &note.UpdatedAt, &importSource, &importRaw, &tags, &groups)
	if err != nil {
		return models.SecureNote{}, err
	}
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

	_, err = tx.Exec(ctx, sqlUpdateNote, uid, note.Title, bodyEnc, userID)
	if err != nil {
		return err
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
