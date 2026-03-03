package importer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"password-manager-go/internal/crypto"
	"password-manager-go/internal/db"
	"password-manager-go/internal/models"
)

type Result struct {
	Passwords int
	Notes     int
	Skipped   int
	Existing  int
	New       int
}

type pifItem struct {
	UUID         string `json:"uuid"`
	Title        string `json:"title"`
	TypeName     string `json:"typeName"`
	Location     string `json:"location"`
	UpdatedAt    int64  `json:"updatedAt"`
	CreatedAt    int64  `json:"createdAt"`
	OpenContents struct {
		Tags []string `json:"tags"`
	} `json:"openContents"`
	SecureFields struct {
		Password        string `json:"password"`
		Fields          []pifField `json:"fields"`
		URLs            []pifURL `json:"URLs"`
		PasswordHistory []pifHistory `json:"passwordHistory"`
		NotesPlain      string `json:"notesPlain"`
		Email           string `json:"email"`
		Firstname       string `json:"firstname"`
		Lastname        string `json:"lastname"`
		Sections        []pifSection `json:"sections"`
	} `json:"secureContents"`
}

type pifField struct {
	Value       string `json:"value"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Designation string `json:"designation"`
}

type pifURL struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type pifHistory struct {
	Value string `json:"value"`
	Time  int64  `json:"time"`
}

type pifSection struct {
	Name   string      `json:"name"`
	Title  string      `json:"title"`
	Fields []pifSField `json:"fields"`
}

type pifSField struct {
	K string                 `json:"k"`
	N string                 `json:"n"`
	T string                 `json:"t"`
	V any                    `json:"v"`
	A map[string]any         `json:"a"`
}

func ImportPIF(ctx context.Context, r io.Reader, store *db.Store, cryptoSvc *crypto.Service, runID string, userID string) (Result, error) {
	if store == nil || cryptoSvc == nil {
		return Result{}, errors.New("store or crypto service not set")
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return Result{}, err
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 5*1024*1024)
	result := Result{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "***") {
			continue
		}
		raw := line
		var item pifItem
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			result.Skipped++
			_ = store.InsertImportIssue(ctx, models.ImportIssue{
				ImportRunID: runID,
				Source:      "1pif",
				Reason:      "invalid json",
				Raw:         raw,
			})
			continue
		}

		switch item.TypeName {
		case "passwords.Password":
			password := item.SecureFields.Password
			if password == "" {
				result.Skipped++
				_ = store.InsertImportIssue(ctx, models.ImportIssue{
					ImportRunID: runID,
					Source:      "1pif",
					TypeName:    item.TypeName,
					Title:       item.Title,
					ExternalUUID: item.UUID,
					Reason:      "missing password",
					Raw:         raw,
				})
				continue
			}
			if id, err := store.ResolveExternalID(item.UUID); err == nil {
				if exists, err := store.ExistsPassword(ctx, userUUID, id); err == nil && exists {
					result.Existing++
				} else if err == nil {
					result.New++
				}
			}
			entry := models.PasswordEntry{
				ID:       item.UUID,
				UserID:   userID,
				Title:    item.Title,
				Password: password,
				Tags:     item.OpenContents.Tags,
				ImportSource: "1pif",
				ImportRaw: raw,
			}
			applyTimestamps(&entry.CreatedAt, &entry.UpdatedAt, item.CreatedAt, item.UpdatedAt)
			if err := store.UpsertPassword(ctx, cryptoSvc, entry); err != nil {
				return result, err
			}
			result.Passwords++
		case "webforms.WebForm":
			username, password := extractUserPass(item.SecureFields.Fields)
			if password == "" {
				result.Skipped++
				_ = store.InsertImportIssue(ctx, models.ImportIssue{
					ImportRunID: runID,
					Source:      "1pif",
					TypeName:    item.TypeName,
					Title:       item.Title,
					ExternalUUID: item.UUID,
					Reason:      "missing password field",
					Raw:         raw,
				})
				continue
			}
			if id, err := store.ResolveExternalID(item.UUID); err == nil {
				if exists, err := store.ExistsPassword(ctx, userUUID, id); err == nil && exists {
					result.Existing++
				} else if err == nil {
					result.New++
				}
			}
			url := item.Location
			if url == "" && len(item.SecureFields.URLs) > 0 {
				url = item.SecureFields.URLs[0].URL
			}
			entry := models.PasswordEntry{
				ID:       item.UUID,
				UserID:   userID,
				Title:    item.Title,
				Username: username,
				Password: password,
				URL:      url,
				Tags:     item.OpenContents.Tags,
				ImportSource: "1pif",
				ImportRaw: raw,
			}
			applyTimestamps(&entry.CreatedAt, &entry.UpdatedAt, item.CreatedAt, item.UpdatedAt)
			if extra := buildSectionNotes(item.SecureFields.Sections); extra != "" {
				if entry.Notes != "" {
					entry.Notes += "\n"
				}
				entry.Notes += extra
			}
			// TODO: map passwordHistory to archived passwords when schema supports it.
			if err := store.UpsertPassword(ctx, cryptoSvc, entry); err != nil {
				return result, err
			}
			result.Passwords++
		case "identities.Identity":
			body := buildIdentityNote(item)
			if body == "" {
				result.Skipped++
				_ = store.InsertImportIssue(ctx, models.ImportIssue{
					ImportRunID: runID,
					Source:      "1pif",
					TypeName:    item.TypeName,
					Title:       item.Title,
					ExternalUUID: item.UUID,
					Reason:      "empty identity body",
					Raw:         raw,
				})
				continue
			}
			if id, err := store.ResolveExternalID(item.UUID); err == nil {
				if exists, err := store.ExistsNote(ctx, userUUID, id); err == nil && exists {
					result.Existing++
				} else if err == nil {
					result.New++
				}
			}
			note := models.SecureNote{
				ID:    item.UUID,
				UserID: userID,
				Title: item.Title,
				Body:  body,
				ImportSource: "1pif",
				ImportRaw: raw,
			}
			applyTimestamps(&note.CreatedAt, &note.UpdatedAt, item.CreatedAt, item.UpdatedAt)
			if err := store.InsertSecureNote(ctx, cryptoSvc, note); err != nil {
				return result, err
			}
			result.Notes++
		case "securenotes.SecureNote":
			body := item.SecureFields.NotesPlain
			if strings.TrimSpace(body) == "" {
				result.Skipped++
				_ = store.InsertImportIssue(ctx, models.ImportIssue{
					ImportRunID: runID,
					Source:      "1pif",
					TypeName:    item.TypeName,
					Title:       item.Title,
					ExternalUUID: item.UUID,
					Reason:      "empty secure note",
					Raw:         raw,
				})
				continue
			}
			if id, err := store.ResolveExternalID(item.UUID); err == nil {
				if exists, err := store.ExistsNote(ctx, userUUID, id); err == nil && exists {
					result.Existing++
				} else if err == nil {
					result.New++
				}
			}
			note := models.SecureNote{
				ID:    item.UUID,
				UserID: userID,
				Title: item.Title,
				Body:  body,
				ImportSource: "1pif",
				ImportRaw: raw,
			}
			applyTimestamps(&note.CreatedAt, &note.UpdatedAt, item.CreatedAt, item.UpdatedAt)
			if err := store.InsertSecureNote(ctx, cryptoSvc, note); err != nil {
				return result, err
			}
			result.Notes++
		// TODO: add secure note mappings once a sample is provided (1Password 7 typeName + fields).
		default:
			result.Skipped++
			_ = store.InsertImportIssue(ctx, models.ImportIssue{
				ImportRunID: runID,
				Source:      "1pif",
				TypeName:    item.TypeName,
				Title:       item.Title,
				ExternalUUID: item.UUID,
				Reason:      "unsupported type",
				Raw:         raw,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func RebuildFromRaw(ctx context.Context, store *db.Store, cryptoSvc *crypto.Service, raw string, userID string) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return false, nil
	}
	var item pifItem
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		return false, err
	}
	switch item.TypeName {
	case "passwords.Password":
		if item.SecureFields.Password == "" {
			return false, nil
		}
		entry := models.PasswordEntry{
			ID:           item.UUID,
			UserID:       userID,
			Title:        item.Title,
			Password:     item.SecureFields.Password,
			Tags:         item.OpenContents.Tags,
			ImportSource: "1pif",
			ImportRaw:    raw,
		}
		applyTimestamps(&entry.CreatedAt, &entry.UpdatedAt, item.CreatedAt, item.UpdatedAt)
		return true, store.UpsertPassword(ctx, cryptoSvc, entry)
	case "webforms.WebForm":
		username, password := extractUserPass(item.SecureFields.Fields)
		if password == "" {
			return false, nil
		}
		url := item.Location
		if url == "" && len(item.SecureFields.URLs) > 0 {
			url = item.SecureFields.URLs[0].URL
		}
		entry := models.PasswordEntry{
			ID:           item.UUID,
			UserID:       userID,
			Title:        item.Title,
			Username:     username,
			Password:     password,
			URL:          url,
			Tags:         item.OpenContents.Tags,
			ImportSource: "1pif",
			ImportRaw:    raw,
		}
		applyTimestamps(&entry.CreatedAt, &entry.UpdatedAt, item.CreatedAt, item.UpdatedAt)
		if extra := buildSectionNotes(item.SecureFields.Sections); extra != "" {
			if entry.Notes != "" {
				entry.Notes += "\n"
			}
			entry.Notes += extra
		}
		return true, store.UpsertPassword(ctx, cryptoSvc, entry)
	case "identities.Identity":
		body := buildIdentityNote(item)
		if body == "" {
			return false, nil
		}
		note := models.SecureNote{
			ID:           item.UUID,
			UserID:       userID,
			Title:        item.Title,
			Body:         body,
			ImportSource: "1pif",
			ImportRaw:    raw,
		}
		applyTimestamps(&note.CreatedAt, &note.UpdatedAt, item.CreatedAt, item.UpdatedAt)
		return true, store.InsertSecureNote(ctx, cryptoSvc, note)
	case "securenotes.SecureNote":
		body := item.SecureFields.NotesPlain
		if strings.TrimSpace(body) == "" {
			return false, nil
		}
		note := models.SecureNote{
			ID:           item.UUID,
			UserID:       userID,
			Title:        item.Title,
			Body:         body,
			ImportSource: "1pif",
			ImportRaw:    raw,
		}
		applyTimestamps(&note.CreatedAt, &note.UpdatedAt, item.CreatedAt, item.UpdatedAt)
		return true, store.InsertSecureNote(ctx, cryptoSvc, note)
	default:
		return false, nil
	}
}

func extractUserPass(fields []pifField) (string, string) {
	var user, pass string
	for _, f := range fields {
		designation := strings.ToLower(strings.TrimSpace(f.Designation))
		name := strings.ToLower(strings.TrimSpace(f.Name))
		if designation == "username" || name == "username" {
			user = f.Value
		}
		if designation == "password" || f.Type == "P" || name == "password" {
			pass = f.Value
		}
	}
	return user, pass
}

func buildIdentityNote(item pifItem) string {
	parts := []string{"Type: identities.Identity"}
	if item.SecureFields.Firstname != "" || item.SecureFields.Lastname != "" {
		parts = append(parts, fmt.Sprintf("Name: %s %s", item.SecureFields.Firstname, item.SecureFields.Lastname))
	}
	if item.SecureFields.Email != "" {
		parts = append(parts, fmt.Sprintf("Email: %s", item.SecureFields.Email))
	}
	if item.SecureFields.NotesPlain != "" {
		parts = append(parts, "Notes: "+item.SecureFields.NotesPlain)
	}
	return strings.Join(parts, "\n")
}

func buildSectionNotes(sections []pifSection) string {
	var lines []string
	for _, section := range sections {
		for _, f := range section.Fields {
			label := f.T
			if label == "" {
				label = f.N
			}
			if label == "" {
				label = "field"
			}
			value := ""
			switch v := f.V.(type) {
			case string:
				value = v
			default:
				b, err := json.Marshal(v)
				if err == nil {
					value = string(b)
				}
			}
			lines = append(lines, label+": "+value)
		}
	}
	return strings.Join(lines, "\n")
}

func applyTimestamps(createdAt *time.Time, updatedAt *time.Time, createdUnix int64, updatedUnix int64) {
	if createdUnix > 0 {
		*createdAt = time.Unix(createdUnix, 0)
	}
	if updatedUnix > 0 {
		*updatedAt = time.Unix(updatedUnix, 0)
	}
}

// duplicate key handling moved to upsert logic
