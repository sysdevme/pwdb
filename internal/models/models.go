package models

import "time"

type PasswordEntry struct {
	ID           string
	UserID       string
	OwnerEmail    string `json:"-"`
	Title        string
	Username     string
	Password     string
	URL          string
	Notes        string
	Tags         []string
	Groups       []string
	ImportSource string
	ImportRaw    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type SecureNote struct {
	ID           string
	UserID       string
	OwnerEmail    string `json:"-"`
	Title        string
	Body         string
	Tags         []string
	Groups       []string
	ImportSource string
	ImportRaw    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ImportRun struct {
	ID                string
	UserID            string
	Filename          string
	FileSize          int64
	ImportedPasswords int
	ImportedNotes     int
	ExistingCount     int
	NewCount          int
	SkippedCount      int
	CreatedAt         time.Time
}

type ImportIssue struct {
	ID           string
	ImportRunID  string
	Source       string
	TypeName     string
	Title        string
	ExternalUUID string
	Reason       string
	Raw          string
	CreatedAt    time.Time
}

type Tag struct {
	ID     string
	Name   string
	UserID string
	Count  int
}

type Group struct {
	ID     string
	Name   string
	UserID string
	Count  int
}

type User struct {
	ID                 string
	Email              string
	Status             string
	PasswordHash       string
	MasterPasswordHash string
	IsAdmin            bool
	CreatedAt          time.Time
}

type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type PasswordShareLink struct {
	Token     string
	EntryID   string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type ServerProfile struct {
	ServerMode     string
	SyncStatus     string
	LinkedMasterID string
	LinkedMasterURL string
	LastPairingPIN string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ControllerLink struct {
	SlaveServerID   string
	SlaveEndpoint   string
	Status          string
	LastHandshakeAt time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type ControllerUpdateEvent struct {
	EventID        string
	MasterServerID string
	VaultVersion   int64
	PayloadHash    string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ControllerRegistryEntry struct {
	ControllerID   string
	Status         string
	Weight         int
	TokenUpdatedAt time.Time
	LastSeenAt     time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
