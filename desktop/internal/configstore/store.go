package configstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Settings struct {
	ServerURL string `json:"server_url"`
	Email     string `json:"email"`
}

type Store struct {
	path string
}

func New() *Store {
	return &Store{}
}

func (s *Store) filePath() (string, error) {
	if strings.TrimSpace(s.path) != "" {
		return s.path, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "pwdb-desktop", "settings.json"), nil
}

func (s *Store) Load() (Settings, error) {
	path, err := s.filePath()
	if err != nil {
		return Settings{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Settings{}, nil
		}
		return Settings{}, err
	}
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return Settings{}, err
	}
	settings.ServerURL = strings.TrimSpace(settings.ServerURL)
	settings.Email = strings.TrimSpace(settings.Email)
	return settings, nil
}

func (s *Store) Save(settings Settings) error {
	path, err := s.filePath()
	if err != nil {
		return err
	}
	settings.ServerURL = strings.TrimSpace(settings.ServerURL)
	settings.Email = strings.TrimSpace(settings.Email)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
