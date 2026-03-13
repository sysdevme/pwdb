package main

import (
	"context"
	"fmt"
	"strings"

	"pwdb-desktop/internal/client"
	"pwdb-desktop/internal/configstore"
)

type App struct {
	ctx    context.Context
	store  *configstore.Store
	client *client.Client
}

type AppInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

type SessionState struct {
	Authenticated bool                      `json:"authenticated"`
	TokenPresent  bool                      `json:"token_present"`
	User          *client.SessionUser       `json:"user,omitempty"`
	Server        *client.ServerInfo        `json:"server,omitempty"`
	Passwords     []client.PasswordListItem `json:"passwords,omitempty"`
	Notes         []client.NoteListItem     `json:"notes,omitempty"`
}

func NewApp() *App {
	store := configstore.New()
	return &App{
		store:  store,
		client: client.New(),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) GetAppInfo() AppInfo {
	return AppInfo{
		Name:    "PWDB Desktop",
		Version: "0.1.0-alpha",
		Mode:    "desktop-api-mvp",
	}
}

func (a *App) GetSettings() (configstore.Settings, error) {
	return a.store.Load()
}

func (a *App) SaveSettings(settings configstore.Settings) (configstore.Settings, error) {
	settings.ServerURL = strings.TrimSpace(settings.ServerURL)
	settings.Email = strings.TrimSpace(settings.Email)
	if settings.ServerURL == "" {
		return configstore.Settings{}, fmt.Errorf("server_url is required")
	}
	if err := a.store.Save(settings); err != nil {
		return configstore.Settings{}, err
	}
	return settings, nil
}

func (a *App) TestConnection(settings configstore.Settings) (client.ConnectionResult, error) {
	return a.client.TestConnection(settings.ServerURL)
}

func (a *App) Login(settings configstore.Settings, password string) (SessionState, error) {
	settings.ServerURL = strings.TrimSpace(settings.ServerURL)
	settings.Email = strings.TrimSpace(settings.Email)
	if settings.ServerURL == "" || settings.Email == "" || password == "" {
		return SessionState{}, fmt.Errorf("server_url, email, and password are required")
	}
	result, err := a.client.Login(settings.ServerURL, settings.Email, password)
	if err != nil {
		return SessionState{}, err
	}
	passwords, err := a.client.ListPasswords()
	if err != nil {
		return SessionState{}, err
	}
	notes, err := a.client.ListNotes()
	if err != nil {
		return SessionState{}, err
	}
	_ = a.store.Save(settings)
	return SessionState{
		Authenticated: true,
		TokenPresent:  strings.TrimSpace(result.Token) != "",
		User:          &result.User,
		Server:        &result.Server,
		Passwords:     passwords,
		Notes:         notes,
	}, nil
}

func (a *App) Logout() error {
	return a.client.Logout()
}

func (a *App) RefreshPasswords() ([]client.PasswordListItem, error) {
	return a.client.ListPasswords()
}

func (a *App) RefreshNotes() ([]client.NoteListItem, error) {
	return a.client.ListNotes()
}

func (a *App) GetPassword(id string) (client.PasswordMetadata, error) {
	return a.client.GetPassword(id)
}

func (a *App) UnlockPassword(id string, masterPassword string) (client.PasswordSecret, error) {
	return a.client.UnlockPassword(id, masterPassword)
}

func (a *App) GetNote(id string) (client.NoteMetadata, error) {
	return a.client.GetNote(id)
}

func (a *App) UnlockNote(id string, masterPassword string) (client.NoteSecret, error) {
	return a.client.UnlockNote(id, masterPassword)
}
