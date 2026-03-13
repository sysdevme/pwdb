package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Client struct {
	http      *http.Client
	serverURL string
	token     string
}

type ConnectionResult struct {
	ServerURL   string `json:"server_url"`
	Reachable   bool   `json:"reachable"`
	StatusCode  int    `json:"status_code"`
	ServerKind  string `json:"server_kind"`
	Description string `json:"description"`
}

type VaultPreview struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type LoginResult struct {
	Token     string      `json:"token"`
	ExpiresAt string      `json:"expires_at"`
	User      SessionUser `json:"user"`
	Server    ServerInfo  `json:"server"`
}

type SessionUser struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	IsAdmin bool   `json:"is_admin"`
	Status  string `json:"status"`
}

type ServerInfo struct {
	Mode       string `json:"mode"`
	SyncStatus string `json:"sync_status"`
}

type PasswordListItem struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Username        string    `json:"username"`
	URL             string    `json:"url"`
	Tags            []string  `json:"tags"`
	Groups          []string  `json:"groups"`
	OwnerEmail      string    `json:"owner_email"`
	IsOwner         bool      `json:"is_owner"`
	SharedAt        time.Time `json:"shared_at"`
	RequiresUnlock  bool      `json:"requires_unlock"`
	SupportsDesktop bool      `json:"supports_desktop"`
}

type PasswordMetadata struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Username       string   `json:"username"`
	URL            string   `json:"url"`
	Tags           []string `json:"tags"`
	Groups         []string `json:"groups"`
	OwnerEmail     string   `json:"owner_email"`
	IsOwner        bool     `json:"is_owner"`
	RequiresUnlock bool     `json:"requires_unlock"`
}

type PasswordSecret struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	URL        string   `json:"url"`
	Notes      string   `json:"notes"`
	Tags       []string `json:"tags"`
	Groups     []string `json:"groups"`
	OwnerEmail string   `json:"owner_email"`
	IsOwner    bool     `json:"is_owner"`
}

type NoteListItem struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Tags            []string  `json:"tags"`
	Groups          []string  `json:"groups"`
	OwnerEmail      string    `json:"owner_email"`
	IsOwner         bool      `json:"is_owner"`
	UpdatedAt       time.Time `json:"updated_at"`
	RequiresUnlock  bool      `json:"requires_unlock"`
	SupportsDesktop bool      `json:"supports_desktop"`
}

type NoteMetadata struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Tags           []string `json:"tags"`
	Groups         []string `json:"groups"`
	OwnerEmail     string   `json:"owner_email"`
	IsOwner        bool     `json:"is_owner"`
	RequiresUnlock bool     `json:"requires_unlock"`
}

type NoteSecret struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Body       string   `json:"body"`
	Tags       []string `json:"tags"`
	Groups     []string `json:"groups"`
	OwnerEmail string   `json:"owner_email"`
	IsOwner    bool     `json:"is_owner"`
}

func New() *Client {
	return &Client{
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Client) TestConnection(rawURL string) (ConnectionResult, error) {
	serverURL := strings.TrimSpace(rawURL)
	if serverURL == "" {
		return ConnectionResult{}, fmt.Errorf("server_url is required")
	}
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return ConnectionResult{}, fmt.Errorf("invalid server_url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return ConnectionResult{}, fmt.Errorf("server_url must be absolute")
	}

	loginURL := strings.TrimRight(serverURL, "/") + "/login"
	req, err := http.NewRequest(http.MethodGet, loginURL, nil)
	if err != nil {
		return ConnectionResult{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ConnectionResult{
			ServerURL:   serverURL,
			Reachable:   false,
			Description: err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	result := ConnectionResult{
		ServerURL:  serverURL,
		Reachable:  resp.StatusCode >= 200 && resp.StatusCode < 500,
		StatusCode: resp.StatusCode,
		ServerKind: "pwdb-web",
	}
	if result.Reachable {
		result.Description = "Server responded on /login. Desktop API should be available on the same node."
	} else {
		result.Description = "Server did not respond successfully."
	}
	return result, nil
}

func (c *Client) Login(rawURL string, email string, password string) (LoginResult, error) {
	serverURL, err := normalizeServerURL(rawURL)
	if err != nil {
		return LoginResult{}, err
	}
	payload := map[string]string{
		"email":    strings.TrimSpace(email),
		"password": password,
	}
	var result LoginResult
	if err := c.doJSON(http.MethodPost, serverURL, "/api/desktop/login", "", payload, &result); err != nil {
		return LoginResult{}, err
	}
	c.serverURL = serverURL
	c.token = strings.TrimSpace(result.Token)
	return result, nil
}

func (c *Client) Logout() error {
	if strings.TrimSpace(c.serverURL) == "" || strings.TrimSpace(c.token) == "" {
		c.serverURL = ""
		c.token = ""
		return nil
	}
	err := c.doJSON(http.MethodPost, c.serverURL, "/api/desktop/logout", c.token, map[string]any{}, nil)
	c.serverURL = ""
	c.token = ""
	return err
}

func (c *Client) ListPasswords() ([]PasswordListItem, error) {
	if strings.TrimSpace(c.serverURL) == "" || strings.TrimSpace(c.token) == "" {
		return nil, fmt.Errorf("desktop session is not initialized")
	}
	var resp struct {
		Items []PasswordListItem `json:"items"`
	}
	if err := c.doJSON(http.MethodGet, c.serverURL, "/api/desktop/passwords", c.token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

func (c *Client) GetPassword(id string) (PasswordMetadata, error) {
	if strings.TrimSpace(c.serverURL) == "" || strings.TrimSpace(c.token) == "" {
		return PasswordMetadata{}, fmt.Errorf("desktop session is not initialized")
	}
	var resp PasswordMetadata
	if err := c.doJSON(http.MethodGet, c.serverURL, "/api/desktop/passwords/"+url.PathEscape(strings.TrimSpace(id)), c.token, nil, &resp); err != nil {
		return PasswordMetadata{}, err
	}
	return resp, nil
}

func (c *Client) UnlockPassword(id string, masterPassword string) (PasswordSecret, error) {
	if strings.TrimSpace(c.serverURL) == "" || strings.TrimSpace(c.token) == "" {
		return PasswordSecret{}, fmt.Errorf("desktop session is not initialized")
	}
	var resp PasswordSecret
	if err := c.doJSON(http.MethodPost, c.serverURL, "/api/desktop/passwords/"+url.PathEscape(strings.TrimSpace(id))+"/unlock", c.token, map[string]string{
		"master_password": masterPassword,
	}, &resp); err != nil {
		return PasswordSecret{}, err
	}
	return resp, nil
}

func (c *Client) ListNotes() ([]NoteListItem, error) {
	if strings.TrimSpace(c.serverURL) == "" || strings.TrimSpace(c.token) == "" {
		return nil, fmt.Errorf("desktop session is not initialized")
	}
	var resp struct {
		Items []NoteListItem `json:"items"`
	}
	if err := c.doJSON(http.MethodGet, c.serverURL, "/api/desktop/notes", c.token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

func (c *Client) GetNote(id string) (NoteMetadata, error) {
	if strings.TrimSpace(c.serverURL) == "" || strings.TrimSpace(c.token) == "" {
		return NoteMetadata{}, fmt.Errorf("desktop session is not initialized")
	}
	var resp NoteMetadata
	if err := c.doJSON(http.MethodGet, c.serverURL, "/api/desktop/notes/"+url.PathEscape(strings.TrimSpace(id)), c.token, nil, &resp); err != nil {
		return NoteMetadata{}, err
	}
	return resp, nil
}

func (c *Client) UnlockNote(id string, masterPassword string) (NoteSecret, error) {
	if strings.TrimSpace(c.serverURL) == "" || strings.TrimSpace(c.token) == "" {
		return NoteSecret{}, fmt.Errorf("desktop session is not initialized")
	}
	var resp NoteSecret
	if err := c.doJSON(http.MethodPost, c.serverURL, "/api/desktop/notes/"+url.PathEscape(strings.TrimSpace(id))+"/unlock", c.token, map[string]string{
		"master_password": masterPassword,
	}, &resp); err != nil {
		return NoteSecret{}, err
	}
	return resp, nil
}

func normalizeServerURL(rawURL string) (string, error) {
	serverURL := strings.TrimSpace(rawURL)
	if serverURL == "" {
		return "", fmt.Errorf("server_url is required")
	}
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server_url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("server_url must be absolute")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func (c *Client) doJSON(method string, serverURL string, endpoint string, token string, payload any, dst any) error {
	u, err := url.Parse(serverURL)
	if err != nil {
		return err
	}
	u.Path = path.Join(u.Path, endpoint)
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr map[string]any
		if err := json.Unmarshal(raw, &apiErr); err == nil {
			if msg, ok := apiErr["error"].(string); ok && strings.TrimSpace(msg) != "" {
				return fmt.Errorf(msg)
			}
		}
		if strings.TrimSpace(string(raw)) != "" {
			return fmt.Errorf(strings.TrimSpace(string(raw)))
		}
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}
	if dst == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}
