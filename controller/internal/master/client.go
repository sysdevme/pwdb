package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ControllerInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Weight int    `json:"weight"`
}

type Client struct {
	baseURL     string
	bootstrap   string
	rotate      string
	listPath    string
	pairPath    string
	updateAckPath   string
	updateApplyPath string
	sharedToken string
	http        *http.Client
}

func New(baseURL string, timeout time.Duration, bootstrapPath string, rotatePath string, listPath string, pairPath string, updateAckPath string, updateApplyPath string, sharedToken string) *Client {
	return &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		bootstrap:   bootstrapPath,
		rotate:      rotatePath,
		listPath:    listPath,
		pairPath:    pairPath,
		updateAckPath:   updateAckPath,
		updateApplyPath: updateApplyPath,
		sharedToken: strings.TrimSpace(sharedToken),
		http:        &http.Client{Timeout: timeout},
	}
}

type bootstrapReq struct {
	ControllerID string `json:"controller_id"`
	MasterKey    string `json:"master_key"`
}

type tokenResp struct {
	NextToken string `json:"next_token"`
}

func (c *Client) Bootstrap(controllerID string, masterKey string) (string, error) {
	payload := bootstrapReq{ControllerID: controllerID, MasterKey: masterKey}
	respBody, status, err := c.postJSON(c.bootstrap, payload, "")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("bootstrap failed: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}
	var tr tokenResp
	if err := json.Unmarshal(respBody, &tr); err != nil {
		return "", err
	}
	if strings.TrimSpace(tr.NextToken) == "" {
		return "", fmt.Errorf("bootstrap response missing next_token")
	}
	return tr.NextToken, nil
}

func (c *Client) Rotate(controllerID string, token string) (string, error) {
	payload := map[string]string{"controller_id": controllerID}
	respBody, status, err := c.postJSON(c.rotate, payload, token)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("rotate failed: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}
	var tr tokenResp
	if err := json.Unmarshal(respBody, &tr); err != nil {
		return "", err
	}
	if strings.TrimSpace(tr.NextToken) == "" {
		return "", fmt.Errorf("rotate response missing next_token")
	}
	return tr.NextToken, nil
}

type listResp struct {
	Controllers []ControllerInfo `json:"controllers"`
	NextToken   string           `json:"next_token"`
}

func (c *Client) ListControllers(token string) ([]ControllerInfo, string, error) {
	respBody, status, err := c.get(c.listPath, token)
	if err != nil {
		return nil, "", err
	}
	if status != http.StatusOK {
		return nil, "", fmt.Errorf("list controllers failed: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}
	var lr listResp
	if err := json.Unmarshal(respBody, &lr); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(lr.NextToken) == "" {
		return nil, "", fmt.Errorf("list controllers response missing next_token")
	}
	return lr.Controllers, lr.NextToken, nil
}

type pairReq struct {
	SlaveServerID string `json:"slave_server_id"`
	SlaveEndpoint string `json:"slave_endpoint"`
}

func (c *Client) PairSlave(slaveID string, slaveURL string) error {
	if c.sharedToken == "" {
		return fmt.Errorf("master.shared_token is required for pair relay")
	}
	payload := pairReq{
		SlaveServerID: strings.TrimSpace(slaveID),
		SlaveEndpoint: strings.TrimSpace(slaveURL),
	}
	respBody, status, err := c.postJSONWithControllerToken(c.pairPath, payload, c.sharedToken)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("pair failed: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

type updateApplyReq struct {
	MasterServerID string `json:"master_server_id"`
	EventID        string `json:"event_id"`
	VaultVersion   int64  `json:"vault_version"`
	PayloadHash    string `json:"payload_hash"`
}

func (c *Client) ApplyUpdateToSlave(slaveURL string, masterServerID string, eventID string, vaultVersion int64, payloadHash string) error {
	if c.sharedToken == "" {
		return fmt.Errorf("master.shared_token is required for slave update relay")
	}
	payload := updateApplyReq{
		MasterServerID: strings.TrimSpace(masterServerID),
		EventID:        strings.TrimSpace(eventID),
		VaultVersion:   vaultVersion,
		PayloadHash:    strings.TrimSpace(payloadHash),
	}
	base := strings.TrimRight(strings.TrimSpace(slaveURL), "/")
	if base == "" {
		return fmt.Errorf("slave_url is required")
	}
	respBody, status, err := c.postJSONWithControllerTokenToBase(base, c.updateApplyPath, payload, c.sharedToken)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("update apply failed: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

type updateAckReq struct {
	MasterServerID string `json:"master_server_id"`
	SlaveServerID  string `json:"slave_server_id"`
	EventID        string `json:"event_id"`
	Status         string `json:"status"`
}

func (c *Client) AckUpdate(masterServerID string, slaveID string, eventID string, statusValue string) error {
	if c.sharedToken == "" {
		return fmt.Errorf("master.shared_token is required for update ack")
	}
	payload := updateAckReq{
		MasterServerID: strings.TrimSpace(masterServerID),
		SlaveServerID:  strings.TrimSpace(slaveID),
		EventID:        strings.TrimSpace(eventID),
		Status:         strings.TrimSpace(statusValue),
	}
	respBody, status, err := c.postJSONWithControllerToken(c.updateAckPath, payload, c.sharedToken)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("update ack failed: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func (c *Client) postJSON(path string, payload any, token string) ([]byte, int, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

func (c *Client) postJSONWithControllerToken(path string, payload any, controllerToken string) ([]byte, int, error) {
	return c.postJSONWithControllerTokenToBase(c.baseURL, path, payload, controllerToken)
}

func (c *Client) postJSONWithControllerTokenToBase(baseURL string, path string, payload any, controllerToken string) ([]byte, int, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Controller-Token", strings.TrimSpace(controllerToken))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

func (c *Client) get(path string, token string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}
