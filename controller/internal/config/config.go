package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type MasterConfig struct {
	BaseURL         string `json:"base_url"`
	BootstrapPath   string `json:"bootstrap_path"`
	RotatePath      string `json:"rotate_path"`
	ControllersPath string `json:"controllers_path"`
	PairPath        string `json:"pair_path"`
	UpdateAckPath   string `json:"update_ack_path"`
	UpdateApplyPath string `json:"update_apply_path"`
	SharedToken     string `json:"shared_token"`
}

type Config struct {
	ControllerID       string       `json:"controller_id"`
	ListenAddr         string       `json:"listen_addr"`
	StateFile          string       `json:"state_file"`
	HTTPTimeoutSeconds int          `json:"http_timeout_seconds"`
	SyncIntervalSec    int          `json:"sync_interval_sec"`
	Master             MasterConfig `json:"master"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Normalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Normalize() error {
	c.ControllerID = strings.TrimSpace(c.ControllerID)
	c.ListenAddr = strings.TrimSpace(c.ListenAddr)
	c.StateFile = strings.TrimSpace(c.StateFile)
	c.Master.BaseURL = strings.TrimSpace(c.Master.BaseURL)
	if c.ControllerID == "" {
		return fmt.Errorf("controller_id is required")
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":9091"
	}
	if c.StateFile == "" {
		c.StateFile = "data/state.json"
	}
	if c.HTTPTimeoutSeconds <= 0 {
		c.HTTPTimeoutSeconds = 10
	}
	if c.SyncIntervalSec <= 0 {
		c.SyncIntervalSec = 30
	}
	if c.Master.BaseURL == "" {
		return fmt.Errorf("master.base_url is required")
	}
	if strings.TrimSpace(c.Master.BootstrapPath) == "" {
		c.Master.BootstrapPath = "/controller/auth/bootstrap"
	}
	if strings.TrimSpace(c.Master.RotatePath) == "" {
		c.Master.RotatePath = "/controller/auth/rotate"
	}
	if strings.TrimSpace(c.Master.ControllersPath) == "" {
		c.Master.ControllersPath = "/controller/controllers"
	}
	if strings.TrimSpace(c.Master.PairPath) == "" {
		c.Master.PairPath = "/controller/pair"
	}
	if strings.TrimSpace(c.Master.UpdateAckPath) == "" {
		c.Master.UpdateAckPath = "/controller/update/ack"
	}
	if strings.TrimSpace(c.Master.UpdateApplyPath) == "" {
		c.Master.UpdateApplyPath = "/controller/update/apply"
	}
	c.Master.SharedToken = strings.TrimSpace(c.Master.SharedToken)
	return nil
}
