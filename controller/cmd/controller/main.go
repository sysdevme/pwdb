package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"pwdb-controller/internal/config"
	"pwdb-controller/internal/master"
	"pwdb-controller/internal/server"
)

func main() {
	cfgPath := flag.String("config", "configs/controller.dev.json", "path to controller config json")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	if err := resolveSecrets(&cfg); err != nil {
		log.Fatalf("config secrets: %v", err)
	}

	state, err := server.NewStateStore(cfg.StateFile)
	if err != nil {
		log.Fatalf("state init: %v", err)
	}

	masterClient := master.New(
		cfg.Master.BaseURL,
		time.Duration(cfg.HTTPTimeoutSeconds)*time.Second,
		cfg.Master.BootstrapPath,
		cfg.Master.RotatePath,
		cfg.Master.ControllersPath,
		cfg.Master.PairPath,
		cfg.Master.SnapshotExportPath,
		cfg.Master.SnapshotApplyPath,
		cfg.Master.UpdateAckPath,
		cfg.Master.UpdateApplyPath,
		cfg.Master.SharedToken,
	)

	svc := server.New(cfg, masterClient, state)
	svc.StartWorkerLoop()

	h := svc.Routes()
	log.Printf("controller listening on %s (id=%s)", cfg.ListenAddr, cfg.ControllerID)
	if err := http.ListenAndServe(cfg.ListenAddr, h); err != nil {
		log.Fatal(err)
	}
}

func resolveSecrets(cfg *config.Config) error {
	if !config.SecretLooksUnset(cfg.Master.SharedToken) {
		return nil
	}
	if !stdinIsTTY() {
		return fmt.Errorf("controller shared token is required; set CONTROLLER_SHARED_TOKEN or update the config file")
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stdout, "Controller shared token: ")
	sharedToken, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	cfg.Master.SharedToken = strings.TrimSpace(sharedToken)
	if config.SecretLooksUnset(cfg.Master.SharedToken) {
		return fmt.Errorf("controller shared token is required")
	}
	if config.SecretLooksUnset(cfg.Master.MasterKey) {
		fmt.Fprint(os.Stdout, "Controller master key (optional, press Enter to skip): ")
		masterKey, err := reader.ReadString('\n')
		if err == nil {
			cfg.Master.MasterKey = strings.TrimSpace(masterKey)
		}
	}
	return nil
}

func stdinIsTTY() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
