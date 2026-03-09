package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
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
	if err := validateSecrets(cfg); err != nil {
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

func validateSecrets(cfg config.Config) error {
	if config.SecretLooksUnset(cfg.Master.SharedToken) {
		return fmt.Errorf("controller shared token is required; set CONTROLLER_SHARED_TOKEN or update a local config file")
	}
	return nil
}
