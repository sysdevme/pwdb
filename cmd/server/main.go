package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"password-manager-go/internal/crypto"
	"password-manager-go/internal/db"
	"password-manager-go/internal/handlers"
)

func main() {
	addr := envOr("APP_ADDR", ":8080")
	master := os.Getenv("MASTER_PASSWORD")
	if master == "" {
		log.Println("warning: MASTER_PASSWORD not set")
	}
	tlsEnabled := envBoolOr("APP_TLS", false)
	var certFile, keyFile string
	var err error
	if tlsEnabled {
		certFile, keyFile, err = resolveTLSFiles()
		if err != nil {
			log.Fatalf("tls config: %v", err)
		}
	}

	ctx := context.Background()
	store, err := db.NewStoreFromEnv(ctx)
	if err != nil {
		log.Fatalf("db init: %v", err)
	}
	defer store.Close()
	if err := waitForDB(ctx, store); err != nil {
		log.Fatalf("db ping: %v", err)
	}
	if err := store.RunMigrations(ctx, envOr("MIGRATIONS_DIR", "db/migrations")); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	cryptoSvc := crypto.NewService(master)

	server := handlers.NewServer(nil, store, cryptoSvc)

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if tlsEnabled {
		log.Printf("listening on https://0.0.0.0%s", addr)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
		return
	}

	log.Printf("listening on http://0.0.0.0%s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBoolOr(key string, fallback bool) bool {
	value := stringsTrim(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func waitForDB(ctx context.Context, store *db.Store) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := store.Ping(ctx); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return store.Ping(ctx)
		}
		time.Sleep(2 * time.Second)
	}
}

func resolveTLSFiles() (string, string, error) {
	certCandidates := []string{
		stringsTrim(os.Getenv("TLS_CERT_FILE")),
		stringsTrim(os.Getenv("CERT_FILE")),
		"certs/certificate",
		"certs/certificate.pem",
		"certs/certificate.crt",
	}
	keyCandidates := []string{
		stringsTrim(os.Getenv("TLS_KEY_FILE")),
		stringsTrim(os.Getenv("KEY_FILE")),
		"certs/private",
		"certs/private.key",
		"certs/private.pem",
		"certs/key",
		"certs/key.pem",
	}
	certFile := firstExistingFile(certCandidates)
	if certFile == "" {
		return "", "", errors.New("certificate file not found in certs/ (expected certificate, certificate.pem, or certificate.crt)")
	}
	keyFile := firstExistingFile(keyCandidates)
	if keyFile == "" {
		return "", "", errors.New("private key file not found in certs/ (expected private, private.key, private.pem, key, or key.pem)")
	}
	return certFile, keyFile, nil
}

func firstExistingFile(candidates []string) string {
	for _, candidate := range candidates {
		path := stringsTrim(candidate)
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			if abs, err := filepath.Abs(path); err == nil {
				return abs
			}
			return path
		}
	}
	return ""
}

func stringsTrim(value string) string {
	return strings.TrimSpace(value)
}
