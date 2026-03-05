package main

import (
	"context"
	"log"
	"net/http"
	"os"
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
	log.Printf("listening on http://0.0.0.0%s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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
