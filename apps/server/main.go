package main

import (
	"log"

	"github.com/zain-23/local-vault/apps/server/internal/app"
	"github.com/zain-23/local-vault/apps/server/internal/config"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("❌ Invalid config: %v", err)
	}

	// Create app — connects to MongoDB, sets up Fiber, registers routes
	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("❌ Failed to start: %v", err) // Fatalf logs and exits the program
	}

	// Start HTTP server — blocks (waits) until server is stopped
	log.Printf("🚀 LocalVault Server v3.0 running on port %s", cfg.Port)
	if err := application.Fiber.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("❌ Server stopped: %v", err)
	}
}
