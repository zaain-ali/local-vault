package main

import (
	"context"
	"log"

	"github.com/zain-23/local-vault/apps/server/internal/config"
	"github.com/zain-23/local-vault/apps/server/internal/email"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("❌ invalid config: %v", err)
	}

	// connect to rabbitMQ and open a channel
	conn, ch, err := email.Connect(cfg.RabbitMQURL)
	if err != nil {
		log.Fatalf("❌ rabbitmq connect: %v", err)
	}
	defer conn.Close() // close the TCP connection when main() returns
	defer ch.Close()

	// Declare exchange + queues (idempotent - the same call the API makes)
	if err := email.DeclareTopology(ch, cfg.EmailRetryDelay); err != nil {
		log.Fatalf("❌ declare topology: %v", err)
	}

	// Build the resend sender and the consumer that drives it
	sender := email.NewSender(cfg.ResendAPIKey, cfg.FromEmail)
	consumer := email.NewConsumer(ch, sender, cfg.EmailMaxRetries)

	log.Println("🚀 LocalVault email worker started")

	// Run blocks forever. context.Background() = no cancellation for now.
	// TODO: reconnect on channel close (v2) — today the worker exits and relies on a restart.
	if err := consumer.Run(context.Background()); err != nil {
		log.Fatalf("❌ worker stopped: %v", err)
	}
}
