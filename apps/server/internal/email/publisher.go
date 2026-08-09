package email

import (
	"context"
	"encoding/json"
	"time"

	ampq "github.com/rabbitmq/amqp091-go"
)

// Publisher drops email jobs onto the queue - held by the API binary
type Publisher struct {
	ch	*ampq.Channel
}

// NewPublisher wraps an open channel (topology must already be declared).
func NewPublisher(ch *ampq.Channel) *Publisher {
	return &Publisher{ch: ch}
}

// Publish JSON-encodes the job and sends it to the work queue
func (p *Publisher) Publish(ctx context.Context, job EmailJob) error {
	body, err := json.Marshal(job) // struct -> JSON bytes for the message body

	if err != nil {
		return err
	}

	// Short timeout so a slow/unreachable broker can't hang the HTTP body
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Send to the "email" exchange with the "send" key; Persistent = written to disk
	return p.ch.PublishWithContext(ctx, exchangeName, routingSend, false, false, ampq.Publishing{
		Body: 			body,
		ContentType: 	"application/json",
		DeliveryMode: 	ampq.Persistent,
	})
}
