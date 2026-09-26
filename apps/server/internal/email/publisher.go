package email

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	ampq "github.com/rabbitmq/amqp091-go"
)

// ErrDisabled is returned by a nil Publisher (development without RabbitMQ).
var ErrDisabled = errors.New("email queue disabled (RabbitMQ not connected)")

// Publisher drops email jobs onto the queue - held by the API binary
type Publisher struct {
	ch	*ampq.Channel
}

// NewPublisher wraps an open channel (topology must already be declared).
func NewPublisher(ch *ampq.Channel) *Publisher {
	return &Publisher{ch: ch}
}

// Publish JSON-encodes the job and sends it to the work queue.
// Safe on a nil *Publisher: returns ErrDisabled so callers just log it.
func (p *Publisher) Publish(ctx context.Context, job EmailJob) error {
	if p == nil || p.ch == nil {
		return ErrDisabled
	}
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
