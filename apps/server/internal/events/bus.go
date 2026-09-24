package events

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync/atomic"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/zain-23/local-vault/apps/server/internal/common/id"
)

// ExchangeName is the RabbitMQ fanout exchange every API instance binds to.
const ExchangeName = "lv.vault.events"

// Publisher is what domains depend on to emit events.
type Publisher interface {
	Publish(ctx context.Context, vaultID, event string, data any)
}

// Bus publishes events and delivers them to the local Hub. With RabbitMQ it
// publishes only to the fanout exchange and delivers locally from its own
// consumer (so every instance, including this one, gets each event exactly
// once). Without RabbitMQ — or after the broker connection is lost — it
// delivers straight to the local hub.
type Bus struct {
	hub        *Hub
	ch         *amqp.Channel
	instanceID string
	remote     atomic.Bool // true while the RabbitMQ consumer is healthy
}

// NewLocalBus is an in-process-only bus (development without RabbitMQ, tests).
func NewLocalBus(hub *Hub) *Bus {
	return &Bus{hub: hub, instanceID: id.Generate("inst_", 6)}
}

// NewRabbitBus declares the fanout exchange plus an exclusive auto-delete queue
// for this instance and starts consuming. ch should be dedicated to the bus.
func NewRabbitBus(hub *Hub, ch *amqp.Channel) (*Bus, error) {
	b := &Bus{hub: hub, ch: ch, instanceID: id.Generate("inst_", 6)}
	if err := ch.ExchangeDeclare(ExchangeName, "fanout", true, false, false, false, nil); err != nil {
		return nil, err
	}
	q, err := ch.QueueDeclare("", false, true, true, false, nil) // server-named, auto-delete, exclusive
	if err != nil {
		return nil, err
	}
	if err := ch.QueueBind(q.Name, "", ExchangeName, false, nil); err != nil {
		return nil, err
	}
	msgs, err := ch.Consume(q.Name, "", true, true, false, false, nil)
	if err != nil {
		return nil, err
	}
	b.remote.Store(true)
	go b.consume(msgs)
	return b, nil
}

func (b *Bus) consume(msgs <-chan amqp.Delivery) {
	for d := range msgs {
		var e Event
		if err := json.Unmarshal(d.Body, &e); err != nil || e.VaultID == "" {
			continue
		}
		b.hub.Deliver(e)
	}
	b.remote.Store(false)
	log.Printf("⚠️ events: RabbitMQ consumer closed — falling back to in-process delivery")
}

// Hub exposes the local hub for SSE handlers.
func (b *Bus) Hub() *Hub { return b.hub }

// Publish emits one event. Never fails the caller: errors are logged and the
// event is delivered locally so at least this instance's subscribers see it.
func (b *Bus) Publish(ctx context.Context, vaultID, event string, data any) {
	if b == nil {
		return
	}
	e, err := newEvent(vaultID, event, data)
	if err != nil {
		log.Printf("⚠️ events: marshal %s: %v", event, err)
		return
	}
	e.OriginID = b.instanceID

	if b.ch != nil && b.remote.Load() {
		body, err := json.Marshal(e)
		if err == nil {
			pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			err = b.ch.PublishWithContext(pctx, ExchangeName, "", false, false, amqp.Publishing{
				ContentType: "application/json",
				Body:        body,
			})
			cancel()
		}
		if err == nil {
			return
		}
		log.Printf("⚠️ events: publish %s to RabbitMQ failed, delivering locally: %v", event, err)
	}
	b.hub.Deliver(e)
}

// newEvent copies inputs (Fiber strings may alias request buffers) and marshals data.
func newEvent(vaultID, event string, data any) (Event, error) {
	if data == nil {
		data = struct{}{}
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return Event{}, err
	}
	e := Event{VaultID: strings.Clone(vaultID), Name: event, Data: raw}
	var probe struct {
		Env string `json:"env"`
	}
	if json.Unmarshal(raw, &probe) == nil {
		e.Env = probe.Env
	}
	return e, nil
}
