// Package events is the vault change feed: an in-process pub/sub hub keyed by
// vault id, an optional RabbitMQ fanout for multi-instance deployments, and the
// SSE writer shared by /vaults/:vid/events and /machine/events.
package events

import (
	"encoding/json"
	"sync"
)

// Event names (the SSE "event:" line).
const (
	Revision      = "revision"
	GrantsPending = "grants_pending"
	RekeyRequired = "rekey_required"
	ChangeRequest = "change_request"
	Members       = "members"
)

// Event is one change notification. It is also the RabbitMQ wire message.
type Event struct {
	VaultID  string          `json:"vault_id"`
	Env      string          `json:"env,omitempty"` // duplicated from Data so subscribers can filter cheaply
	Name     string          `json:"event"`
	Data     json.RawMessage `json:"data"`
	OriginID string          `json:"origin_instance_id,omitempty"`
}

// subscriberBuffer bounds how far a slow SSE client may fall behind before
// events are dropped for it (clients resync by polling head anyway).
const subscriberBuffer = 64

// Subscription receives events for one vault until Close is called.
type Subscription struct {
	C       <-chan Event
	ch      chan Event
	hub     *Hub
	vaultID string
	once    sync.Once
}

// Close unsubscribes; safe to call more than once.
func (s *Subscription) Close() {
	s.once.Do(func() { s.hub.unsubscribe(s) })
}

// Hub fans events out to local subscribers.
type Hub struct {
	mu   sync.RWMutex
	subs map[string]map[*Subscription]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: map[string]map[*Subscription]struct{}{}}
}

// Subscribe registers a subscriber for one vault.
func (h *Hub) Subscribe(vaultID string) *Subscription {
	ch := make(chan Event, subscriberBuffer)
	s := &Subscription{C: ch, ch: ch, hub: h, vaultID: vaultID}
	h.mu.Lock()
	if h.subs[vaultID] == nil {
		h.subs[vaultID] = map[*Subscription]struct{}{}
	}
	h.subs[vaultID][s] = struct{}{}
	h.mu.Unlock()
	return s
}

func (h *Hub) unsubscribe(s *Subscription) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.subs[s.vaultID]
	if _, ok := set[s]; !ok {
		return
	}
	delete(set, s)
	if len(set) == 0 {
		delete(h.subs, s.vaultID)
	}
	close(s.ch)
}

// Deliver pushes an event to every local subscriber of its vault without
// blocking; a full subscriber buffer drops the event for that subscriber.
func (h *Hub) Deliver(e Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for s := range h.subs[e.VaultID] {
		select {
		case s.ch <- e:
		default:
		}
	}
}

// SubscriberCount reports local subscribers for a vault (tests / metrics).
func (h *Hub) SubscriberCount(vaultID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[vaultID])
}
