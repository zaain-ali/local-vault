package events

import (
	"bufio"
	"bytes"
	"context"
	"testing"
	"time"
)

func TestLocalBusDeliversToVaultSubscribersOnly(t *testing.T) {
	hub := NewHub()
	bus := NewLocalBus(hub)

	a := hub.Subscribe("vlt_a")
	b := hub.Subscribe("vlt_b")
	defer a.Close()
	defer b.Close()

	bus.Publish(context.Background(), "vlt_a", Revision, map[string]any{"env": "production", "revision": 42})

	select {
	case e := <-a.C:
		if e.Name != Revision || e.Env != "production" || string(e.Data) != `{"env":"production","revision":42}` {
			t.Fatalf("unexpected event %+v (%s)", e, e.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber a got nothing")
	}
	select {
	case e := <-b.C:
		t.Fatalf("subscriber b got %+v", e)
	default:
	}
}

func TestCloseIsIdempotentAndUnsubscribes(t *testing.T) {
	hub := NewHub()
	s := hub.Subscribe("v")
	s.Close()
	s.Close()
	if hub.SubscriberCount("v") != 0 {
		t.Fatal("still subscribed")
	}
	if _, ok := <-s.C; ok {
		t.Fatal("channel not closed")
	}
	hub.Deliver(Event{VaultID: "v", Name: Members}) // must not panic
}

func TestWriteEventFormat(t *testing.T) {
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	if err := WriteEvent(w, Event{Name: Members}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "event: members\ndata: {}\n\n" {
		t.Fatalf("got %q", got)
	}
}
