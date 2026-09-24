package events

import (
	"bufio"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
)

// PingInterval is how often a ": ping" comment keeps idle streams alive.
const PingInterval = 25 * time.Second

// StreamOptions customise one SSE stream.
type StreamOptions struct {
	// Filter drops events the subscriber must not see (e.g. other envs for a machine). nil = all.
	Filter func(Event) bool
	// StillAllowed is re-checked on every ping; returning false ends the stream
	// (access revoked mid-stream). nil = never re-check.
	StillAllowed func() bool
}

// Stream turns the request into a text/event-stream fed by sub. It takes
// ownership of sub and closes it when the client goes away. Call it as the
// last thing a handler does and return its result.
func Stream(c *fiber.Ctx, sub *Subscription, opts StreamOptions) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)

	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer sub.Close()
		if _, err := w.WriteString(": connected\n\n"); err != nil || w.Flush() != nil {
			return
		}
		ticker := time.NewTicker(PingInterval)
		defer ticker.Stop()
		for {
			select {
			case e, ok := <-sub.C:
				if !ok {
					return
				}
				if opts.Filter != nil && !opts.Filter(e) {
					continue
				}
				if err := WriteEvent(w, e); err != nil {
					return
				}
			case <-ticker.C:
				if opts.StillAllowed != nil && !opts.StillAllowed() {
					return
				}
				if _, err := w.WriteString(": ping\n\n"); err != nil {
					return
				}
				if err := w.Flush(); err != nil {
					return // client disconnected
				}
			}
		}
	})
	return nil
}

// WriteEvent writes one "event:/data:" frame and flushes.
func WriteEvent(w *bufio.Writer, e Event) error {
	data := e.Data
	if len(data) == 0 {
		data = []byte("{}")
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Name, data); err != nil {
		return err
	}
	return w.Flush()
}
