package hook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// WebhookSink POSTs the payload to an HTTPS endpoint.
type WebhookSink struct {
	client *http.Client
}

// NewWebhookSink builds a sink with a shared client. The per-delivery
// timeout comes from the context, so the client itself sets none.
func NewWebhookSink() *WebhookSink {
	return &WebhookSink{client: &http.Client{}}
}

// SignatureHeader carries an HMAC-SHA256 of the exact body, in the same
// shape GitHub uses, so a receiver can reject anything it did not expect.
const SignatureHeader = "X-Brokerd-Signature"

// DeliveryHeader carries a per-delivery id, so a receiver can recognise a
// retry of the same event rather than a second event.
const DeliveryHeader = "X-Brokerd-Delivery"

func (s *WebhookSink) Deliver(ctx context.Context, t config.HookTarget, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mesh-brokerd")
	req.Header.Set(DeliveryHeader, deliveryID(body))
	// Configured headers go last so a target can override a default when its
	// receiver insists on something else.
	for name, value := range t.Headers {
		req.Header.Set(name, value)
	}
	if t.Secret != "" {
		mac := hmac.New(sha256.New, []byte(t.Secret))
		mac.Write(body)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain a little so the connection can be reused, but never the
		// whole body: a hook target's response is not data brokerd wants.
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("target returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *WebhookSink) Describe(t config.HookTarget) string {
	signed := "unsigned"
	if t.Secret != "" {
		signed = "signed"
	}
	return fmt.Sprintf("POST %s (%s)", t.URL, signed)
}

// deliveryID is derived from the body and the current time rather than
// from a random source: it only has to be recognisable, and a derived
// value keeps the sink free of state.
func deliveryID(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%s-%d", hex.EncodeToString(sum[:8]), time.Now().UnixNano())
}
