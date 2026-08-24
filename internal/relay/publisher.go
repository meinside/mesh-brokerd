package relay

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// PahoPublisher is the real Publisher: a lazily-connected
// github.com/eclipse/paho.mqtt.golang client per configured target.
// Only ever exercised when outbound_relay.dry_run_all_rules is false
// (docs/outbound-relay.md section 7) -- constructing this does not by
// itself connect to anything.
type PahoPublisher struct {
	targets map[string]config.RelayTarget

	mu      sync.Mutex
	clients map[string]mqtt.Client
}

// NewPahoPublisher builds a publisher for the given targets. It does
// not connect to any of them yet -- connections are established
// lazily, on the first Publish call for each target.
func NewPahoPublisher(targets []config.RelayTarget) *PahoPublisher {
	byID := make(map[string]config.RelayTarget, len(targets))
	for _, t := range targets {
		byID[t.ID] = t
	}
	return &PahoPublisher{targets: byID, clients: make(map[string]mqtt.Client)}
}

// Publish implements Engine's Publisher interface.
func (p *PahoPublisher) Publish(targetID, topic string, payload []byte) error {
	client, err := p.clientFor(targetID)
	if err != nil {
		return err
	}
	token := client.Publish(topic, 0, false, payload)
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("relay: publish to target %q timed out", targetID)
	}
	return token.Error()
}

// clientOptionsFor builds the MQTT connection options for one target.
// Split out from clientFor so the credential wiring is testable without a
// live broker — the reason it needs to be is that dry_run mode never opens
// a connection, so nothing else exercises this path until a real publish.
func (p *PahoPublisher) clientOptionsFor(target config.RelayTarget) *mqtt.ClientOptions {
	opts := mqtt.NewClientOptions().
		AddBroker(brokerURL(target)).
		SetClientID(fmt.Sprintf("brokerd-relay-%s", target.ID)).
		SetConnectTimeout(10 * time.Second)
	if target.TLSEnabled {
		opts.SetTLSConfig(&tls.Config{})
	}
	// Only set credentials that exist: sending empty strings is not the
	// same as connecting anonymously, and some brokers reject the former.
	if target.Username != "" {
		opts.SetUsername(target.Username)
	}
	if target.Password != "" {
		opts.SetPassword(target.Password)
	}
	return opts
}

func (p *PahoPublisher) clientFor(targetID string) (mqtt.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.clients[targetID]; ok && c.IsConnected() {
		return c, nil
	}

	target, ok := p.targets[targetID]
	if !ok {
		return nil, fmt.Errorf("relay: unknown target %q", targetID)
	}

	client := mqtt.NewClient(p.clientOptionsFor(target))
	token := client.Connect()
	if !token.WaitTimeout(15 * time.Second) {
		return nil, fmt.Errorf("relay: connecting to target %q timed out", targetID)
	}
	if err := token.Error(); err != nil {
		return nil, fmt.Errorf("relay: connecting to target %q: %w", targetID, err)
	}

	p.clients[targetID] = client
	return client, nil
}

func brokerURL(target config.RelayTarget) string {
	scheme := "tcp"
	if target.TLSEnabled {
		scheme = "tls"
	}
	return fmt.Sprintf("%s://%s", scheme, target.Address)
}

// Close disconnects every connected client. Safe to call even if some
// (or all) targets were never connected.
func (p *PahoPublisher) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, c := range p.clients {
		c.Disconnect(250)
		delete(p.clients, id)
	}
}
