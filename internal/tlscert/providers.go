package tlscert

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
)

// dnsProviderFactories is a small, explicit registry of supported
// DNS-01 providers (ADR-8, docs/adr.md).
//
// This is deliberately NOT lego's own
// providers/dns.NewDNSChallengeProviderByName — that function's
// package imports all ~200 of lego's provider packages (and their full
// SDKs: AWS, Azure, GCP, Alibaba, Tencent, etc.) unconditionally, just
// to offer lookup-by-name. That ballooned this project's dependency
// graph by hundreds of indirect modules to support one provider
// (discovered while implementing this package, not a hypothetical).
//
// Adding support for a new DNS provider means importing its lego
// package here and adding one line below — see
// https://go-acme.github.io/lego/dns/<name>/ for the provider's
// required environment variables. This is a small, explicit cost
// (one import + one line) traded for not vendoring 200 cloud SDKs.
var dnsProviderFactories = map[string]func() (challenge.Provider, error){
	"cloudflare": func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() },
}

func newDNSProvider(name string) (challenge.Provider, error) {
	factory, ok := dnsProviderFactories[name]
	if !ok {
		supported := supportedDNSProviderNames()
		return nil, fmt.Errorf("tlscert: unsupported DNS provider %q (supported: %v) — add it in internal/tlscert/providers.go", name, supported)
	}
	return factory()
}

// supportedDNSProviderNames returns the registry's keys, for error
// messages and (later) config validation.
func supportedDNSProviderNames() []string {
	names := make([]string, 0, len(dnsProviderFactories))
	for n := range dnsProviderFactories {
		names = append(names, n)
	}
	return names
}
