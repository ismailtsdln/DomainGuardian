package engine

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/ismailtsdln/DomainGuardian/internal/models"
)

// DNSResolver handles DNS lookups for subdomains
type DNSResolver struct {
	Resolver *net.Resolver
	Timeout  time.Duration
}

// NewDNSResolver creates a new DNSResolver with default settings
func NewDNSResolver(timeout time.Duration) *DNSResolver {
	return &DNSResolver{
		Resolver: &net.Resolver{},
		Timeout:  timeout,
	}
}

// Resolve fetches A, AAAA, CNAME, and NS records for a subdomain
func (d *DNSResolver) Resolve(subdomain string) (*models.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	result := &models.Result{
		Subdomain: subdomain,
		Timestamp: time.Now(),
	}

	// Resolve CNAME
	cname, err := d.Resolver.LookupCNAME(ctx, subdomain)
	if err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != subdomain {
			result.CNAMEs = append(result.CNAMEs, cname)
		}
	}

	// Resolve IPs (A and AAAA)
	ips, err := d.Resolver.LookupHost(ctx, subdomain)
	if err == nil {
		result.IPs = ips
	}

	// Resolve NS
	ns, err := d.Resolver.LookupNS(ctx, subdomain)
	if err == nil {
		for _, n := range ns {
			result.NS = append(result.NS, strings.TrimSuffix(n.Host, "."))
		}
	}

	return result, nil
}

// IsWildcard checks if a subdomain is part of a wildcard DNS entry
func (d *DNSResolver) IsWildcard(subdomain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	parts := strings.Split(subdomain, ".")
	if len(parts) < 3 {
		return false
	}
	parent := strings.Join(parts[1:], ".")

	randomSub := "dg-" + time.Now().Format("02150405") + "." + parent
	_, err := d.Resolver.LookupHost(ctx, randomSub)
	return err == nil
}
