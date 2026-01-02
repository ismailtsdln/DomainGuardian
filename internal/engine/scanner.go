package engine

import (
	"sync"
	"time"

	"github.com/ismailtsdln/DomainGuardian/internal/models"
	"github.com/ismailtsdln/DomainGuardian/internal/validation"
)

// Scanner coordinates the scanning process
type Scanner struct {
	DNSResolver   *DNSResolver
	HTTPValidator *HTTPValidator
	Validator     *validation.Validator
	Threads       int
}

// NewScanner creates a new scanner instance
func NewScanner(threads int, timeout time.Duration, validator *validation.Validator) *Scanner {
	return &Scanner{
		DNSResolver:   NewDNSResolver(timeout),
		HTTPValidator: NewHTTPValidator(timeout),
		Validator:     validator,
		Threads:       threads,
	}
}

// Scan performs a scan on a list of subdomains
func (s *Scanner) Scan(subdomains []string) <-chan models.Result {
	results := make(chan models.Result, len(subdomains))
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.Threads)

	go func() {
		for _, sub := range subdomains {
			wg.Add(1)
			sem <- struct{}{} // Acquire token

			go func(subdomain string) {
				defer wg.Done()
				defer func() { <-sem }() // Release token

				if s.DNSResolver.IsWildcard(subdomain) {
					// Suppression of wildcard domains to avoid noise
					return
				}

				result, err := s.DNSResolver.Resolve(subdomain)
				if err != nil {
					// Log error or handle it
					return
				}

				// Only probe HTTP if there are records found (A/CNAME/NS)
				if len(result.IPs) > 0 || len(result.CNAMEs) > 0 || len(result.NS) > 0 {
					_ = s.HTTPValidator.Probe(result)
					s.Validator.Validate(result)
					results <- *result
				}
			}(sub)
		}

		wg.Wait()
		close(results)
	}()

	return results
}
