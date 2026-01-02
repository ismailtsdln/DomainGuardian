package engine

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/ismailtsdln/DomainGuardian/internal/models"
)

// HTTPValidator handles HTTP probing for subdomains
type HTTPValidator struct {
	Client  *http.Client
	Timeout time.Duration
}

// NewHTTPValidator creates a new HTTPValidator with default settings
func NewHTTPValidator(timeout time.Duration) *HTTPValidator {
	return &HTTPValidator{
		Client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects to keep validation accurate
			},
		},
		Timeout: timeout,
	}
}

// Probe performs an HTTP GET request to the subdomain
func (h *HTTPValidator) Probe(result *models.Result) error {
	url := "http://" + result.Subdomain

	resp, err := h.Client.Get(url)
	if err != nil {
		// Try HTTPS if HTTP fails or just report the error
		url = "https://" + result.Subdomain
		resp, err = h.Client.Get(url)
		if err != nil {
			return err
		}
	}
	defer resp.Body.Close()

	result.HTTPStatus = resp.StatusCode

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
	if err == nil {
		result.Evidence = string(body)
	}

	return nil
}
