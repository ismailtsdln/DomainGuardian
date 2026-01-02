package fingerprints

import (
	"os"
	"strings"

	"github.com/ismailtsdln/DomainGuardian/internal/models"
	"gopkg.in/yaml.v3"
)

// Engine handles fingerprint matching
type Engine struct {
	Fingerprints []models.Fingerprint
}

// NewEngine creates a new fingerprint engine
func NewEngine() *Engine {
	return &Engine{
		Fingerprints: []models.Fingerprint{},
	}
}

// LoadFromYAML loads fingerprints from a YAML file
func (e *Engine) LoadFromYAML(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	var fps []models.Fingerprint
	err = yaml.Unmarshal(data, &fps)
	if err != nil {
		return err
	}

	e.Fingerprints = append(e.Fingerprints, fps...)
	return nil
}

// Match checks if a result matches any fingerprint
func (e *Engine) Match(result *models.Result) *models.Fingerprint {
	for _, fp := range e.Fingerprints {
		// Match by CNAME
		for _, pattern := range fp.CNAMEPatterns {
			for _, cname := range result.CNAMEs {
				if strings.Contains(cname, strings.ReplaceAll(pattern, "*", "")) {
					// Potential match, check HTTP status and body if defined
					if dmatch(result, &fp) {
						return &fp
					}
				}
			}
		}
	}
	return nil
}

func dmatch(result *models.Result, fp *models.Fingerprint) bool {
	// If fingerprint specifies HTTP status, it must match
	if fp.HTTPStatus != 0 && result.HTTPStatus != fp.HTTPStatus {
		return false
	}

	// If fingerprint specifies body content, it must match
	if len(fp.BodyContains) > 0 {
		found := false
		for _, snippet := range fp.BodyContains {
			if strings.Contains(result.Evidence, snippet) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
