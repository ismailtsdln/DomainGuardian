package validation

import (
	"github.com/ismailtsdln/DomainGuardian/internal/fingerprints"
	"github.com/ismailtsdln/DomainGuardian/internal/models"
)

// Validator orchestrates the validation process
type Validator struct {
	FingerprintEngine *fingerprints.Engine
}

// NewValidator creates a new validator
func NewValidator(fe *fingerprints.Engine) *Validator {
	return &Validator{
		FingerprintEngine: fe,
	}
}

// Validate processes a result and assigns confidence scores
func (v *Validator) Validate(result *models.Result) {
	fp := v.FingerprintEngine.Match(result)
	if fp != nil {
		result.Provider = fp.Service
		result.Fingerprint = fp.Service
		result.TakeoverPossible = fp.TakeoverPossible

		// Scoring Logic
		if result.HTTPStatus == fp.HTTPStatus && fp.HTTPStatus != 0 {
			result.Confidence = models.ConfidenceHigh
		} else if result.HTTPStatus != 0 {
			result.Confidence = models.ConfidenceMedium
		} else {
			result.Confidence = models.ConfidenceLow
		}
	} else {
		result.Confidence = models.ConfidenceLow
		result.TakeoverPossible = false
	}
}
