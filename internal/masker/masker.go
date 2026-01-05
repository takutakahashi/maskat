package masker

import (
	"crypto/sha256"
	"fmt"
	"regexp"
)

// emailRegex matches email addresses including RFC-violating ones
// This regex is intentionally permissive to catch:
// - Standard RFC 5322 compliant emails
// - RFC-violating emails with consecutive dots (e.g., user..name@example.com)
// - RFC-violating emails with dots at start/end of local part (e.g., .user@example.com)
// - Emails with special characters in local part
var emailRegex = regexp.MustCompile(`(?i)[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~.-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+`)

// Replacement represents a single email replacement
type Replacement struct {
	Original string
	Masked   string
}

// Masker handles email masking operations
type Masker struct {
	replacements []Replacement
}

// New creates a new Masker instance
func New() *Masker {
	return &Masker{
		replacements: make([]Replacement, 0),
	}
}

// hashEmail generates SHA256 hash of email and returns first 14 characters
func hashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return fmt.Sprintf("%x", hash)[:14]
}

// Mask replaces all email addresses in text with their SHA256 hash (first 14 chars)
func (m *Masker) Mask(text string) string {
	return emailRegex.ReplaceAllStringFunc(text, func(email string) string {
		masked := hashEmail(email)
		m.replacements = append(m.replacements, Replacement{
			Original: email,
			Masked:   masked,
		})
		return masked
	})
}

// GetReplacements returns all replacements made during masking
func (m *Masker) GetReplacements() []Replacement {
	return m.replacements
}

// Reset clears all recorded replacements
func (m *Masker) Reset() {
	m.replacements = make([]Replacement, 0)
}
