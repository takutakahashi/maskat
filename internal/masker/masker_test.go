package masker

import (
	"strings"
	"testing"
)

func TestHashEmail(t *testing.T) {
	// Test that hash is deterministic
	email := "test@example.com"
	hash1 := hashEmail(email)
	hash2 := hashEmail(email)

	if hash1 != hash2 {
		t.Errorf("hashEmail should be deterministic, got %s and %s", hash1, hash2)
	}

	// Test that hash is 14 characters
	if len(hash1) != 14 {
		t.Errorf("hashEmail should return 14 characters, got %d", len(hash1))
	}

	// Test that different emails produce different hashes
	email2 := "other@example.com"
	hash3 := hashEmail(email2)
	if hash1 == hash3 {
		t.Error("Different emails should produce different hashes")
	}
}

func TestMask_StandardEmails(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int // number of emails to mask
	}{
		{
			name:     "single email",
			input:    "Contact us at test@example.com",
			expected: 1,
		},
		{
			name:     "multiple emails",
			input:    "From user1@test.com to user2@test.org",
			expected: 2,
		},
		{
			name:     "no emails",
			input:    "No email addresses here",
			expected: 0,
		},
		{
			name:     "email with subdomain",
			input:    "Send to admin@mail.company.co.jp",
			expected: 1,
		},
		{
			name:     "email with plus sign",
			input:    "Tagged email user+tag@example.com",
			expected: 1,
		},
		{
			name:     "email with numbers",
			input:    "user123@test456.com",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New()
			result := m.Mask(tt.input)
			replacements := m.GetReplacements()

			if len(replacements) != tt.expected {
				t.Errorf("expected %d replacements, got %d", tt.expected, len(replacements))
			}

			// Verify all originals are replaced
			for _, r := range replacements {
				if strings.Contains(result, r.Original) {
					t.Errorf("original email %s should not be in result", r.Original)
				}
				if !strings.Contains(result, r.Masked) {
					t.Errorf("masked value %s should be in result", r.Masked)
				}
			}
		})
	}
}

func TestMask_RFCViolatingEmails(t *testing.T) {
	tests := []struct {
		name  string
		input string
		email string // the RFC-violating email that should be masked
	}{
		{
			name:  "consecutive dots",
			input: "RFC violation: user..name@example.com",
			email: "user..name@example.com",
		},
		{
			name:  "leading dot",
			input: "Leading dot: .user@example.com",
			email: ".user@example.com",
		},
		{
			name:  "trailing dot in local part",
			input: "Trailing dot: user.@example.com",
			email: "user.@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New()
			result := m.Mask(tt.input)
			replacements := m.GetReplacements()

			if len(replacements) != 1 {
				t.Errorf("expected 1 replacement, got %d", len(replacements))
				return
			}

			if replacements[0].Original != tt.email {
				t.Errorf("expected original %s, got %s", tt.email, replacements[0].Original)
			}

			if strings.Contains(result, tt.email) {
				t.Errorf("RFC-violating email %s should be masked in result", tt.email)
			}
		})
	}
}

func TestMask_Deterministic(t *testing.T) {
	m1 := New()
	m2 := New()

	input := "Email: test@example.com"
	result1 := m1.Mask(input)
	result2 := m2.Mask(input)

	if result1 != result2 {
		t.Errorf("masking should be deterministic, got %s and %s", result1, result2)
	}
}

func TestGetReplacements(t *testing.T) {
	m := New()
	m.Mask("Contact test@example.com and other@test.org")

	replacements := m.GetReplacements()
	if len(replacements) != 2 {
		t.Fatalf("expected 2 replacements, got %d", len(replacements))
	}

	// Verify structure
	for _, r := range replacements {
		if r.Original == "" {
			t.Error("Original should not be empty")
		}
		if r.Masked == "" {
			t.Error("Masked should not be empty")
		}
		if len(r.Masked) != 14 {
			t.Errorf("Masked should be 14 characters, got %d", len(r.Masked))
		}
	}
}

func TestReset(t *testing.T) {
	m := New()
	m.Mask("Email: test@example.com")

	if len(m.GetReplacements()) != 1 {
		t.Error("expected 1 replacement before reset")
	}

	m.Reset()

	if len(m.GetReplacements()) != 0 {
		t.Error("expected 0 replacements after reset")
	}
}

func TestEmailRegex_ValidEmails(t *testing.T) {
	validEmails := []string{
		"simple@example.com",
		"very.common@example.com",
		"disposable.style.email.with+symbol@example.com",
		"other.email-with-hyphen@example.com",
		"fully-qualified-domain@example.com",
		"user.name+tag+sorting@example.com",
		"x@example.com",
		"example-indeed@strange-example.com",
		"admin@mailserver1.example.org",
		"example@s.example",
		"user-@example.org",
		// RFC-violating but should still be caught
		"user..double..dots@example.com",
		".leadingdot@example.com",
		"trailingdot.@example.com",
	}

	for _, email := range validEmails {
		t.Run(email, func(t *testing.T) {
			if !emailRegex.MatchString(email) {
				t.Errorf("email %s should match regex", email)
			}
		})
	}
}

func TestEmailRegex_InvalidStrings(t *testing.T) {
	invalidStrings := []string{
		"plainaddress",
		"@missinglocal.com",
		"missing@",
		"missing.domain@",
	}

	for _, s := range invalidStrings {
		t.Run(s, func(t *testing.T) {
			matches := emailRegex.FindAllString(s, -1)
			// These should either not match or match a different part
			for _, match := range matches {
				if match == s {
					t.Errorf("invalid string %s should not fully match as email", s)
				}
			}
		})
	}
}
