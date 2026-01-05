package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMain_Help(t *testing.T) {
	tests := []string{"-h", "--help", "help"}

	for _, arg := range tests {
		t.Run(arg, func(t *testing.T) {
			cmd := exec.Command("go", "run", ".", arg)
			output, _ := cmd.CombinedOutput()
			outputStr := string(output)
			if !strings.Contains(outputStr, "Usage: maskat") {
				t.Errorf("expected help output, got: %s", outputStr)
			}
			if !strings.Contains(outputStr, "list-sensitive-data") {
				t.Errorf("expected list-sensitive-data in help, got: %s", outputStr)
			}
		})
	}
}

func TestMain_UnknownCommand(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "unknown-command")
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("expected error for unknown command")
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "Unknown command") {
		t.Errorf("expected 'Unknown command' error, got: %s", outputStr)
	}
}

func TestMain_Mask(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Stdin = strings.NewReader("Contact test@example.com for help")

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	outputStr := string(output)
	// Should not contain the original email
	if strings.Contains(outputStr, "test@example.com") {
		t.Error("output should not contain original email")
	}
	// Should contain the masked hash
	if !strings.Contains(outputStr, "973dfe463ec857") {
		t.Errorf("output should contain masked hash, got: %s", outputStr)
	}
	// Should preserve other text
	if !strings.Contains(outputStr, "Contact") {
		t.Error("output should preserve other text")
	}
}

func TestMain_MaskMultipleLines(t *testing.T) {
	input := `Line 1: user1@example.com
Line 2: user2@test.org
Line 3: no email here`

	cmd := exec.Command("go", "run", ".")
	cmd.Stdin = strings.NewReader(input)

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// Line 1 should be masked
	if strings.Contains(lines[0], "user1@example.com") {
		t.Error("line 1 should have email masked")
	}
	// Line 2 should be masked
	if strings.Contains(lines[1], "user2@test.org") {
		t.Error("line 2 should have email masked")
	}
	// Line 3 should be unchanged
	if lines[2] != "Line 3: no email here" {
		t.Errorf("line 3 should be unchanged, got: %s", lines[2])
	}
}

func TestMain_ListSensitiveData_WithoutEnv(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "list-sensitive-data")
	cmd.Stdin = strings.NewReader("test@example.com")
	cmd.Env = filterEnv(os.Environ(), "MASKAT_LIST_SENSITIVE_DATA")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Error("expected error when env var is not set")
	}

	if !strings.Contains(stderr.String(), "MASKAT_LIST_SENSITIVE_DATA") {
		t.Errorf("expected error about env var, got: %s", stderr.String())
	}
}

func TestMain_ListSensitiveData_WithEnv(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "list-sensitive-data")
	cmd.Stdin = strings.NewReader("Contact test@example.com and admin@test.org")
	cmd.Env = append(os.Environ(), "MASKAT_LIST_SENSITIVE_DATA=1")

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	outputStr := string(output)
	// Should contain mapping for both emails
	if !strings.Contains(outputStr, "test@example.com ->") {
		t.Errorf("output should contain test@example.com mapping, got: %s", outputStr)
	}
	if !strings.Contains(outputStr, "admin@test.org ->") {
		t.Errorf("output should contain admin@test.org mapping, got: %s", outputStr)
	}
}

func TestMain_EmptyInput(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Stdin = strings.NewReader("")

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(output) != 0 {
		t.Errorf("expected empty output for empty input, got: %s", string(output))
	}
}

func TestMain_NoEmailsInInput(t *testing.T) {
	input := "This is just plain text without any emails"

	cmd := exec.Command("go", "run", ".")
	cmd.Stdin = strings.NewReader(input)

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr != input {
		t.Errorf("expected unchanged output, got: %s", outputStr)
	}
}

func TestMain_RFCViolatingEmails(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{"consecutive dots", "user..name@example.com"},
		{"leading dot", ".user@example.com"},
		{"trailing dot", "user.@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("go", "run", ".")
			cmd.Stdin = strings.NewReader("Email: " + tt.email)

			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if strings.Contains(string(output), tt.email) {
				t.Errorf("RFC-violating email should be masked: %s", tt.email)
			}
		})
	}
}

// filterEnv returns a new environment slice with the specified key removed
func filterEnv(env []string, key string) []string {
	result := make([]string, 0, len(env))
	prefix := key + "="
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			result = append(result, e)
		}
	}
	return result
}
