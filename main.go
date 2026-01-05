package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/maskat/maskat/internal/masker"
)

const (
	envListSensitiveData = "MASKAT_LIST_SENSITIVE_DATA"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "list-sensitive-data":
			runListSensitiveData()
			return
		case "-h", "--help", "help":
			printUsage()
			return
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
			printUsage()
			os.Exit(1)
		}
	}

	// Default behavior: mask stdin and output to stdout
	runMask()
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: maskat [command]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "maskat is 'cat with mask sensitive data'")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  (none)              Read from stdin and output masked text to stdout")
	fmt.Fprintln(os.Stderr, "  list-sensitive-data List all replacements (original -> masked)")
	fmt.Fprintln(os.Stderr, "                      Requires MASKAT_LIST_SENSITIVE_DATA environment variable")
	fmt.Fprintln(os.Stderr, "  help, -h, --help    Show this help message")
}

func runMask() {
	m := masker.New()
	scanner := bufio.NewScanner(os.Stdin)

	// Increase buffer size to handle long lines
	const maxCapacity = 1024 * 1024 // 1MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Text()
		masked := m.Mask(line)
		fmt.Println(masked)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
}

func runListSensitiveData() {
	if os.Getenv(envListSensitiveData) == "" {
		fmt.Fprintf(os.Stderr, "Error: %s environment variable is not set\n", envListSensitiveData)
		fmt.Fprintln(os.Stderr, "This command requires explicit opt-in for security reasons.")
		os.Exit(1)
	}

	m := masker.New()
	scanner := bufio.NewScanner(os.Stdin)

	// Increase buffer size to handle long lines
	const maxCapacity = 1024 * 1024 // 1MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Text()
		m.Mask(line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	// Output replacements
	for _, r := range m.GetReplacements() {
		fmt.Printf("%s -> %s\n", r.Original, r.Masked)
	}
}
