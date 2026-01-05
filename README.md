# maskat
maskat is "cat with mask sensitive data"

## Installation

```bash
go install github.com/maskat/maskat@latest
```

Or build from source:

```bash
go build -o maskat .
```

## Usage

### Basic Usage

Pipe text through maskat to mask email addresses:

```bash
echo "Contact us at user@example.com" | maskat
# Output: Contact us at 973dfe463ec857
```

Email addresses are replaced with the first 14 characters of their SHA256 hash.

### List Sensitive Data

To see the mapping between original emails and their masked values:

```bash
MASKAT_LIST_SENSITIVE_DATA=1 maskat list-sensitive-data < input.txt
# Output:
# user@example.com -> 973dfe463ec857
# admin@company.org -> a1b2c3d4e5f678
```

This command requires the `MASKAT_LIST_SENSITIVE_DATA` environment variable to be set for security reasons.

### Help

```bash
maskat --help
```

## Features

- Masks email addresses in text streams
- Handles RFC-violating email addresses (e.g., consecutive dots, leading/trailing dots)
- Deterministic masking (same email always produces the same hash)
- Supports long lines (up to 1MB per line)
- `list-sensitive-data` subcommand to audit replacements

## License

MIT License - see [LICENSE](LICENSE) for details.
