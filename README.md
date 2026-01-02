# DomainGuardian 🛡️

**DomainGuardian** is a high-performance, accurate subdomain takeover detection platform. Designed for security researchers, bug bounty hunters, and red teams, it focuses on minimizing false positives through multi-layer validation.

## 🚀 Key Features

- **High Accuracy**: Aggressive false-positive suppression using multi-layered DNS and HTTP validation.
- **Fast & Scalable**: Efficient worker pool architecture for scanning millions of subdomains.
- **Fingerprint Driven**: Easily extensible YAML-based service signatures.
- **Wildcard Detection**: Automatic detection and suppression of wildcard DNS entries to reduce noise.
- **Modern CLI**: Intuitive interface with support for multiple output formats (Table, JSON, Markdown).

## 🛠️ Installation

### Using Go

```bash
go install github.com/ismailtsdln/DomainGuardian/cmd/domainguardian@latest
```

### Using Docker

```bash
docker build -t domainguardian .
docker run domainguardian scan -d example.com
```

## 📖 Usage

### Scan a single domain

```bash
domainguardian scan -d sub.example.com
```

### Scan from a list of subdomains

```bash
domainguardian scan -i subdomains.txt --threads 50
```

### Export to Markdown (Bug Bounty Ready)

```bash
domainguardian scan -i targets.txt -f md > report.md
```

### Flags

- `-i, --input`: Path to a file containing subdomains.
- `-d, --domain`: Single subdomain to scan.
- `-t, --threads`: Number of concurrent workers (default: 10).
- `-f, --format`: Output format: `table`, `json`, `md` (default: `table`).
- `--timeout`: Timeout in seconds for DNS/HTTP requests (default: 10s).

## 🏗️ Architecture

DomainGuardian follows a clean, modular architecture:

- **Scanner Engine**: Orchestrates DNS resolution and HTTP probing.
- **Fingerprint Engine**: Matches discovered patterns against known service signatures.
- **Validation Layer**: Assesses confidence scores based on DNS records and HTTP response evidence.
- **Output Layer**: Handles pretty printing and machine-readable data export.

## 🧩 Adding Fingerprints

Fingerprints are stored in `internal/fingerprints/data/fingerprints.yaml`. You can add new providers by following this schema:

```yaml
- service: My Service
  cname_patterns: ["myservice.io"]
  http_status: 404
  body_contains: ["No such space", "Domain not configured"]
  takeover_possible: true
```

## ⚖️ Legal Disclaimer

Usage of DomainGuardian for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 📄 License

This project is licensed under the MIT License.
