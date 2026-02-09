# nox-plugin-exposure

**Exposure correlation and sensitive data pattern detection.**

## Overview

`nox-plugin-exposure` scans source code and configuration files for patterns that expose sensitive internal information -- private IP addresses, internal hostnames, email addresses, system file paths, and server version fingerprints. These exposure patterns create information leakage vectors that attackers use during reconnaissance to map internal infrastructure, identify targets, and plan attacks.

Exposed information is often dismissed as low-risk, but it plays a critical role in the attack chain. A hardcoded internal IP address (`10.0.1.42`) in a JavaScript frontend reveals network topology. An email address in source code (`alice.johnson@acme.com`) enables targeted phishing. A server version header (`Apache/2.4.51`) tells attackers exactly which CVEs to exploit. This plugin systematically detects these patterns across source code and configuration files, correlating multiple exposure signals to reveal the broader attack surface.

The plugin belongs to the **Intelligence** track and operates with a passive risk class. It performs read-only analysis without making any network requests or modifying files.

## Use Cases

### Preventing Internal Network Topology Leakage

A frontend application contains API client code that references `http://10.0.1.42:8080/api/v2` -- an internal service IP that was used during development. If this code is deployed to a browser-facing application, it reveals the internal network topology to anyone who views the page source. The exposure plugin catches all RFC 1918 private IP addresses, `.internal.*` hostnames, and `.corp.*` hostnames in source code.

### PII Detection for GDPR Compliance

A codebase review reveals that email addresses are scattered throughout configuration files, test fixtures, and even production code. For GDPR compliance, the team needs to identify every instance where personal data (email addresses) appears in the codebase. The exposure plugin detects email address patterns across all supported file types, helping the team identify and remove or anonymize PII.

### Eliminating Server Version Fingerprinting

An API service returns version information in response headers (`Server: Nginx/1.21.3`, `X-Powered-By: Express`) or in JSON responses (`"version": "3.2.1"`). This information helps attackers identify specific software versions and their known vulnerabilities. The exposure plugin flags these version disclosure patterns so the team can strip version information from user-facing responses.

### System Path Disclosure Audit

A security audit requires verifying that no production code references system paths like `/etc/passwd`, `/proc/self`, or `C:\Windows\System32`. These references in source code can indicate path traversal vulnerabilities or information disclosure risks. The exposure plugin detects system path patterns across all supported languages and configuration formats.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/nox-hq/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install nox-hq/nox-plugin-exposure
   ```

2. **Create a test project with exposure patterns**

   ```bash
   mkdir -p demo-exposure && cd demo-exposure
   ```

   Create `app.go`:

   ```go
   package main

   import (
       "fmt"
       "net/http"
       "os"
   )

   const (
       internalAPI = "http://10.0.1.42:8080/api/v2"
       backupHost  = "db-primary.internal.acme.com"
       adminEmail  = "admin@acme-corp.com"
   )

   func healthHandler(w http.ResponseWriter, r *http.Request) {
       w.Header().Set("Server", "Nginx/1.21.3")
       w.Header().Set("X-Powered-By", "Go")
       logPath := "/var/log/myapp/access.log"
       fmt.Fprintf(w, `{"status":"ok","version":"2.4.1","log":"%s"}`, logPath)
   }

   func main() {
       http.HandleFunc("/health", healthHandler)
       http.ListenAndServe(":"+os.Getenv("PORT"), nil)
   }
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/exposure .
   ```

4. **Review findings**

   ```
   EXPOSE-001  HIGH/HIGH   app.go:10  Exposed internal IP address or hostname in source code: internalAPI = "http://10.0.1.42:8080/api/v2"
   EXPOSE-001  HIGH/HIGH   app.go:11  Exposed internal IP address or hostname in source code: backupHost  = "db-primary.internal.acme.com"
   EXPOSE-002  HIGH/MED    app.go:12  Exposed email address in source code (potential PII leak): adminEmail  = "admin@acme-corp.com"
   EXPOSE-003  MED/HIGH    app.go:18  Exposed file path pointing to system directory: logPath := "/var/log/myapp/access.log"
   EXPOSE-004  MED/MED     app.go:16  Exposed version information in user-facing response: w.Header().Set("Server", "Nginx/1.21.3")
   EXPOSE-004  MED/MED     app.go:17  Exposed version information in user-facing response: w.Header().Set("X-Powered-By", "Go")
   EXPOSE-004  MED/MED     app.go:19  Exposed version information in user-facing response: fmt.Fprintf(w, `{"status":"ok","version":"2.4.1","log":"%s"}`, logPath)

   7 findings (3 high, 4 medium)
   ```

## Rules

| Rule ID    | Description                                                      | Severity | Confidence | CWE |
|------------|------------------------------------------------------------------|----------|------------|-----|
| EXPOSE-001 | Exposed internal IP address or hostname (RFC 1918, .internal, .corp, .local) | HIGH     | HIGH       | --  |
| EXPOSE-002 | Exposed email address in source code (potential PII leak)        | HIGH     | MEDIUM     | --  |
| EXPOSE-003 | Exposed file path pointing to system directory (/etc, /proc, /var/log, C:\Windows) | MEDIUM   | HIGH       | --  |
| EXPOSE-004 | Exposed version information in user-facing response (Server header, X-Powered-By, version strings) | MEDIUM   | MEDIUM     | --  |

### Patterns Detected

| Category           | Patterns                                                                |
|--------------------|-------------------------------------------------------------------------|
| Internal IPs       | `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`                           |
| Internal Hostnames | `*.internal.*`, `*.corp.*`, `*.local`                                  |
| Email Addresses    | Standard email format (`user@domain.tld`)                              |
| System Paths       | `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/var/log/*`, `/proc/self`, `C:\Windows\System32`, `C:\Users\` |
| Version Info       | `Server: Apache/x`, `Server: Nginx/x`, `Server: IIS/x`, `X-Powered-By`, `version: x.y.z` |

## Supported Languages / File Types

| Language / Format | Extension |
|-------------------|-----------|
| Go                | `.go`     |
| Python            | `.py`     |
| JavaScript        | `.js`     |
| TypeScript        | `.ts`     |
| JSON              | `.json`   |
| YAML              | `.yaml`   |

## Configuration

The plugin uses Nox's standard configuration. No additional configuration is required.

```yaml
# .nox.yaml (optional)
plugins:
  nox/exposure:
    enabled: true
```

Directories automatically skipped during scanning: `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`.

## Installation

### Via Nox (recommended)

```bash
nox plugin install nox-hq/nox-plugin-exposure
```

### Standalone

```bash
go install github.com/nox-hq/nox-plugin-exposure@latest
```

### From source

```bash
git clone https://github.com/nox-hq/nox-plugin-exposure.git
cd nox-plugin-exposure
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run all tests
make test

# Run linter
make lint

# Build Docker image
docker build -t nox-plugin-exposure .

# Clean build artifacts
make clean
```

## Architecture

The plugin operates as a Nox plugin server communicating over stdio using the Nox Plugin SDK. The scan uses a straightforward line-by-line matching approach:

1. **File Discovery** -- Recursively walks the workspace directory, filtering by supported extensions (`.go`, `.py`, `.js`, `.ts`, `.json`, `.yaml`) and skipping common non-source directories.
2. **Line-by-Line Matching** -- Each file is read line-by-line. Every line is tested against all exposure rule patterns for the matching file extension. Each rule has a single compiled regex per extension (unlike the DAST plugin which has multiple patterns per extension per rule).
3. **Finding Emission** -- Each match produces a finding with the rule ID, severity, confidence, the matched line content, and file location metadata. The finding message includes the full description and the trimmed source line for context.

The plugin uses a flat rule structure where each rule maps file extensions to a single compiled regex. This design makes it simple to add new exposure patterns or support new file types.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/nox-hq/nox-plugin-exposure).

When adding new exposure rules:
1. Define a new `exposureRule` in the `rules` slice with an ID, description, severity, confidence, and per-extension regex patterns.
2. Add corresponding test cases in `main_test.go` with sample files in `testdata/`.
3. Consider whether the pattern needs different regex variants for different file types.

## License

Apache-2.0
