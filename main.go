package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// exposureRule defines an exposure detection rule with compiled regex patterns
// keyed by file extension.
type exposureRule struct {
	ID          string
	Description string
	Severity    pluginv1.Severity
	ConfLevel   pluginv1.Confidence
	Patterns    map[string]*regexp.Regexp // extension -> compiled regex
}

// Compiled regex patterns for each rule, grouped by language extension.
var rules = []exposureRule{
	{
		ID:          "EXPOSE-001",
		Description: "Exposed internal IP address or hostname in source code",
		Severity:    sdk.SeverityHigh,
		ConfLevel:   sdk.ConfidenceHigh,
		Patterns: map[string]*regexp.Regexp{
			".go":   regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|\w+\.internal\.\w+|\w+\.corp\.\w+|\w+\.local\b)`),
			".py":   regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|\w+\.internal\.\w+|\w+\.corp\.\w+|\w+\.local\b)`),
			".js":   regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|\w+\.internal\.\w+|\w+\.corp\.\w+|\w+\.local\b)`),
			".ts":   regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|\w+\.internal\.\w+|\w+\.corp\.\w+|\w+\.local\b)`),
			".json": regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|\w+\.internal\.\w+|\w+\.corp\.\w+|\w+\.local\b)`),
			".yaml": regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|\w+\.internal\.\w+|\w+\.corp\.\w+|\w+\.local\b)`),
		},
	},
	{
		ID:          "EXPOSE-002",
		Description: "Exposed email address in source code (potential PII leak)",
		Severity:    sdk.SeverityHigh,
		ConfLevel:   sdk.ConfidenceMedium,
		Patterns: map[string]*regexp.Regexp{
			".go":   regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			".py":   regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			".js":   regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			".ts":   regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			".json": regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			".yaml": regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		},
	},
	{
		ID:          "EXPOSE-003",
		Description: "Exposed file path pointing to system directory",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceHigh,
		Patterns: map[string]*regexp.Regexp{
			".go":   regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/var/log/\w+|/proc/self|/dev/null|C:\\Windows\\System32|C:\\Users\\)`),
			".py":   regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/var/log/\w+|/proc/self|/dev/null|C:\\Windows\\System32|C:\\Users\\)`),
			".js":   regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/var/log/\w+|/proc/self|/dev/null|C:\\Windows\\System32|C:\\Users\\)`),
			".ts":   regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/var/log/\w+|/proc/self|/dev/null|C:\\Windows\\System32|C:\\Users\\)`),
			".json": regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/var/log/\w+|/proc/self|C:\\Windows\\System32|C:\\Users\\)`),
			".yaml": regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/var/log/\w+|/proc/self|C:\\Windows\\System32|C:\\Users\\)`),
		},
	},
	{
		ID:          "EXPOSE-004",
		Description: "Exposed version information in user-facing response",
		Severity:    sdk.SeverityMedium,
		ConfLevel:   sdk.ConfidenceMedium,
		Patterns: map[string]*regexp.Regexp{
			".go":   regexp.MustCompile(`(?i)(Server:\s*(Apache|Nginx|IIS)/\d|X-Powered-By|version["':\s]+\d+\.\d+\.\d+)`),
			".py":   regexp.MustCompile(`(?i)(Server:\s*(Apache|Nginx|IIS)/\d|X-Powered-By|version["':\s]+\d+\.\d+\.\d+)`),
			".js":   regexp.MustCompile(`(?i)(Server:\s*(Apache|Nginx|IIS)/\d|X-Powered-By|version["':\s]+\d+\.\d+\.\d+)`),
			".ts":   regexp.MustCompile(`(?i)(Server:\s*(Apache|Nginx|IIS)/\d|X-Powered-By|version["':\s]+\d+\.\d+\.\d+)`),
			".json": regexp.MustCompile(`(?i)("server"\s*:\s*"(Apache|Nginx|IIS)/\d|"X-Powered-By"|"version"\s*:\s*"\d+\.\d+\.\d+")`),
			".yaml": regexp.MustCompile(`(?i)(server:\s*(Apache|Nginx|IIS)/\d|X-Powered-By|version:\s*['"]?\d+\.\d+\.\d+)`),
		},
	},
}

// supportedExtensions lists file extensions the exposure scanner processes.
var supportedExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".json": true,
	".yaml": true,
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/exposure", version).
		Capability("exposure", "Exposure correlation and sensitive data pattern detection").
		Tool("scan", "Scan source files for exposed sensitive data patterns including IPs, emails, system paths, and version info", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !supportedExtensions[ext] {
			return nil
		}

		return scanFile(resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

func scanFile(resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil // skip unreadable files
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for i := range rules {
			rule := &rules[i]
			pattern, ok := rule.Patterns[ext]
			if !ok {
				continue
			}
			if pattern.MatchString(line) {
				resp.Finding(
					rule.ID,
					rule.Severity,
					rule.ConfLevel,
					fmt.Sprintf("%s: %s", rule.Description, strings.TrimSpace(line)),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("language", extToLanguage(ext)).
					Done()
			}
		}
	}

	return scanner.Err()
}

func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".json":
		return "json"
	case ".yaml":
		return "yaml"
	default:
		return "unknown"
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-exposure: %v\n", err)
		os.Exit(1)
	}
}
