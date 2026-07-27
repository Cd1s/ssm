package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type environmentLookup func(string) (string, bool)

func newIsolatedProcessEnvironment(tempDir string) ([]string, error) {
	for _, directory := range []string{
		"home",
		"xdg-config",
		"xdg-cache",
		"xdg-data",
		"xdg-state",
		"tmp",
		"go-build",
		"go-mod",
		"gopath",
		"golangci-lint",
	} {
		if err := os.MkdirAll(filepath.Join(tempDir, directory), 0o700); err != nil { //nolint:gosec // tempDir is verifier-created and directory is from the fixed list above
			return nil, fmt.Errorf("create isolated environment directory %s: %w", directory, err)
		}
	}
	return isolatedEnvironmentForOS(tempDir, runtime.GOOS, os.LookupEnv)
}

func isolatedEnvironmentForOS(tempDir, goos string, lookup environmentLookup) ([]string, error) {
	path, ok := lookup("PATH")
	if !ok || path == "" {
		return nil, fmt.Errorf("PATH is required for verification children")
	}

	values := map[string]string{
		"PATH":                   path,
		"HOME":                   environmentPath(tempDir, goos, "home"),
		"XDG_CONFIG_HOME":        environmentPath(tempDir, goos, "xdg-config"),
		"XDG_CACHE_HOME":         environmentPath(tempDir, goos, "xdg-cache"),
		"XDG_DATA_HOME":          environmentPath(tempDir, goos, "xdg-data"),
		"XDG_STATE_HOME":         environmentPath(tempDir, goos, "xdg-state"),
		"TMPDIR":                 environmentPath(tempDir, goos, "tmp"),
		"TMP":                    environmentPath(tempDir, goos, "tmp"),
		"TEMP":                   environmentPath(tempDir, goos, "tmp"),
		"GOCACHE":                environmentPath(tempDir, goos, "go-build"),
		"GOMODCACHE":             environmentPath(tempDir, goos, "go-mod"),
		"GOPATH":                 environmentPath(tempDir, goos, "gopath"),
		"GOLANGCI_LINT_CACHE":    environmentPath(tempDir, goos, "golangci-lint"),
		"GOENV":                  "off",
		"GOTOOLCHAIN":            "local",
		"GIT_CONFIG_NOSYSTEM":    "1",
		"GIT_CONFIG_GLOBAL":      environmentPath(tempDir, goos, "xdg-config", "gitconfig"),
		"GIT_TERMINAL_PROMPT":    "0",
		"GCM_INTERACTIVE":        "Never",
		"GIT_ASKPASS":            "",
		"SSH_ASKPASS":            "",
		"GIT_PAGER":              "cat",
		"GIT_OPTIONAL_LOCKS":     "0",
		"GOVCS":                  "public:git|hg,private:off",
		"GOTELEMETRY":            "off",
		"GO111MODULE":            "on",
		"GOFLAGS":                "",
		"GIT_PROTOCOL_FROM_USER": "0",
	}

	for _, name := range []string{
		"LANG",
		"LC_ALL",
		"LC_CTYPE",
		"TZ",
		"SSL_CERT_FILE",
		"SSL_CERT_DIR",
		"SSHD",
		"GOPROXY",
		"GOSUMDB",
		"GONOSUMDB",
		"GOPRIVATE",
		"GONOPROXY",
	} {
		if value, present := lookup(name); present {
			if name == "GOPROXY" {
				if err := validateUnauthenticatedGoProxy(value); err != nil {
					return nil, err
				}
			}
			values[name] = value
		}
	}

	if goos == "windows" {
		values["USERPROFILE"] = values["HOME"]
		values["APPDATA"] = values["XDG_CONFIG_HOME"]
		values["LOCALAPPDATA"] = values["XDG_CACHE_HOME"]
		for _, name := range []string{"SystemRoot", "WINDIR", "ComSpec", "PATHEXT"} {
			if value, present := lookup(name); present {
				values[name] = value
			}
		}
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}

func validateUnauthenticatedGoProxy(value string) error {
	for _, entry := range strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == '|'
	}) {
		if entry == "" || entry == "direct" || entry == "off" {
			continue
		}
		parsed, err := url.Parse(entry)
		if err != nil {
			return fmt.Errorf("GOPROXY entry %q is invalid: %w", entry, err)
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("GOPROXY entry %q may contain authentication material", entry)
		}
	}
	return nil
}

func environmentPath(root, goos string, components ...string) string {
	separator := "/"
	if goos == "windows" {
		separator = `\`
	}
	value := strings.TrimRight(root, `/\`)
	for _, component := range components {
		value += separator + component
	}
	return value
}

func environmentValue(environment []string, name string) (string, bool) {
	prefix := name + "="
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix), true
		}
	}
	return "", false
}
