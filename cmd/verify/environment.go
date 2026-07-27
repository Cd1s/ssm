package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"ssm/internal/privatepath"
)

type environmentLookup func(string) (string, bool)

type verifierCache struct {
	Root    string
	GoBuild string
	GoMod   string
	GoPath  string
}

func newIsolatedProcessEnvironment(tempDir string) ([]string, error) {
	cache := verifierCache{
		Root:    tempDir,
		GoBuild: filepath.Join(tempDir, "go-build"),
		GoMod:   filepath.Join(tempDir, "go-mod"),
		GoPath:  filepath.Join(tempDir, "gopath"),
	}
	return newIsolatedProcessEnvironmentWithCache(tempDir, cache)
}

func newIsolatedProcessEnvironmentWithCache(tempDir string, cache verifierCache) ([]string, error) {
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
	return isolatedEnvironmentForOSWithCache(tempDir, runtime.GOOS, os.LookupEnv, cache)
}

func isolatedEnvironmentForOS(tempDir, goos string, lookup environmentLookup) ([]string, error) {
	cache := verifierCache{
		Root:    tempDir,
		GoBuild: environmentPath(tempDir, goos, "go-build"),
		GoMod:   environmentPath(tempDir, goos, "go-mod"),
		GoPath:  environmentPath(tempDir, goos, "gopath"),
	}
	return isolatedEnvironmentForOSWithCache(tempDir, goos, lookup, cache)
}

func isolatedEnvironmentForOSWithCache(
	tempDir string,
	goos string,
	lookup environmentLookup,
	cache verifierCache,
) ([]string, error) {
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
		"GOCACHE":                cache.GoBuild,
		"GOMODCACHE":             cache.GoMod,
		"GOPATH":                 cache.GoPath,
		"GOLANGCI_LINT_CACHE":    environmentPath(tempDir, goos, "golangci-lint"),
		"GOENV":                  "off",
		"GOTOOLCHAIN":            "local",
		"GOPROXY":                "https://proxy.golang.org,direct",
		"GOSUMDB":                "sum.golang.org",
		"GONOSUMDB":              "",
		"GOPRIVATE":              "",
		"GONOPROXY":              "",
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
	} {
		if value, present := lookup(name); present {
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

func prepareVerifierCache(repoRoot, requestedRoot string) (verifierCache, error) {
	root := requestedRoot
	if root == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return verifierCache{}, fmt.Errorf("resolve user cache directory: %w", err)
		}
		root = filepath.Join(base, "ssm", "verify", "go1.25.12")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return verifierCache{}, fmt.Errorf("make verifier cache path absolute: %w", err)
	}
	repository, err := filepath.Abs(repoRoot)
	if err != nil {
		return verifierCache{}, fmt.Errorf("make repository path absolute: %w", err)
	}
	resolvedRepository, err := filepath.EvalSymlinks(repository)
	if err != nil {
		return verifierCache{}, fmt.Errorf("resolve repository path: %w", err)
	}
	resolvedRoot, err := resolvePathForCreation(root)
	if err != nil {
		return verifierCache{}, fmt.Errorf("resolve verifier cache path: %w", err)
	}
	if samePathVolume(filepath.VolumeName(resolvedRepository), filepath.VolumeName(resolvedRoot)) {
		relative, err := filepath.Rel(resolvedRepository, resolvedRoot)
		if err != nil {
			return verifierCache{}, fmt.Errorf("compare verifier cache and repository paths: %w", err)
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return verifierCache{}, fmt.Errorf("verifier cache must be outside repository")
		}
	}

	cache := verifierCache{
		Root:    root,
		GoBuild: filepath.Join(root, "go-build"),
		GoMod:   filepath.Join(root, "go-mod"),
		GoPath:  filepath.Join(root, "gopath"),
	}
	for _, directory := range []string{cache.Root, cache.GoBuild, cache.GoMod, cache.GoPath} {
		if err := ensurePrivateCacheDirectory(directory); err != nil {
			return verifierCache{}, err
		}
	}
	return cache, nil
}

func createPrivateProfileTempDirectory(
	repoRoot string,
	pattern string,
	removeAll func(string) error,
) (directory string, returnErr error) {
	directory, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create profile temporary directory: %w", err)
	}
	createdDirectory := directory
	accepted := false
	defer func() {
		if accepted {
			return
		}
		if cleanupErr := removeAll(createdDirectory); cleanupErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove rejected profile temporary directory: %w", cleanupErr))
		}
		directory = ""
	}()

	if err := privatepath.RestrictDirectory(directory); err != nil {
		return "", fmt.Errorf("restrict profile temporary directory: %w", err)
	}
	if err := privatepath.VerifyDirectory(directory); err != nil {
		return "", fmt.Errorf("verify profile temporary directory privacy: %w", err)
	}
	repository, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", fmt.Errorf("make source repository path absolute: %w", err)
	}
	repository, err = filepath.EvalSymlinks(repository)
	if err != nil {
		return "", fmt.Errorf("resolve source repository path: %w", err)
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", fmt.Errorf("resolve profile temporary directory: %w", err)
	}
	inside, err := pathInsideOrEqual(repository, resolvedDirectory)
	if err != nil {
		return "", fmt.Errorf("compare source repository and profile temporary directory: %w", err)
	}
	if inside {
		return "", fmt.Errorf("profile temporary directory must be outside source repository")
	}
	accepted = true
	return directory, nil
}

func pathInsideOrEqual(parent, candidate string) (bool, error) {
	if !samePathVolume(filepath.VolumeName(parent), filepath.VolumeName(candidate)) {
		return false, nil
	}
	relative, err := filepath.Rel(parent, candidate)
	if err != nil {
		return false, err
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}

func samePathVolume(left, right string) bool {
	return strings.EqualFold(left, right)
}

func resolvePathForCreation(path string) (string, error) {
	current := path
	var missing []string
	for {
		_, err := os.Lstat(current)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing cache path ancestor")
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func ensurePrivateCacheDirectory(path string) error {
	//nolint:gosec // path is an absolute dedicated verifier cache already proven outside the repository
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private verifier cache directory: %w", err)
	}
	//nolint:gosec // inspect the same validated dedicated verifier cache path without following a leaf symlink
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private verifier cache directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private verifier cache path is not a regular directory")
	}
	if err := privatepath.RestrictDirectory(path); err != nil {
		return fmt.Errorf("restrict private verifier cache directory: %w", err)
	}
	if err := privatepath.VerifyDirectory(path); err != nil {
		return fmt.Errorf("verify private verifier cache directory: %w", err)
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
