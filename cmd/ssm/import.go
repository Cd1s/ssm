package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"ssm/internal/config"
)

type importRoot struct {
	Servers []importServer `json:"servers"`
}

type importServer struct {
	Name           string `json:"name"`
	Alias          string `json:"alias"`
	Host           string `json:"host"`
	HostAlias      string `json:"host_alias"`
	Port           any    `json:"port"`
	User           string `json:"user"`
	AuthType       string `json:"auth_type"`
	Password       string `json:"password"`
	PrivateKey     string `json:"private_key"`
	PrivateKeyPath string `json:"private_key_path"`
	KeyPath        string `json:"key_path"`
	Notes          string `json:"notes"`
}

func loadServerImport(path, manifestPath string) (*config.Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	servers, err := decodeImportServers(data)
	if err != nil {
		return nil, err
	}
	aliases, err := loadManifestAliases(manifestPath)
	if err != nil {
		return nil, err
	}

	v := &config.Vault{}
	keyByMaterial := map[string]string{}
	usedConnNames := map[string]bool{}
	usedKeyNames := map[string]bool{}

	for _, s := range servers {
		if alias := aliases[manifestKey(s)]; alias != "" && s.Alias == "" {
			s.Alias = alias
		}
		c, k, ok, err := convertImportServer(s, keyByMaterial, usedConnNames, usedKeyNames)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if k != nil {
			v.Keys = append(v.Keys, *k)
		}
		v.Connections = append(v.Connections, c)
	}
	return v, nil
}

func loadManifestAliases(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	servers, err := decodeImportServers(data)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, s := range servers {
		if s.Alias == "" {
			continue
		}
		out[manifestKey(s)] = s.Alias
	}
	return out, nil
}

func manifestKey(s importServer) string {
	port, _ := parsePort(s.Port)
	return strings.Join([]string{
		strings.TrimSpace(s.Name),
		strings.TrimSpace(s.Host),
		strconv.Itoa(port),
		strings.TrimSpace(s.User),
	}, "\x00")
}

func decodeImportServers(data []byte) ([]importServer, error) {
	var arr []importServer
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}

	var root importRoot
	if err := json.Unmarshal(data, &root); err == nil && root.Servers != nil {
		return root.Servers, nil
	}

	var rootMap struct {
		Servers map[string]importServer `json:"servers"`
	}
	if err := json.Unmarshal(data, &rootMap); err == nil && rootMap.Servers != nil {
		out := make([]importServer, 0, len(rootMap.Servers))
		for _, key := range sortedKeys(rootMap.Servers) {
			item := rootMap.Servers[key]
			if item.Alias == "" {
				item.Alias = key
			}
			out = append(out, item)
		}
		return out, nil
	}

	var raw map[string]importServer
	if err := json.Unmarshal(data, &raw); err == nil {
		out := make([]importServer, 0, len(raw))
		for _, key := range sortedKeys(raw) {
			item := raw[key]
			if item.Alias == "" {
				item.Alias = key
			}
			out = append(out, item)
		}
		return out, nil
	}

	return nil, errors.New("unsupported import JSON shape")
}

func convertImportServer(s importServer, keyByMaterial map[string]string, usedConnNames, usedKeyNames map[string]bool) (config.Connection, *config.SSHKey, bool, error) {
	name := firstNonEmpty(s.Alias, s.HostAlias, s.Name)
	host := strings.TrimSpace(s.Host)
	user := strings.TrimSpace(s.User)
	if name == "" || host == "" || user == "" {
		return config.Connection{}, nil, false, nil
	}
	name = uniqueName(name, usedConnNames)
	port, err := parsePort(s.Port)
	if err != nil {
		return config.Connection{}, nil, false, fmt.Errorf("%s: %w", name, err)
	}
	if port == 0 {
		port = 22
	}

	authType := strings.ToLower(strings.TrimSpace(s.AuthType))
	c := config.Connection{
		Name:  name,
		Host:  host,
		Port:  port,
		User:  user,
		Group: "imported",
	}

	var newKey *config.SSHKey
	keyMaterial := strings.TrimSpace(s.PrivateKey)
	if keyMaterial == "" && strings.TrimSpace(s.PrivateKeyPath) != "" {
		keyBytes, err := os.ReadFile(expandPath(strings.TrimSpace(s.PrivateKeyPath)))
		if err != nil {
			return config.Connection{}, nil, false, fmt.Errorf("%s: read private key path: %w", name, err)
		}
		keyMaterial = strings.TrimSpace(string(keyBytes))
	}
	if keyMaterial == "" && strings.TrimSpace(s.KeyPath) != "" {
		keyBytes, err := os.ReadFile(expandPath(strings.TrimSpace(s.KeyPath)))
		if err != nil {
			return config.Connection{}, nil, false, fmt.Errorf("%s: read key path: %w", name, err)
		}
		keyMaterial = strings.TrimSpace(string(keyBytes))
	}

	switch {
	case authType == "password":
		if s.Password == "" {
			return config.Connection{}, nil, false, fmt.Errorf("%s: password auth has empty password", name)
		}
		c.Password = s.Password
	case keyMaterial != "":
		keyName, exists := keyByMaterial[keyMaterial]
		if !exists {
			keyName = uniqueName(name, usedKeyNames)
			keyByMaterial[keyMaterial] = keyName
			newKey = &config.SSHKey{Name: keyName, PrivateKey: keyMaterial}
		}
		c.KeyName = keyName
	case s.Password != "":
		c.Password = s.Password
	default:
		return config.Connection{}, nil, false, fmt.Errorf("%s: no supported auth material", name)
	}

	return c, newKey, true, nil
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

func parsePort(v any) (int, error) {
	switch p := v.(type) {
	case nil:
		return 22, nil
	case float64:
		return int(p), nil
	case string:
		if strings.TrimSpace(p) == "" {
			return 22, nil
		}
		i, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return 0, err
		}
		return i, nil
	default:
		return 0, fmt.Errorf("unsupported port type %T", v)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func uniqueName(name string, used map[string]bool) string {
	base := sanitizeName(name)
	if base == "" {
		base = "host"
	}
	out := base
	for i := 2; used[out]; i++ {
		out = fmt.Sprintf("%s-%d", base, i)
	}
	used[out] = true
	return out
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	replacer := strings.NewReplacer("/", "-", "\\", "-", "\x00", "")
	return replacer.Replace(name)
}

func expandPath(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
