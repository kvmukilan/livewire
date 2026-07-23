// Package runvars validates typed replay variables and centralizes redaction.
package runvars

import (
	"fmt"
	"sort"
	"strings"
)

func ParseAssignment(s string) (string, string, error) {
	name, value, ok := strings.Cut(s, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return "", "", fmt.Errorf("variable must be name=value")
	}
	for _, r := range name {
		if !(r == '.' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return "", "", fmt.Errorf("variable name %q contains an invalid character", name)
		}
	}
	return name, value, nil
}

func IsSecret(name string) bool {
	n := strings.ToLower(name)
	if n == "mqtt.username" || n == "http.body" {
		return true
	}
	for _, marker := range []string{"password", "passwd", "secret", "token", "authorization", "credential", "private_key", "private-key", "keylog", "api_key", "apikey"} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}

func Redacted(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for k, v := range values {
		if IsSecret(k) {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}

func Names(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for k := range values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
