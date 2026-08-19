package runvars

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Redactor removes known secret values from structured reports and text.
type Redactor struct {
	secrets []string
}

// NewRedactor learns secret-shaped variables and explicitly supplied secrets.
func NewRedactor(values map[string]string, extra ...string) *Redactor {
	seen := map[string]struct{}{}
	for name, value := range values {
		if IsSecret(name) && value != "" {
			seen[value] = struct{}{}
		}
	}
	for _, value := range extra {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	secrets := make([]string, 0, len(seen))
	for value := range seen {
		secrets = append(secrets, value)
	}
	// Replace longer values first so overlapping secrets cannot leave suffixes.
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	return &Redactor{secrets: secrets}
}

func (r *Redactor) Text(value string) string {
	if r == nil {
		return value
	}
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
		quoted := strconv.Quote(secret)
		if len(quoted) >= 2 {
			value = strings.ReplaceAll(value, quoted[1:len(quoted)-1], "[REDACTED]")
		}
	}
	return value
}

// MarshalIndent redacts string values in the object graph before the final JSON
// encoding, so JSON escaping cannot hide a supplied secret from replacement.
func (r *Redactor) MarshalIndent(value any, prefix, indent string) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	tree = r.walk(tree)
	return json.MarshalIndent(tree, prefix, indent)
}

func (r *Redactor) walk(value any) any {
	switch value := value.(type) {
	case string:
		return r.Text(value)
	case []any:
		for i := range value {
			value[i] = r.walk(value[i])
		}
	case map[string]any:
		for key := range value {
			value[key] = r.walk(value[key])
		}
	}
	return value
}
