package runvars

import (
	"strings"
	"testing"
)

func TestRedactorHandlesJSONEscapedSecrets(t *testing.T) {
	secret := "quote\" slash\\ newline\n snowman☃"
	r := NewRedactor(map[string]string{"ftp.password": secret})
	b, err := r.MarshalIndent(map[string]any{"error": "login failed for " + secret, "nested": []any{secret}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, fragment := range []string{"quote", "slash", "newline", "snowman", `\"`, `\\`} {
		if strings.Contains(text, fragment) {
			t.Fatalf("redacted JSON contains secret fragment %q: %s", fragment, text)
		}
	}
	if strings.Count(text, "[REDACTED]") != 2 {
		t.Fatalf("unexpected redacted JSON: %s", text)
	}
}
