package runvars

import "testing"

func TestRedacted(t *testing.T) {
	values := map[string]string{"site": "lab", "mqtt.username": "operator", "mqtt.password": "hunter2", "Authorization": "Bearer abc"}
	got := Redacted(values)
	if got["site"] != "lab" || got["mqtt.username"] != "[REDACTED]" || got["mqtt.password"] != "[REDACTED]" || got["Authorization"] != "[REDACTED]" {
		t.Fatalf("redaction=%v", got)
	}
}

func TestParseAssignment(t *testing.T) {
	k, v, err := ParseAssignment("http.host=device.local")
	if err != nil || k != "http.host" || v != "device.local" {
		t.Fatalf("%q %q %v", k, v, err)
	}
	if _, _, err := ParseAssignment("bad name=x"); err == nil {
		t.Fatal("invalid name should fail")
	}
}
