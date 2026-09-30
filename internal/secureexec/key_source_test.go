package secureexec

import (
	"bytes"
	"strings"
	"testing"
)

func TestTLSKeySourcePrecedenceAndFailClosed(t *testing.T) {
	valid := []byte("CLIENT_RANDOM " + strings.Repeat("12", 32) + " " + strings.Repeat("34", 48) + "\n")
	got, source, err := SelectTLSKeyLog(valid, nil, false)
	if err != nil || source != "embedded" || !bytes.Equal(got, valid) {
		t.Fatalf("embedded selection: %q %v", source, err)
	}
	got[0] = 'X'
	if valid[0] != 'C' {
		t.Fatal("returned secrets alias capture")
	}
	explicit := []byte("selected external log")
	got, source, err = SelectTLSKeyLog([]byte("malformed embedded"), explicit, true)
	if err != nil || source != "external" || !bytes.Equal(got, explicit) {
		t.Fatalf("explicit priority: %q %v", source, err)
	}
	got[0] = 'X'
	if explicit[0] != 's' {
		t.Fatal("returned secrets alias explicit input")
	}
	for _, invalid := range [][]byte{[]byte("bad secret material\n"), []byte("# comments only\n"), append(append([]byte(nil), valid...), bytes.ReplaceAll(valid, []byte(strings.Repeat("34", 48)), []byte(strings.Repeat("56", 48)))...)} {
		if _, _, err := SelectTLSKeyLog(invalid, nil, false); err == nil || strings.Contains(err.Error(), "343434") {
			t.Fatalf("invalid embedded log accepted or disclosed: %v", err)
		}
	}
	if _, _, err := SelectTLSKeyLog(valid, nil, true); err == nil {
		t.Fatal("empty explicit log fell back")
	}
	got, source, err = SelectTLSKeyLog(nil, nil, false)
	if err != nil || got != nil || source != "none" {
		t.Fatalf("keyless source: %q %v", source, err)
	}
}
