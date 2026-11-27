package webui

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func uploadRequest(s *Server, query, contentType, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, uploadPath+"?"+query, bytes.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		r.Header.Set("X-Livewire-CSRF", token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestUploadStoresFilesWithoutOverwriting(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(dir)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	const stream = "application/octet-stream"
	stored := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		var out struct{ Name string }
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Name
	}
	if got := stored(uploadRequest(s, "kind=capture&name=issue.pcap", stream, s.CSRFToken(), []byte("first"))); got != "issue.pcap" {
		t.Fatalf("stored as %q", got)
	}
	if got := stored(uploadRequest(s, "kind=capture&name=issue.pcap", stream, s.CSRFToken(), []byte("second"))); got != "issue-2.pcap" {
		t.Fatalf("second upload stored as %q", got)
	}
	for name, want := range map[string]string{"issue.pcap": "first", "issue-2.pcap": "second"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", name, got, err)
		}
	}
	if got := stored(uploadRequest(s, "kind=keylog&name=sslkeys.log", stream, s.CSRFToken(), []byte("CLIENT_RANDOM 00 00\n"))); got != "sslkeys.log" {
		t.Fatalf("key log stored as %q", got)
	}
	if _, err := s.planningKeyLog("sslkeys.log"); err != nil {
		t.Fatalf("uploaded key log is not usable by name: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".upload-") {
			t.Fatalf("temporary upload %q left behind", e.Name())
		}
	}
}

func TestUploadRejectsUnsafeRequests(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(dir)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	const stream = "application/octet-stream"
	cases := []struct {
		name, query, contentType, token string
		body                            []byte
		want                            int
	}{
		{"missing token", "kind=capture&name=a.pcap", stream, "", []byte("x"), http.StatusForbidden},
		{"json body", "kind=capture&name=a.pcap", "application/json", s.CSRFToken(), []byte("{}"), http.StatusUnsupportedMediaType},
		{"unknown kind", "kind=script&name=a.pcap", stream, s.CSRFToken(), []byte("x"), http.StatusBadRequest},
		{"wrong extension", "kind=capture&name=a.exe", stream, s.CSRFToken(), []byte("x"), http.StatusBadRequest},
		{"extension for another kind", "kind=ca&name=a.pcap", stream, s.CSRFToken(), []byte("x"), http.StatusBadRequest},
		{"traversal", "kind=capture&name=..%2Fa.pcap", stream, s.CSRFToken(), []byte("x"), http.StatusBadRequest},
		{"windows traversal", "kind=capture&name=..%5Ca.pcap", stream, s.CSRFToken(), []byte("x"), http.StatusBadRequest},
		{"hidden file", "kind=capture&name=.pcap", stream, s.CSRFToken(), []byte("x"), http.StatusBadRequest},
		{"empty file", "kind=capture&name=a.pcap", stream, s.CSRFToken(), nil, http.StatusBadRequest},
		{"oversized key log", "kind=keylog&name=a.log", stream, s.CSRFToken(), make([]byte, maxSupportUpload+1), http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		if got := uploadRequest(s, c.query, c.contentType, c.token, c.body).Code; got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected uploads left files: %v %v", entries, err)
	}
}

func TestLocalTLSIdentityPersistsAndRenews(t *testing.T) {
	state := t.TempDir()
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	first, err := LoadTLSIdentity(TLSOptions{StateDir: state, Hosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	if !first.SelfSigned || first.Config.MinVersion < tls.VersionTLS12 {
		t.Fatalf("unexpected identity %+v", first)
	}
	leaf, err := x509.ParseCertificate(first.Config.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range hosts {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("certificate does not cover %s: %v", host, err)
		}
	}
	if info, err := os.Stat(filepath.Join(state, localKeyFile)); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private key not stored privately: %v %v", info, err)
	}
	again, err := LoadTLSIdentity(TLSOptions{StateDir: state, Hosts: hosts})
	if err != nil || again.Fingerprint != first.Fingerprint {
		t.Fatalf("certificate was not reused: %v", err)
	}
	wider, err := LoadTLSIdentity(TLSOptions{StateDir: state, Hosts: append(hosts, "lab-host.example")})
	if err != nil || wider.Fingerprint == first.Fingerprint {
		t.Fatalf("certificate missing a host was reused: %v", err)
	}
	if _, err := LoadTLSIdentity(TLSOptions{CertFile: filepath.Join(state, localCertFile)}); err == nil {
		t.Fatal("certificate without a key was accepted")
	}
	supplied, err := LoadTLSIdentity(TLSOptions{CertFile: filepath.Join(state, localCertFile), KeyFile: filepath.Join(state, localKeyFile)})
	if err != nil || supplied.SelfSigned || supplied.Fingerprint != wider.Fingerprint {
		t.Fatalf("supplied pair not loaded: %+v %v", supplied, err)
	}
}
