package webui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	uploadPath = "/api/upload"
	// A capture larger than the loader's decoded-data limit cannot be replayed,
	// so accepting more than that plus container overhead only fills the disk.
	maxCaptureUpload = 600 << 20
	// Key logs, CA bundles and SSH key material are read with a 4 MiB limit.
	maxSupportUpload = 4 << 20
	maxUploadName    = 120
)

var errUploadTooLarge = errors.New("file exceeds the upload limit")

// uploadKinds maps the file's role to the extensions the run handlers accept
// for it, so an uploaded file is always usable by name afterwards.
var uploadKinds = map[string]struct {
	extensions []string
	limit      int64
}{
	"capture": {[]string{".pcap", ".pcapng"}, maxCaptureUpload},
	"keylog":  {[]string{".keylog", ".log", ".txt", ".keys"}, maxSupportUpload},
	"ca":      {[]string{".pem", ".crt"}, maxSupportUpload},
	"key":     {[]string{".pem", ".key", ".txt"}, maxSupportUpload},
	"hostkey": {[]string{".pub", ".txt"}, maxSupportUpload},
}

// handleUpload stores a browser-selected file in the dashboard directory so
// captures and key material do not have to be copied there by hand. The body is
// the raw file; the middleware has already checked origin and the CSRF token.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	kind, ok := uploadKinds[r.URL.Query().Get("kind")]
	if !ok {
		writeErr(w, 400, fmt.Errorf("kind must be capture, keylog, ca, key or hostkey"))
		return
	}
	name, err := uploadName(r.URL.Query().Get("name"), kind.extensions)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if r.ContentLength > kind.limit {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("file exceeds %d bytes", kind.limit))
		return
	}
	stored, err := s.storeUpload(name, r.Body, kind.limit)
	if errors.Is(err, errUploadTooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("file exceeds %d bytes", kind.limit))
		return
	}
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"name": stored})
}

func uploadName(raw string, extensions []string) (string, error) {
	if raw == "" || len(raw) > maxUploadName {
		return "", fmt.Errorf("file name must be 1 to %d characters", maxUploadName)
	}
	if strings.ContainsAny(raw, `/\:`) || filepath.Base(raw) != raw || strings.HasPrefix(raw, ".") {
		return "", fmt.Errorf("invalid file name")
	}
	for _, c := range raw {
		if c < 0x20 || c == 0x7f || strings.ContainsRune(`<>"|?*`, c) {
			return "", fmt.Errorf("invalid file name")
		}
	}
	lower := strings.ToLower(raw)
	for _, ext := range extensions {
		if strings.HasSuffix(lower, ext) && len(raw) > len(ext) {
			return raw, nil
		}
	}
	return "", fmt.Errorf("file name must end in %s", strings.Join(extensions, ", "))
}

// storeUpload writes to a private temporary name and links the finished file
// into place, so a partial upload is never visible as a capture and an existing
// file is never overwritten. A taken name gets a numeric suffix.
func (s *Server) storeUpload(name string, body io.Reader, limit int64) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	temp := ".upload-" + hex.EncodeToString(suffix) + ".part"
	f, err := s.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	n, copyErr := io.Copy(f, io.LimitReader(body, limit+1))
	if err := errors.Join(copyErr, f.Close()); err != nil {
		return "", errors.Join(err, s.root.Remove(temp))
	}
	if n > limit {
		return "", errors.Join(errUploadTooLarge, s.root.Remove(temp))
	}
	if n == 0 {
		return "", errors.Join(fmt.Errorf("file is empty"), s.root.Remove(temp))
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; i <= 1000; i++ {
		candidate := name
		if i > 1 {
			candidate = fmt.Sprintf("%s-%d%s", stem, i, ext)
		}
		err := s.root.Link(temp, candidate)
		if err == nil {
			return candidate, s.root.Remove(temp)
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		// Removable media formatted as FAT or exFAT has no hard links.
		if _, statErr := s.root.Lstat(candidate); statErr == nil {
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", errors.Join(statErr, s.root.Remove(temp))
		}
		if renameErr := s.root.Rename(temp, candidate); renameErr != nil {
			return "", errors.Join(err, renameErr, s.root.Remove(temp))
		}
		return candidate, nil
	}
	return "", errors.Join(fmt.Errorf("too many files named %q", name), s.root.Remove(temp))
}
