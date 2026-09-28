// Package runstate stores secret-free, crash-consistent replay progress.
package runstate

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/kvmukilan/livewire/internal/securefile"
)

const Version = 1

type Manifest struct {
	Version             int    `json:"version"`
	CaptureDigest       string `json:"captureDigest"`
	ConfigurationDigest string `json:"configurationDigest"`
}
type Result struct {
	Completed bool `json:"completed"`
	Verified  bool `json:"verified"`
	Matched   bool `json:"matched"`
	Sent      int  `json:"sent"`
	Received  int  `json:"received"`
}
type Event struct {
	Artifact  string    `json:"artifact,omitempty"`
	Session   string    `json:"session"`
	Kind      string    `json:"kind"`
	Operation int       `json:"operation,omitempty"`
	Result    *Result   `json:"result,omitempty"`
	Resource  *Resource `json:"resource,omitempty"`
}

type Resource struct {
	Target     string `json:"target"`
	TargetPort uint16 `json:"targetPort"`
	LocalPort  uint16 `json:"localPort"`
	Owner      string `json:"owner"`
}
type record struct {
	Sequence uint64 `json:"sequence"`
	Previous string `json:"previous"`
	Event    Event  `json:"event"`
	Hash     string `json:"hash"`
}
type Progress struct {
	Started            bool    `json:"started"`
	Uncertain          bool    `json:"uncertain"`
	LastConfirmed      int     `json:"lastConfirmed"`
	UncertainOperation int     `json:"uncertainOperation,omitempty"`
	Result             *Result `json:"result,omitempty"`
}
type Store struct {
	mu        sync.Mutex
	dir       string
	lock      *os.File
	journal   *os.File
	sequence  uint64
	previous  string
	progress  map[string]Progress
	failure   error
	resources map[string]Resource
	artifacts []string
}

func Digest(value any) (string, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Open reserves a new state directory, or verifies and locks an existing one.
// Preview validates existing state without truncating or creating files.
func Open(dir string, manifest Manifest, resume, preview bool) (store *Store, retErr error) {
	if manifest.Version != Version || manifest.CaptureDigest == "" || manifest.ConfigurationDigest == "" {
		return nil, fmt.Errorf("invalid state manifest")
	}
	if preview && !resume {
		return nil, fmt.Errorf("preview requires an existing run")
	}
	if !resume {
		if err := os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("state path must be a real directory")
	}
	s := &Store{dir: dir, progress: map[string]Progress{}, resources: map[string]Resource{}}
	defer func() {
		if retErr != nil {
			s.Close()
		}
	}()
	lockPath := filepath.Join(dir, "run.lock")
	if err := regularOrMissing(lockPath); err != nil {
		return nil, err
	}
	flags := os.O_RDWR | os.O_CREATE
	if preview {
		flags = os.O_RDWR
	}
	s.lock, err = os.OpenFile(lockPath, flags, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(s.lock); err != nil {
		return nil, fmt.Errorf("run is already locked or cannot be locked: %w", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if resume {
		if err := regularOrMissing(manifestPath); err != nil {
			return nil, err
		}
		b, err := readLimited(manifestPath, 1<<20)
		if err != nil {
			return nil, err
		}
		var existing Manifest
		if err := decodeStrict(b, &existing); err != nil {
			return nil, err
		}
		if existing != manifest {
			return nil, fmt.Errorf("resume refused: capture, configuration, or checkpoint version differs")
		}
	} else {
		b, _ := json.Marshal(manifest)
		if err := securefile.WriteFileAtomic(manifestPath, b); err != nil {
			return nil, err
		}
	}
	journalPath := filepath.Join(dir, "journal.jsonl")
	if err := regularOrMissing(journalPath); err != nil {
		return nil, err
	}
	if preview {
		flags = os.O_RDONLY
	} else if resume {
		flags = os.O_RDWR
	} else {
		flags = os.O_RDWR | os.O_CREATE | os.O_EXCL
	}
	s.journal, err = os.OpenFile(journalPath, flags, 0600)
	if err != nil {
		return nil, err
	}
	valid, err := s.load()
	if err != nil {
		return nil, err
	}
	if !preview {
		if err = s.journal.Truncate(valid); err != nil {
			return nil, err
		}
		if _, err = s.journal.Seek(valid, io.SeekStart); err != nil {
			return nil, err
		}
	} else {
		s.failure = fmt.Errorf("preview state is read-only")
	}
	return s, nil
}

func regularOrMissing(path string) error {
	i, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() {
		return fmt.Errorf("state file is not regular: %s", filepath.Base(path))
	}
	return nil
}
func readLimited(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("state file exceeds size limit")
	}
	return b, e
}
func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}
func recordHash(r record) string { r.Hash = ""; h, _ := Digest(r); return h }

func (s *Store) load() (int64, error) {
	r := bufio.NewReaderSize(s.journal, 64*1024)
	var offset int64
	for {
		line, e := r.ReadSlice('\n')
		if e == io.EOF {
			return offset, nil
		} // only an unterminated final record may be discarded
		if e != nil {
			return offset, fmt.Errorf("invalid journal record: %w", e)
		}
		var rec record
		if e = decodeStrict(line, &rec); e != nil {
			return offset, fmt.Errorf("corrupt committed journal record: %w", e)
		}
		if rec.Sequence != s.sequence+1 || rec.Previous != s.previous || rec.Hash != recordHash(rec) {
			return offset, fmt.Errorf("journal chain verification failed")
		}
		if e = s.apply(rec.Event); e != nil {
			return offset, e
		}
		s.sequence, s.previous = rec.Sequence, rec.Hash
		offset += int64(len(line))
	}
}
func (s *Store) apply(e Event) error {
	if e.Session == "" || len(e.Session) > 256 || e.Operation < 0 {
		return fmt.Errorf("invalid journal event")
	}
	p := s.progress[e.Session]
	switch e.Kind {
	case "evidence-partial", "evidence-published":
		if e.Artifact == "" {
			return fmt.Errorf("missing evidence reference")
		}
		s.artifacts = append(s.artifacts, e.Artifact)
		return nil
	case "resource-intent":
		if e.Resource == nil {
			return fmt.Errorf("missing resource")
		}
		s.resources[e.Session] = *e.Resource
		return nil
	case "resource-released":
		delete(s.resources, e.Session)
		return nil
	case "begin":
		p.Started = true
		p.Result = nil
	case "intent":
		if !p.Started {
			return fmt.Errorf("intent before session")
		}
		p.Uncertain = true
		p.UncertainOperation = e.Operation
	case "ack":
		if !p.Started {
			return fmt.Errorf("ack before session")
		}
		p.LastConfirmed = e.Operation
	case "finish":
		if !p.Started || e.Result == nil {
			return fmt.Errorf("invalid session completion")
		}
		p.Result = e.Result
		if e.Result.Completed {
			p.Uncertain = false
			p.UncertainOperation = 0
		}
	default:
		return fmt.Errorf("unknown journal event")
	}
	s.progress[e.Session] = p
	return nil
}

func (s *Store) Owner() string {
	path, _ := filepath.Abs(s.dir)
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:16])
}

func (s *Store) EvidenceReference(path string, published bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kind := "evidence-partial"
	if published {
		kind = "evidence-published"
	}
	return s.append(Event{Session: "evidence", Kind: kind, Artifact: path})
}
func (s *Store) ResourceIntent(key string, r Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(Event{Session: key, Kind: "resource-intent", Resource: &r})
}
func (s *Store) ResourceReleased(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(Event{Session: key, Kind: "resource-released"})
}
func (s *Store) Resources() map[string]Resource {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]Resource{}
	for k, v := range s.resources {
		out[k] = v
	}
	return out
}
func (s *Store) append(e Event) error {
	if s.failure != nil {
		return s.failure
	}
	r := record{Sequence: s.sequence + 1, Previous: s.previous, Event: e}
	r.Hash = recordHash(r)
	b, err := json.Marshal(r)
	if err == nil {
		b = append(b, '\n')
		var n int
		n, err = s.journal.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = s.journal.Sync()
	}
	if err != nil {
		s.failure = fmt.Errorf("persist replay progress: %w", err)
		return s.failure
	}
	if err = s.apply(e); err != nil {
		s.failure = err
		return err
	}
	s.sequence, s.previous = r.Sequence, r.Hash
	return nil
}

func (s *Store) Begin(key string, restartSafe bool) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.progress[key]
	if p.Result != nil && p.Result.Completed {
		copy := *p.Result
		return &copy, nil
	}
	if p.Uncertain && !restartSafe {
		return nil, fmt.Errorf("resume blocked for %s: operation outcome is uncertain (last confirmed %d); target validation is required", key, p.LastConfirmed)
	}
	return nil, s.append(Event{Session: key, Kind: "begin"})
}
func (s *Store) Record(key, kind string, operation int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(Event{Session: key, Kind: kind, Operation: operation})
}

func (s *Store) Restart(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(Event{Session: key, Kind: "begin"})
}
func (s *Store) Finish(key string, result Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.append(Event{Session: key, Kind: "finish", Result: &result}); e != nil {
		return e
	}
	b, e := json.Marshal(struct {
		Version  int                 `json:"version"`
		Sequence uint64              `json:"sequence"`
		Hash     string              `json:"hash"`
		Progress map[string]Progress `json:"progress"`
		Evidence []string            `json:"evidence"`
	}{Version, s.sequence, s.previous, s.progress, s.artifacts})
	if e != nil {
		return e
	}
	// The journal is authoritative. Checkpoints are immutable accelerators/evidence.
	path := filepath.Join(s.dir, fmt.Sprintf("checkpoint-%020d.json", s.sequence))
	if e = securefile.WriteFileAtomic(path, b); e != nil {
		s.failure = e
	}
	return e
}
func (s *Store) Progress() map[string]Progress {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]Progress{}
	for k, v := range s.progress {
		if v.Result != nil {
			r := *v.Result
			v.Result = &r
		}
		out[k] = v
	}
	return out
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.journal != nil {
		errs = append(errs, s.journal.Close())
		s.journal = nil
	}
	if s.lock != nil {
		errs = append(errs, unlockFile(s.lock), s.lock.Close())
		s.lock = nil
	}
	return errors.Join(errs...)
}
