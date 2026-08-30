// Package securefile creates sensitive artifacts with restrictive permissions
// and publishes them only after all writes have succeeded.
package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AtomicFile is a private temporary file that can be atomically renamed into
// place. Call Abort unless Commit succeeds.
type AtomicFile struct {
	file   *os.File
	tmp    string
	target string
}

// Create creates a mode-0600 temporary file beside an unused target. The
// up-front check gives long-running capture/replay commands an immediate error;
// Commit's link step remains the race-safe no-replace authority.
func Create(target string) (*AtomicFile, error) {
	// #nosec G703 -- target is the caller's local artifact path; Lstat prevents
	// replacing any existing file, directory, symlink, or reparse point.
	if _, err := os.Lstat(target); err == nil {
		return nil, fmt.Errorf("securefile: target %q already exists: %w", target, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("securefile: inspect target %q: %w", target, err)
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		closeErr := f.Close()
		removeErr := os.Remove(f.Name())
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		return nil, errors.Join(err, closeErr, removeErr)
	}
	return &AtomicFile{file: f, tmp: f.Name(), target: target}, nil
}

func (a *AtomicFile) Write(p []byte) (int, error) { return a.file.Write(p) }
func (a *AtomicFile) File() *os.File              { return a.file }
func (a *AtomicFile) Name() string                { return a.target }

// Commit flushes, closes, and publishes the completed file without replacing an
// existing target. A hard link is used for the publication step because link
// creation is atomic and has consistent no-replace semantics on Unix and
// Windows; os.Rename would silently overwrite on Unix but fail on Windows.
func (a *AtomicFile) Commit() error {
	if a == nil || a.file == nil {
		return fmt.Errorf("securefile: no open temporary file")
	}
	var errs []error
	if err := a.file.Sync(); err != nil {
		errs = append(errs, err)
	}
	if err := a.file.Close(); err != nil {
		errs = append(errs, err)
	}
	a.file = nil
	if len(errs) == 0 {
		if err := os.Link(a.tmp, a.target); err != nil {
			errs = append(errs, err)
		} else if err := os.Remove(a.tmp); err != nil {
			// The target is already a complete published link. Keep tmp recorded
			// so Abort can retry only its cleanup; it must never remove target.
			errs = append(errs, err)
		} else {
			a.tmp = ""
		}
	}
	return errors.Join(errs...)
}

// Abort closes and removes an unpublished temporary file.
func (a *AtomicFile) Abort() error {
	if a == nil {
		return nil
	}
	var errs []error
	if a.file != nil {
		if err := a.file.Close(); err != nil {
			errs = append(errs, err)
		}
		a.file = nil
	}
	if a.tmp != "" {
		if err := os.Remove(a.tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
		a.tmp = ""
	}
	return errors.Join(errs...)
}

// WriteAtomic writes a complete sensitive artifact before publishing it.
func WriteAtomic(target string, write func(io.Writer) error) (err error) {
	a, err := Create(target)
	if err != nil {
		return err
	}
	defer func() {
		if abortErr := a.Abort(); err == nil && abortErr != nil {
			err = abortErr
		}
	}()
	if err = write(a); err != nil {
		return err
	}
	return a.Commit()
}

// WriteFileAtomic publishes data with mode 0600.
func WriteFileAtomic(target string, data []byte) error {
	return WriteAtomic(target, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}
