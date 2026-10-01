package recording

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

// Process owns the child, its descendants, and one private temporary key log.
// Close must be called on every successful Start, including after child exit.
type Process struct {
	cmd      *exec.Cmd
	done     chan struct{}
	waitErr  error
	kill     func() error
	dir      string
	log      *os.File
	identity os.FileInfo
	stopped  bool
}

func Start(argv []string) (_ *Process, retErr error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("TLS recording requires an application after --")
	}
	p := &Process{done: make(chan struct{})}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, p.Close())
		}
	}()
	var err error
	p.dir, err = os.MkdirTemp("", "livewire-tls-*")
	if err != nil {
		return nil, err
	}
	if err = restrictDirectory(p.dir); err != nil {
		return nil, fmt.Errorf("protect TLS recording directory: %w", err)
	}
	path := filepath.Join(p.dir, "keys.log")
	p.log, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = RestrictFile(p.log); err != nil {
		return nil, err
	}
	p.identity, err = p.log.Stat()
	if err != nil {
		return nil, err
	}
	// The executable is explicitly supplied by the operator. No shell expansion
	// or capture-derived command text is used.
	p.cmd = exec.Command(argv[0], argv[1:]...) // #nosec G204 -- explicit operator-owned recording application
	p.cmd.Stdin, p.cmd.Stdout, p.cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(name, "SSLKEYLOGFILE") {
			p.cmd.Env = append(p.cmd.Env, entry)
		}
	}
	p.cmd.Env = append(p.cmd.Env, "SSLKEYLOGFILE="+path)
	p.kill, err = startOwned(p.cmd)
	if err != nil {
		p.cmd = nil
		return nil, fmt.Errorf("start recording application: %w", err)
	}
	kill := p.kill
	go func() { p.waitErr = waitOwned(p.cmd, kill); close(p.done) }()
	return p, nil
}

func (p *Process) Done() <-chan struct{} { return p.done }

// ExitError is only valid after Done closes. It never includes argv or secrets.
func (p *Process) ExitError() error {
	if p.waitErr != nil {
		return fmt.Errorf("recording application failed: %w", p.waitErr)
	}
	return nil
}

// CheckLog rejects replacement/symlink attacks and bounds exported data. The
// original open file, not a later path lookup, is used to read the secrets.
func (p *Process) CheckLog() error {
	info, err := os.Lstat(p.log.Name())
	if err != nil {
		return fmt.Errorf("inspect TLS key export: %w", err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, p.identity) {
		return fmt.Errorf("TLS key export file was replaced")
	}
	if info.Size() > pcapio.MaxTLSKeyLogBytes {
		return fmt.Errorf("TLS key export exceeds the 1 MiB limit")
	}
	return nil
}

// Stop terminates the owned process tree before the key log is finalized.
func (p *Process) Stop() error {
	if p.stopped {
		return nil
	}
	var err error
	if p.kill != nil {
		err = p.kill()
		if err == nil {
			p.kill = nil
		}
	}
	if p.cmd != nil {
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			err = errors.Join(err, fmt.Errorf("recording application did not exit within 5 seconds"))
		}
	}
	p.stopped = err == nil
	return err
}

func (p *Process) Secrets() ([]byte, error) {
	if !p.stopped {
		return nil, fmt.Errorf("stop the recording application before reading TLS secrets")
	}
	if err := p.CheckLog(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.NewSectionReader(p.log, 0, pcapio.MaxTLSKeyLogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > pcapio.MaxTLSKeyLogBytes {
		return nil, fmt.Errorf("TLS key export exceeds the 1 MiB limit")
	}
	return data, nil
}

func (p *Process) Close() error {
	err := p.Stop()
	if err != nil {
		return fmt.Errorf("TLS recording cleanup incomplete; private files retained in %q: %w", p.dir, err)
	}
	if p.log != nil {
		name := p.log.Name()
		err = errors.Join(err, p.log.Close())
		p.log = nil
		if e := os.Remove(name); !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}
	if p.dir != "" {
		// Never recursively remove application-created paths or follow links.
		if e := os.Remove(p.dir); !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
		p.dir = ""
	}
	return err
}
