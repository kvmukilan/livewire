// Package evidence streams packet evidence with bounded memory and atomic final
// publication. The private partial file remains available until Close/Commit.
package evidence

import (
	"fmt"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/runstate"
	"github.com/kvmukilan/livewire/internal/securefile"
	"github.com/kvmukilan/livewire/internal/wire"
	"sync"
)

type Stream struct {
	mu      sync.Mutex
	path    string
	file    *securefile.AtomicFile
	writer  *pcapio.Writer
	link    wire.LinkType
	count   int
	bytes   int64
	err     error
	journal *runstate.Store
}

func New(path string) *Stream { return &Stream{path: path} }

// SetJournal is called before recording begins. Only file references, never
// packet contents, enter the progress journal.
func (s *Stream) SetJournal(j *runstate.Store) { s.journal = j }
func (s *Stream) Record(r pcapio.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if len(r.Data) > 16<<20 || s.bytes+int64(len(r.Data)) > 512<<20 {
		s.err = fmt.Errorf("packet evidence resource limit exceeded (512 MiB per run)")
		return s.err
	}
	if s.file == nil {
		s.file, s.err = securefile.Create(s.path)
		if s.err != nil {
			return s.err
		}
		s.link = r.LinkType
		if s.journal != nil {
			if s.err = s.journal.EvidenceReference(s.file.File().Name(), false); s.err != nil {
				return s.err
			}
		}
		s.writer, s.err = pcapio.NewWriter(s.file, s.link, true)
		if s.err != nil {
			return s.err
		}
	}
	if r.LinkType != s.link {
		s.err = fmt.Errorf("evidence link types differ; use separate runs")
		return s.err
	}
	if s.err = s.writer.Write(&r); s.err != nil {
		return s.err
	}
	if s.err = s.writer.Flush(); s.err != nil {
		return s.err
	}
	s.count++
	s.bytes += int64(len(r.Data))
	return nil
}
func (s *Stream) Commit() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return 0, s.err
	}
	if s.err != nil {
		path, err := s.file.PreservePartial()
		return s.count, fmt.Errorf("%w; partial evidence retained at %s (close: %v)", s.err, path, err)
	}
	s.err = s.file.Commit()
	if s.err != nil {
		path, err := s.file.PreservePartial()
		s.err = fmt.Errorf("%w; partial evidence retained at %s (close: %v)", s.err, path, err)
	}
	if s.err == nil && s.journal != nil {
		s.err = s.journal.EvidenceReference(s.path, true)
	}
	return s.count, s.err
}
func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Abort()
	}
	return nil
}
