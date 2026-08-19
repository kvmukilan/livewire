//go:build ignore

// releasezip creates the Windows release ZIP with bytes that do not depend on
// the host PowerShell or .NET runtime. Run it through the pinned release Go
// toolchain; it is intentionally excluded from normal package builds.
package main

import (
	"archive/zip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

var archiveTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func main() {
	source := flag.String("source", "", "directory containing files to archive")
	output := flag.String("output", "", "ZIP file to create")
	flag.Parse()
	if *source == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "releasezip: -source and -output are required")
		os.Exit(2)
	}
	if err := writeZIP(*source, *output); err != nil {
		fmt.Fprintln(os.Stderr, "releasezip:", err)
		os.Exit(1)
	}
}

func writeZIP(source, output string) (retErr error) {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	out, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if out != nil {
			retErr = errors.Join(retErr, out.Close())
		}
		if retErr != nil {
			if err := os.Remove(output); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, err)
			}
		}
	}()

	zw := zip.NewWriter(out)
	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("source contains directory %q", entry.Name())
		}
		name := entry.Name()
		if filepath.Base(name) != name {
			return fmt.Errorf("unsafe archive name %q", name)
		}
		header := &zip.FileHeader{Name: name, Method: zip.Store, Modified: archiveTime}
		header.SetMode(0o644)
		dst, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		src, err := os.Open(filepath.Join(source, name))
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(dst, src)
		if err := errors.Join(copyErr, src.Close()); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	closeErr := out.Close()
	out = nil
	if closeErr != nil {
		return closeErr
	}
	return nil
}
