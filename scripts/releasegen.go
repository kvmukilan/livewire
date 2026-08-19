//go:build ignore

// releasegen creates release metadata and archives with bytes that do not
// depend on the host PowerShell or .NET runtime. Run it through the pinned
// release Go toolchain; it is intentionally excluded from package builds.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

var archiveTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

type module struct {
	Path    string
	Version string
	Main    bool
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type bom struct {
	Format      string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    bomMetadata `json:"metadata"`
	Components  []component `json:"components"`
}

type bomMetadata struct {
	Component component `json:"component"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "sbom":
		flags := flag.NewFlagSet("sbom", flag.ExitOnError)
		version := flags.String("version", "", "release version")
		output := flags.String("output", "", "CycloneDX output file")
		_ = flags.Parse(os.Args[2:])
		if *version == "" || *output == "" {
			usage()
		}
		err = writeSBOM(*version, *output)
	case "zip":
		flags := flag.NewFlagSet("zip", flag.ExitOnError)
		source := flags.String("source", "", "directory containing files to archive")
		output := flags.String("output", "", "ZIP file to create")
		_ = flags.Parse(os.Args[2:])
		if *source == "" || *output == "" {
			usage()
		}
		err = writeZIP(*source, *output)
	case "checksums":
		flags := flag.NewFlagSet("checksums", flag.ExitOnError)
		directory := flags.String("directory", "", "artifact directory")
		output := flags.String("output", "", "checksum manifest to create")
		_ = flags.Parse(os.Args[2:])
		if *directory == "" || *output == "" {
			usage()
		}
		err = writeChecksums(*directory, *output)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasegen:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: releasegen <sbom|zip|checksums> [options]")
	os.Exit(2)
}

func writeSBOM(version, output string) error {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	data, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("go list: %w: %s", err, bytes.TrimSpace(exitErr.Stderr))
		}
		return fmt.Errorf("go list: %w", err)
	}

	var components []component
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var item module
		err := decoder.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("decode module list: %w", err)
		}
		if item.Main {
			continue
		}
		components = append(components, component{
			Type:    "library",
			Name:    item.Path,
			Version: item.Version,
			PURL:    "pkg:golang/" + item.Path + "@" + item.Version,
		})
	}
	sort.Slice(components, func(i, j int) bool {
		if components[i].Name == components[j].Name {
			return components[i].Version < components[j].Version
		}
		return components[i].Name < components[j].Name
	})

	document := bom{
		Format:      "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: bomMetadata{Component: component{
			Type:    "application",
			Name:    "livewire",
			Version: version,
			PURL:    "pkg:golang/github.com/kvmukilan/livewire@" + version,
		}},
		Components: components,
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writeBytes(output, append(encoded, '\n'))
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
			retErr = errors.Join(retErr, removeIfPresent(output))
		}
	}()

	zw := zip.NewWriter(out)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("source entry is not a regular file: %q", entry.Name())
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
	return closeErr
}

func writeChecksums(directory, output string) error {
	absDirectory, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if filepath.Clean(filepath.Dir(absOutput)) != filepath.Clean(absDirectory) {
		return errors.New("checksum manifest must be created inside the artifact directory")
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	outputName := filepath.Base(output)
	for _, entry := range entries {
		if entry.Name() == outputName {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact is not a regular file: %q", entry.Name())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	var manifest bytes.Buffer
	for _, name := range names {
		file, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		if err := errors.Join(copyErr, file.Close()); err != nil {
			return err
		}
		fmt.Fprintf(&manifest, "%x  %s\n", hash.Sum(nil), name)
	}
	return writeBytes(output, manifest.Bytes())
}

func writeBytes(path string, data []byte) (retErr error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			retErr = errors.Join(retErr, file.Close())
		}
		if retErr != nil {
			retErr = errors.Join(retErr, removeIfPresent(path))
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	closeErr := file.Close()
	file = nil
	return closeErr
}

func removeIfPresent(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
