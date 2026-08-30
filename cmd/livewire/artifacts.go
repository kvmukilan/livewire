package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveOutputPath protects operator evidence from accidental replacement. An
// explicit path must be unused; a default path receives a small numeric suffix
// when a prior run already owns the preferred name.
func resolveOutputPath(requested, preferred, flagName string) (string, error) {
	if requested != "" {
		if err := outputPathAvailable(requested); err != nil {
			return "", fmt.Errorf("%s output %q: %w", flagName, requested, err)
		}
		return requested, nil
	}
	for n := 1; n <= 10_000; n++ {
		candidate := preferred
		if n > 1 {
			ext := filepath.Ext(preferred)
			candidate = strings.TrimSuffix(preferred, ext) + fmt.Sprintf("-%d", n) + ext
		}
		err := outputPathAvailable(candidate)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("choose default %s output %q: %w", flagName, candidate, err)
		}
	}
	return "", fmt.Errorf("could not find an unused default %s output near %q", flagName, preferred)
}

func outputPathAvailable(path string) error {
	// #nosec G703 -- this is the local CLI's explicit or generated output path;
	// Lstat is intentionally used to prevent overwriting any existing entry.
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return os.ErrExist
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return err
	}
}

func sameOutputPath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return strings.EqualFold(filepath.Clean(absA), filepath.Clean(absB))
}
