//go:build !windows

package recording

import "os"

// RestrictFile limits a secret-bearing file to its owner.
func RestrictFile(f *os.File) error       { return f.Chmod(0o600) }
func restrictDirectory(path string) error { return os.Chmod(path, 0o700) }
