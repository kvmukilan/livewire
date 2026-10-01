//go:build !windows

package recording

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateUnixPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := restrictDirectory(dir); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := RestrictFile(f); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{dir: 0700, f.Name(): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("secret permissions differ for %s: %v", path, err)
		}
	}
}
