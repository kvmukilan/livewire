package recording

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordingChild(t *testing.T) {
	if os.Getenv("LIVEWIRE_RECORDING_TEST_CHILD") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "leaf" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			os.Exit(6)
		}
		if err := os.WriteFile(os.Getenv("LIVEWIRE_RECORDING_LEAF_ADDRESS"), []byte(listener.Addr().String()), 0600); err != nil {
			os.Exit(7)
		}
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	f, err := os.OpenFile(os.Getenv("SSLKEYLOGFILE"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		os.Exit(2)
	}
	data := []byte("child-export\n")
	if mode == "large" {
		data = bytes.Repeat([]byte{'x'}, (1<<20)+1)
	}
	if _, err := f.Write(data); err != nil {
		os.Exit(3)
	}
	if err := f.Close(); err != nil {
		os.Exit(4)
	}
	if mode == "tree" {
		child := exec.Command(os.Args[0], "-test.run=^TestRecordingChild$", "--", "leaf")
		if err := child.Start(); err != nil {
			os.Exit(8)
		}
		time.Sleep(time.Minute)
	}
	if mode == "wait" {
		time.Sleep(time.Minute)
	}
	if mode == "fail" {
		os.Exit(9)
	}
	os.Exit(0)
}

func TestProcessStopsOwnedDescendants(t *testing.T) {
	t.Setenv("LIVEWIRE_RECORDING_TEST_CHILD", "1")
	marker := filepath.Join(t.TempDir(), "leaf-address")
	t.Setenv("LIVEWIRE_RECORDING_LEAF_ADDRESS", marker)
	p, err := Start([]string{os.Args[0], "-test.run=^TestRecordingChild$", "--", "tree"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	deadline := time.Now().Add(5 * time.Second)
	var address []byte
	for time.Now().Before(deadline) {
		address, _ = os.ReadFile(marker)
		if len(address) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(address) == 0 {
		t.Fatal("descendant did not start")
	}
	conn, err := net.DialTimeout("tcp", string(address), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", string(address), 100*time.Millisecond)
		if err != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("owned descendant survived Stop")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProcessPrivateExportAndCleanup(t *testing.T) {
	for _, mode := range []string{"success", "large", "wait", "fail"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("LIVEWIRE_RECORDING_TEST_CHILD", "1")
			global := filepath.Join(t.TempDir(), "global.keys")
			if err := os.WriteFile(global, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SSLKEYLOGFILE", global)
			p, err := Start([]string{os.Args[0], "-test.run=^TestRecordingChild$", "--", mode})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := p.Close(); err != nil {
					t.Error(err)
				}
			})
			dir := p.dir
			if mode == "wait" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					info, err := p.log.Stat()
					if err != nil {
						t.Fatal(err)
					}
					if info.Size() > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("child never wrote")
					}
					time.Sleep(10 * time.Millisecond)
				}
			} else {
				select {
				case <-p.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("child did not finish")
				}
				if (p.ExitError() != nil) != (mode == "fail") {
					t.Fatalf("exit error: %v", p.ExitError())
				}
			}
			if err := p.Stop(); err != nil {
				t.Fatal(err)
			}
			keys, err := p.Secrets()
			if mode == "large" {
				if err == nil || !strings.Contains(err.Error(), "limit") {
					t.Fatalf("unbounded export: %v", err)
				}
			} else if err != nil || string(keys) != "child-export\n" {
				t.Fatalf("private export: bytes=%d err=%v", len(keys), err)
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("temporary secret directory leaked")
			}
			data, err := os.ReadFile(global)
			if err != nil || string(data) != "untouched" || os.Getenv("SSLKEYLOGFILE") != global {
				t.Fatal("parent key log was consumed or modified")
			}
		})
	}
}

func TestProcessStartFailureCleansPrivateDirectory(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMPDIR", tmp)
	if _, err := Start([]string{filepath.Join(tmp, "absent-executable")}); err == nil {
		t.Fatal("missing executable succeeded")
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("start failure leaked files: %v %v", entries, err)
	}
}

func TestProcessFailedCleanupCanRetry(t *testing.T) {
	attempts := 0
	p := &Process{kill: func() error {
		attempts++
		if attempts == 1 {
			return errors.New("transient cleanup failure")
		}
		return nil
	}}
	if err := p.Stop(); err == nil || p.stopped {
		t.Fatal("failed cleanup marked complete")
	}
	if err := p.Stop(); err != nil || !p.stopped || attempts != 2 {
		t.Fatalf("failed cleanup did not retry: %v", err)
	}
}
