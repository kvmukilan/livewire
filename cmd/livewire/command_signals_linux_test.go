//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGuardCommandSignalHelper runs only in isolated children. A fake iptables
// in PATH records operations; these tests never alter the host firewall.
func TestGuardCommandSignalHelper(t *testing.T) {
	scenario := os.Getenv("LIVEWIRE_SIGNAL_TEST")
	if scenario == "" {
		return
	}
	var err error
	if scenario == "web" {
		err = cmdWeb([]string{"-addr", "127.0.0.1:0", "-dir", os.Getenv("LIVEWIRE_SIGNAL_DIR")})
	} else {
		err = cmdRstdrop([]string{"-t", "192.0.2.10", "-port", "502", "-sport", "41001"})
	}
	wantPipe := scenario == "initial-output" || scenario == "final-output" || scenario == "restored"
	if wantPipe && !errors.Is(err, syscall.EPIPE) || !wantPipe && err != nil {
		fmt.Fprintf(os.Stderr, "unexpected command error: %v\n", err)
		os.Exit(2)
	}
	if scenario == "restored" {
		// After command cleanup the prior default signal behavior must return.
		_, _ = os.Stdout.WriteString("outside command scope\n")
		os.Exit(3)
	}
	// Avoid the testing package writing PASS to an intentionally closed fd 1.
	os.Exit(0)
}

func TestGuardCommandsReleaseRulesOnBrokenPipe(t *testing.T) {
	for _, scenario := range []string{"initial-output", "final-output", "signal", "restored", "web"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "iptables.log")
			script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$LIVEWIRE_SIGNAL_LOG\"\n"
			if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			// #nosec G204 -- runs this test binary, with only fixed helper arguments.
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuardCommandSignalHelper$")
			cmd.Env = append(os.Environ(), "LIVEWIRE_SIGNAL_TEST="+scenario, "LIVEWIRE_SIGNAL_DIR="+dir,
				"LIVEWIRE_SIGNAL_LOG="+logPath, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			readEnd, writeEnd, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readEnd.Close()
			defer writeEnd.Close()
			cmd.Stdout = writeEnd
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if scenario == "initial-output" || scenario == "restored" {
				_ = readEnd.Close()
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			_ = writeEnd.Close()
			if scenario != "initial-output" && scenario != "restored" {
				reader := bufio.NewReader(readEnd)
				first, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("startup: %v", err)
				}
				if _, err := reader.ReadString('\n'); err != nil {
					t.Fatalf("startup prompt: %v", err)
				}
				if scenario == "web" {
					armDashboardTestRule(t, strings.Fields(first)[3])
				}
				sig := syscall.SIGPIPE
				if scenario == "final-output" {
					_ = readEnd.Close()
					sig = syscall.SIGINT
				}
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
			}
			err = cmd.Wait()
			if scenario == "restored" {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGPIPE {
					t.Fatalf("default SIGPIPE not restored: %v stderr=%s", err, stderr.String())
				}
			} else if err != nil {
				t.Fatalf("command failed: %v stderr=%s", err, stderr.String())
			}
			operations, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(operations)), "\n")
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "-I ") || lines[1] != "-D "+strings.TrimPrefix(lines[0], "-I ") {
				t.Fatalf("owned rule was not removed exactly once: %q", operations)
			}
		})
	}
}

func armDashboardTestRule(t *testing.T, url string) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	csrf := regexp.MustCompile(`name="livewire-csrf" content="([^"]+)"`).FindSubmatch(body)
	if len(csrf) != 2 {
		t.Fatal("dashboard omitted CSRF token")
	}
	req, err := http.NewRequest(http.MethodPost, url+"/api/rstrule", strings.NewReader(`{"action":"add","ip":"192.0.2.10","port":502}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Livewire-CSRF", string(csrf[1]))
	response, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("arm dashboard rule: status=%d body=%s", response.StatusCode, body)
	}
}
