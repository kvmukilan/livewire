//go:build !windows && !linux

package recording

import (
	"fmt"
	"os/exec"
)

func startOwned(*exec.Cmd) (func() error, error) {
	return nil, fmt.Errorf("TLS recording is supported on Windows and Linux")
}
func waitOwned(cmd *exec.Cmd, _ func() error) error { return cmd.Wait() }
