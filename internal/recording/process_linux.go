//go:build linux

package recording

import (
	"errors"
	"golang.org/x/sys/unix"
	"os/exec"
	"sync"
	"syscall"
)

func startOwned(cmd *exec.Cmd) (func() error, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	active := true
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		if !active {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			err = nil
		}
		if err == nil {
			active = false
		}
		return err
	}, nil
}

func waitOwned(cmd *exec.Cmd, kill func() error) error {
	// Observe exit without reaping the leader. Its PID cannot be reused while
	// we terminate the group. A shared one-shot guard prevents a later Stop
	// from signalling an unrelated group after the leader has been reaped.
	var info unix.Siginfo
	var err error
	for {
		err = unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	return errors.Join(err, kill(), cmd.Wait())
}
