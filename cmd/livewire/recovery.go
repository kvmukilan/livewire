package main

import (
	"fmt"
	"strings"
)

func blockedReplayError(capture, reason string) error {
	// Single quoting is copyable in PowerShell and POSIX shells for ordinary
	// paths. A path with a quote uses a placeholder rather than unsafe escaping.
	path := "'" + capture + "'"
	if strings.ContainsAny(capture, "'\r\n") {
		path = "<capture>"
	}
	return fmt.Errorf("no safely executable session: %s; no packets were sent\nNext: livewire check %s -details\nSelect an exchange shown there, then preview: livewire reproduce %s -mode application -session <session-id> -dry-run\nFor local driver or interface issues: livewire doctor", reason, path, path)
}
