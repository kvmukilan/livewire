package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// commandSignalContext keeps termination, including a broken stdout/stderr
// pipe on Unix, on the ordinary cancellation path while privileged resources
// are owned. Call stop only after those resources have been released; it restores
// the signal handling that preceded the command. Windows ignores SIGPIPE.
func commandSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE)
}

// Progress writers also cancel synchronously on an output error, including on
// platforms without SIGPIPE. cancel must cancel the work context, not unregister
// its signal handler, because resource cleanup has not finished yet.
func writeCommandProgress(out io.Writer, cancel context.CancelFunc, format string, args ...any) {
	if _, err := fmt.Fprintf(out, format, args...); err != nil && cancel != nil {
		cancel()
	}
}
