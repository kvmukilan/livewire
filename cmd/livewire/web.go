package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/webui"
)

// cmdWeb serves the browser dashboard (capture, load, replay, RST rules, SSH).
// Binds to localhost by default; live replay needs the same privileges as the CLI.
func cmdWeb(args []string) error {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "address to serve the dashboard on")
	dir := fs.String("dir", ".", "directory pcaps are read from / captured into")
	unsafeListen := fs.Bool("unsafe-listen", false, "allow an unauthenticated non-loopback dashboard listener")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire web [-addr 127.0.0.1:8080] [-dir .]")
		fmt.Println("\nServe the livewire dashboard in a browser.")
		printFlags(fs, "addr", "dir", "unsafe-listen")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, nil) {
		return errAllFlags
	}

	if !*unsafeListen && !isLoopbackListenAddr(*addr) {
		return fmt.Errorf("refusing non-loopback dashboard address %q without -unsafe-listen", *addr)
	}
	ctx, stop := commandSignalContext(context.Background())
	defer stop()
	srv, err := webui.NewServerWithConfig(webui.Config{Dir: *dir, ListenAddr: *addr, UnsafeListen: *unsafeListen, Version: version})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		_ = srv.Shutdown(context.Background())
		return err
	}
	httpServer := &http.Server{
		Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
	}
	if _, err := fmt.Printf("livewire dashboard on http://%s  (pcap dir: %s)\nlive replay needs the same privileges as the CLI (Administrator/root for RST suppression)\n", listener.Addr(), *dir); err != nil {
		return errors.Join(err, srv.Shutdown(context.Background()), listener.Close())
	}
	if *unsafeListen {
		if _, err := fmt.Println("WARNING: dashboard authentication is not configured; network clients with the session page can control privileged replay"); err != nil {
			return errors.Join(err, srv.Shutdown(context.Background()), listener.Close())
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.Serve(listener) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errCh:
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Cancel replay and close privileged resources before waiting for HTTP
	// handlers to drain. Late handlers cannot create work after Server.Shutdown.
	return errors.Join(serveErr, srv.Shutdown(shutdownCtx), httpServer.Shutdown(shutdownCtx))
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
