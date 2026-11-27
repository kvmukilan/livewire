package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/webui"
)

const defaultWebAddr = "127.0.0.1:8080"

// cmdWeb serves the browser dashboard (capture, load, replay, RST rules, SSH)
// over HTTPS only and opens it in the default browser. It binds to localhost by
// default; live replay needs the same privileges as the CLI.
func cmdWeb(args []string) error {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	addr := fs.String("addr", defaultWebAddr, "address to serve the dashboard on")
	dir := fs.String("dir", ".", "directory pcaps are read from / captured into")
	unsafeListen := fs.Bool("unsafe-listen", false, "allow an unauthenticated non-loopback dashboard listener")
	noOpen := fs.Bool("no-open", false, "do not open the dashboard in the default browser")
	tlsCert := fs.String("tls-cert", "", "PEM certificate for the dashboard (default: a local self-signed certificate)")
	tlsKey := fs.String("tls-key", "", "PEM private key for -tls-cert")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire web [-addr " + defaultWebAddr + "] [-dir .]")
		fmt.Println("\nServe the livewire dashboard over HTTPS and open it in a browser.")
		printFlags(fs, "addr", "dir", "no-open", "tls-cert", "tls-key", "unsafe-listen")
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
	identity, err := webui.LoadTLSIdentity(webui.TLSOptions{CertFile: *tlsCert, KeyFile: *tlsKey, StateDir: dashboardStateDir(), Hosts: dashboardCertHosts(*addr)})
	if err != nil {
		_ = srv.Shutdown(context.Background())
		return err
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil && !flagWasSet(fs, "addr") {
		// The default port is a convenience, not a contract: a second copy or
		// another local service must not stop the dashboard from starting.
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		_ = srv.Shutdown(context.Background())
		return err
	}
	url := "https://" + listener.Addr().String()
	httpServer := &http.Server{
		Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
	}
	if _, err := fmt.Printf("livewire dashboard on %s  (pcap dir: %s)\nlive replay needs the same privileges as the CLI (Administrator/root for RST suppression)\n", url, *dir); err != nil {
		return errors.Join(err, srv.Shutdown(context.Background()), listener.Close())
	}
	if identity.SelfSigned {
		if _, err := fmt.Printf("HTTPS uses a certificate made on this machine, so the browser asks once before trusting it.\nIts SHA-256 fingerprint is %s\n", identity.Fingerprint); err != nil {
			return errors.Join(err, srv.Shutdown(context.Background()), listener.Close())
		}
	}
	if *unsafeListen {
		if _, err := fmt.Println("WARNING: dashboard authentication is not configured; network clients with the session page can control privileged replay"); err != nil {
			return errors.Join(err, srv.Shutdown(context.Background()), listener.Close())
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.Serve(tls.NewListener(listener, identity.Config)) }()
	if !*noOpen && !*unsafeListen {
		openBrowser(url)
	}
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

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// dashboardStateDir is where the dashboard keeps its local certificate. An
// empty result keeps the certificate in memory for this launch only.
func dashboardStateDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "livewire")
}

func dashboardCertHosts(addr string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	host, _, err := net.SplitHostPort(addr)
	host = strings.Trim(host, "[]")
	if err != nil || host == "" || isLoopbackListenAddr(addr) {
		return hosts
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return hosts
	}
	return append(hosts, host)
}

// openBrowser is best effort: the URL is already printed, so a machine without
// a desktop session simply does not get a browser window.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err == nil {
		go func() { _ = cmd.Wait() }()
	}
}
