package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/kvmukilan/livewire/internal/webui"
)

// cmdWeb serves the browser dashboard (capture, load, replay, RST rules, SSH).
// Binds to localhost by default; live replay needs the same privileges as the CLI.
func cmdWeb(args []string) error {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "address to serve the dashboard on")
	dir := fs.String("dir", ".", "directory pcaps are read from / captured into")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire web [-addr 127.0.0.1:8080] [-dir .]")
		fmt.Println("\nServe the livewire dashboard in a browser.")
		printFlags(fs, "addr", "dir")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, nil) {
		return errAllFlags
	}

	webui.Version = version
	srv := webui.NewServer(*dir)
	fmt.Printf("livewire dashboard on http://%s  (pcap dir: %s)\n", *addr, *dir)
	fmt.Println("live replay needs the same privileges as the CLI (Administrator/root for RST suppression)")
	return http.ListenAndServe(*addr, srv.Handler())
}
