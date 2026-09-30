package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
)

type doctorFinding struct {
	Code       string `json:"code"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	NextAction string `json:"nextAction"`
}

type doctorReport struct {
	Version   string          `json:"version"`
	Platform  string          `json:"platform"`
	Interface string          `json:"interface,omitempty"`
	OutputDir string          `json:"outputDir"`
	Ready     bool            `json:"ready"`
	Findings  []doctorFinding `json:"findings"`
}

type doctorDeps struct {
	interfaces func() ([]net.Interface, error)
	platform   func(string) []doctorFinding
	writable   func(string) error
}

func cmdDoctor(args []string) error {
	return runDoctor(args, os.Stdout, doctorDeps{net.Interfaces, doctorPlatform, probeOutputDir})
}

func runDoctor(args []string, out io.Writer, deps doctorDeps) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(out)
	iface := fs.String("i", "", "packet interface to check (omit for general diagnostics)")
	jsonOut := fs.Bool("json", false, "write structured diagnostics to stdout")
	dir := fs.String("out-dir", ".", "existing output directory to test with a temporary file")
	all := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(out, "usage: livewire doctor [-i <interface>] [-json] [-out-dir <directory>]")
		fmt.Fprintln(out, "Checks local prerequisites without sending traffic or changing host configuration.")
		fmt.Fprintln(out, "Output writability uses a temporary file which is removed after the check.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *all {
		fs.Usage()
		return errAllFlags
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments; run livewire doctor --help")
	}
	r := doctorReport{Version: version, Platform: runtime.GOOS + "/" + runtime.GOARCH, Interface: *iface, OutputDir: *dir, Ready: true}
	r.Findings = append(r.Findings, deps.platform(*iface)...)
	ifaces, err := deps.interfaces()
	if err != nil {
		r.Findings = append(r.Findings, doctorFinding{"interface-list", packetSeverity(*iface), err.Error(), "Run livewire ifaces and check the operating system's network adapters."})
	} else if *iface == "" {
		r.Findings = append(r.Findings, doctorFinding{"interface-selection", "info", fmt.Sprintf("%d OS interfaces found; no packet interface selected", len(ifaces)), "For packet replay, run livewire ifaces, then livewire doctor -i <interface>."})
	} else {
		// Npcap device identities and flags are checked by doctorPlatform.
		found := false
		for _, nic := range ifaces {
			if nic.Name != *iface {
				continue
			}
			found = true
			if nic.Flags&net.FlagUp == 0 {
				r.Findings = append(r.Findings, doctorFinding{"interface-down", "blocker", "Selected interface is down", "Enable the adapter and connect the lab cable, then rerun livewire doctor -i <interface>."})
			} else {
				r.Findings = append(r.Findings, doctorFinding{"interface-up", "info", "Selected OS interface is up", "Preview the capture with livewire live <capture> -mode <intent> -dry-run."})
			}
		}
		if !found && runtime.GOOS != "windows" {
			r.Findings = append(r.Findings, doctorFinding{"interface-missing", "blocker", "Selected interface does not exist", "Run livewire ifaces and use an interface name from that list."})
		}
	}
	if err := deps.writable(*dir); err != nil {
		r.Findings = append(r.Findings, doctorFinding{"output-unwritable", "blocker", err.Error(), "Choose an existing writable directory with livewire doctor -out-dir <directory>; check free disk space and permissions."})
	} else {
		r.Findings = append(r.Findings, doctorFinding{"output-writable", "info", "Temporary output creation, write, sync, and cleanup succeeded", "Keep enough disk space for reports and packet evidence; this check does not reserve space."})
	}
	r.Findings = append(r.Findings, doctorFinding{"qualification-boundary", "info", "Local checks do not prove driver access, target reachability, or DUT behavior", "Review livewire live <capture> -mode <intent> -dry-run before a controlled lab replay."})
	for _, f := range r.Findings {
		if f.Severity == "blocker" {
			r.Ready = false
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(out, "Livewire doctor (%s)\n", r.Platform)
		for _, f := range r.Findings {
			fmt.Fprintf(out, "[%s] %s: %s\n  Next: %s\n", f.Severity, f.Code, f.Message, f.NextAction)
		}
		fmt.Fprintf(out, "\nLocal prerequisites ready: %t\n", r.Ready)
	}
	if !r.Ready {
		return fmt.Errorf("local prerequisites blocked; see diagnostic findings")
	}
	return nil
}

func packetSeverity(iface string) string {
	if iface != "" {
		return "blocker"
	}
	return "warning"
}

func probeOutputDir(dir string) (retErr error) {
	f, err := os.CreateTemp(dir, ".livewire-doctor-*")
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, os.Remove(f.Name())) }()
	_, writeErr := f.Write([]byte("Livewire output probe\n"))
	return errors.Join(writeErr, f.Sync(), f.Close())
}
