package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/kvmukilan/livewire/internal/runstate"
	"net/netip"
	"time"

	"github.com/kvmukilan/livewire/internal/hoststack"
	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/replay"
)

type executionFlags struct {
	concurrency  int
	runTimeout   time.Duration
	strictExit   bool
	stateDir     string
	resumeDir    string
	journal      *runstate.Store
	scenarioPath string
	scenario     *replay.Scenario
}

func (o *executionFlags) register(fs *flag.FlagSet) {
	fs.IntVar(&o.concurrency, "concurrency", 32, "maximum concurrent replay sessions (1..1024)")
	fs.DurationVar(&o.runTimeout, "run-timeout", 0, "overall run deadline including attempts and waits (0 disables)")
	fs.BoolVar(&o.strictExit, "strict-exit", false, "fail unless every selected exchange completes and its checked responses match")
	fs.StringVar(&o.stateDir, "state-dir", "", "new directory for durable replay progress (opt-in)")
	fs.StringVar(&o.resumeDir, "resume", "", "resume a run from its state directory; provide the same capture and replay options")
	fs.StringVar(&o.scenarioPath, "scenario", "", "versioned application dependencies and response bindings JSON")
}
func (o executionFlags) validate() error {
	if o.stateDir != "" && o.resumeDir != "" {
		return fmt.Errorf("use only one of -state-dir and -resume")
	}
	if o.concurrency < 1 || o.concurrency > 1024 {
		return fmt.Errorf("-concurrency must be between 1 and 1024")
	}
	if o.runTimeout < 0 {
		return fmt.Errorf("-run-timeout cannot be negative")
	}
	return nil
}
func (o executionFlags) context(parent context.Context) (context.Context, context.CancelFunc) {
	ctx := replay.WithExecution(parent, replay.ExecutionConfig{Concurrency: o.concurrency, Journal: o.journal, Scenario: replay.NewScenarioRuntime(o.scenario)})
	if o.runTimeout > 0 {
		return context.WithTimeout(ctx, o.runTimeout)
	}
	return context.WithCancel(ctx)
}

func (o *executionFlags) openState(captureDigest string, configuration any, preview bool) error {
	if o.stateDir == "" && o.resumeDir == "" {
		return nil
	}
	if preview && o.resumeDir == "" {
		return nil
	}
	digest, err := runstate.Digest(configuration)
	if err != nil {
		return err
	}
	dir := o.stateDir
	if o.resumeDir != "" {
		dir = o.resumeDir
	}
	o.journal, err = runstate.Open(dir, runstate.Manifest{Version: runstate.Version, CaptureDigest: captureDigest, ConfigurationDigest: digest}, o.resumeDir != "", preview)
	if err == nil && !preview && o.resumeDir != "" {
		for key, r := range o.journal.Resources() {
			if r.Owner != o.journal.Owner() {
				o.journal.Close()
				return fmt.Errorf("resume refused: firewall resource ownership differs")
			}
			ip, e := netip.ParseAddr(r.Target)
			if e != nil {
				o.journal.Close()
				return e
			}
			if e = hoststack.ReconcileOwned(hoststack.Rule{TargetIP: ip, TargetPort: r.TargetPort, LocalPort: r.LocalPort, Owner: r.Owner}); e != nil {
				o.journal.Close()
				return fmt.Errorf("reconcile this run's firewall rule: %w", e)
			}
			if e = o.journal.ResourceReleased(key); e != nil {
				o.journal.Close()
				return e
			}
		}
	}
	if err == nil && preview {
		for key, p := range o.journal.Progress() {
			fmt.Printf("Resume %s: completed=%v uncertain=%v last-confirmed=%d\n", key, p.Result != nil && p.Result.Completed, p.Uncertain, p.LastConfirmed)
		}
	}
	return err
}
func strictExitError(enabled bool, ctx context.Context, summary iterate.Summary) error {
	if !enabled {
		return nil
	}
	t := summary.Sessions
	if ctx.Err() != nil || t.Same == 0 || t.Different+t.Unverified+t.WireOnly+t.Incomplete > 0 {
		return fmt.Errorf("strict exit: not every selected exchange completed with positively verified matching responses")
	}
	return nil
}
