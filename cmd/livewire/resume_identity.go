package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"github.com/kvmukilan/livewire/internal/runvars"
	"os"
)

func reproduceIdentity(o reproduceOptions, inspection *replayintent.Inspection, registry *replay.Registry) (any, error) {
	vars := map[string]string{}
	for k, v := range o.variables {
		if !runvars.IsSecret(k) {
			vars[k] = v
		}
	}
	files := map[string]string{}
	vars["livewire.guard-disabled"] = fmt.Sprint(o.noGuard)
	vars["livewire.response-timeout"] = o.responseTimeout.String()
	vars["livewire.expect-fault"] = o.expectFault
	for name, path := range map[string]string{"ca": o.ca, "hostKey": o.sshHostKey} {
		if path != "" {
			b, e := os.ReadFile(path)
			if e != nil {
				return nil, e
			}
			files[name] = fmt.Sprintf("%x", sha256.Sum256(b))
		}
	}
	return map[string]any{"scenario": o.scenario, "plan": inspection.Plan, "mode": inspection.Mode, "target": o.target, "interface": o.iface, "strict": o.strict, "insecure": o.insecure, "serverName": o.serverName, "user": o.sshUser, "commands": o.sshCommands, "expects": o.sshExpects, "variables": vars, "adapters": adapters.VersionsForRegistry(registry), "securityFiles": files, "times": o.times, "gap": o.gap, "stopWhenDifferent": o.stopWhenDifferent, "concurrency": o.concurrency, "timeout": o.timeout}, nil
}
