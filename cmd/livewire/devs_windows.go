//go:build windows

package main

import "github.com/kvmukilan/livewire/internal/backend"

type pcapDev struct{ name, desc string }

func listPcapDevices() ([]pcapDev, error) {
	devs, err := backend.ListPcapDevices()
	if err != nil {
		return nil, err
	}
	out := make([]pcapDev, len(devs))
	for i, d := range devs {
		out[i] = pcapDev{name: d.Name, desc: d.Description}
	}
	return out, nil
}
