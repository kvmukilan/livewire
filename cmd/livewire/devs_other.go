//go:build !windows

package main

type pcapDev struct{ name, desc string }

// listPcapDevices is Windows-only; other OSes use net.Interfaces.
func listPcapDevices() ([]pcapDev, error) { return nil, nil }
