//go:build !windows

package main

func launchedWithoutTerminal() bool { return false }

func holdWindowOpen() {}
