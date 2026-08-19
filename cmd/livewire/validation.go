package main

import (
	"fmt"
	"net"
	"strconv"
)

const maxReplayAttempts = 1000

func validateNetworkTarget(value, flagName string) error {
	_, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", flagName, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s port must be between 1 and 65535", flagName)
	}
	return nil
}
