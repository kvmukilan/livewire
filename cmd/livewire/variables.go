package main

import (
	"sort"
	"strings"

	"github.com/kvmukilan/livewire/internal/runvars"
)

type setFlags map[string]string

func (s *setFlags) Set(value string) error {
	k, v, err := runvars.ParseAssignment(value)
	if err != nil {
		return err
	}
	if *s == nil {
		*s = map[string]string{}
	}
	(*s)[k] = v
	return nil
}

func (s *setFlags) String() string {
	if s == nil || len(*s) == 0 {
		return ""
	}
	keys := runvars.Names(*s)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		value := (*s)[k]
		if runvars.IsSecret(k) {
			value = "[REDACTED]"
		}
		parts = append(parts, k+"="+value)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func redactRunText(value string, variables map[string]string) string {
	for name, secret := range variables {
		if runvars.IsSecret(name) && secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}
