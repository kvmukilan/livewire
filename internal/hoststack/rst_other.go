//go:build !linux && !windows

package hoststack

import "fmt"

// newSuppressor reports that automatic RST suppression isn't implemented here;
// suppress manually (e.g. pf) or run without the guard.
func newSuppressor(r Rule) (Suppressor, error) {
	return nil, fmt.Errorf("hoststack: automatic host-RST suppression is not implemented on this OS; " +
		"suppress outbound RSTs to the target manually (e.g. pf) or run with the guard disabled")
}
