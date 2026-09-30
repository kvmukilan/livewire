package qualification

import (
	"strconv"
	"strings"
)

// UsesStatelessReproduce separates the corrected v1.1 command contract from
// immutable v1.0 qualification records. Unknown versions use the stricter gate.
func UsesStatelessReproduce(version string) bool {
	return labVersionAtLeast(version, 1, 1, 0)
}

func labVersionAtLeast(version string, major, minor, patch int) bool {
	parts := strings.Split(strings.SplitN(strings.TrimPrefix(version, "v"), "-", 2)[0], ".")
	if len(parts) != 3 {
		return true
	}
	want := [3]int{major, minor, patch}
	var got [3]int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return true
		}
		got[i] = n
	}
	for i := range got {
		if got[i] != want[i] {
			return got[i] > want[i]
		}
	}
	return true
}

func labCommandAllowed(version, suite, command string) bool {
	if suite == "stateless" {
		return command == "replay" || UsesStatelessReproduce(version) && command == "reproduce"
	}
	return command == "live" || !UsesStatelessReproduce(version) && command == "reproduce"
}

func requiredLabRuns(version string) []string {
	var required []string
	for _, suite := range []string{"windows-amd64/application", "linux-amd64/application", "linux-amd64/packet"} {
		required = append(required, suite+"/live")
		if !UsesStatelessReproduce(version) {
			required = append(required, suite+"/reproduce")
		}
	}
	if requiresStatelessLab(version) {
		required = append(required, "linux-amd64/stateless/replay")
	}
	if UsesStatelessReproduce(version) {
		required = append(required, "linux-amd64/stateless/reproduce")
	}
	return required
}
