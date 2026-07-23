package lab

import (
	"encoding/json"
	"testing"
)

func FuzzScenarioParsing(f *testing.F) {
	f.Add([]byte(`{"version":1,"seed":1,"rules":[]}`))
	f.Add([]byte(`{"version":1,"rules":[{"match":{"direction":"client-to-server"},"action":{"delay":"5ms"}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var scenario Scenario
		if json.Unmarshal(data, &scenario) == nil {
			_ = scenario.Validate()
		}
	})
}
