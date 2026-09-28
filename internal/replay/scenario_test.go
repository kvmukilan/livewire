package replay

import (
	"context"
	"testing"
	"time"
)

func TestScenarioRejectsAmbiguousAndCyclicDependencies(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"captureDigest":"x","steps":[{"id":"a","session":"tcp-0","request":1,"dependsOn":["missing"]}]}`,
		`{"version":1,"captureDigest":"x","steps":[{"id":"a","session":"tcp-0","request":1,"dependsOn":["b"]},{"id":"b","session":"tcp-0","request":2}]}`,
		`{"version":1,"captureDigest":"x","steps":[{"id":"a","session":"tcp-0","request":1},{"id":"b","session":"tcp-0","request":1}]}`,
		`{"version":1,"captureDigest":"x","steps":[{"id":"a","session":"tcp-0","request":1,"set":{"http.header.Authorization":"${absent}"}}]}`,
	} {
		if _, err := ParseScenario([]byte(body), "x"); err == nil {
			t.Fatalf("accepted invalid scenario %s", body)
		}
	}
}
func TestScenarioDependencyFailureUnblocksWaiter(t *testing.T) {
	s, err := ParseScenario([]byte(`{"version":1,"captureDigest":"x","steps":[{"id":"a","session":"tcp-0","request":1},{"id":"b","session":"tcp-1","request":1,"dependsOn":["a"]}]}`), "x")
	if err != nil {
		t.Fatal(err)
	}
	r := NewScenarioRuntime(s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Before(ctx, "tcp-1", 1, NewRuntimeState(nil)) }()
	r.End("tcp-0")
	if err := <-done; err == nil || ctx.Err() != nil {
		t.Fatalf("waiter did not stop on failed prerequisite: %v", err)
	}
}
