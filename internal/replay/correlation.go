package replay

import "fmt"

// KeyedResponses opts in only protocols that permit transaction reordering.
// Ordered protocols such as HTTP/1 must never match by response content.
type KeyedResponses interface{ ResponseKey(Message) string }

func AlignResponses(a Adapter, expected, actual []Message, state *RuntimeState) ([]Message, error) {
	keyed, ok := a.(KeyedResponses)
	if !ok {
		return actual, nil
	}
	byKey := map[string][]Message{}
	for _, m := range actual {
		key := keyed.ResponseKey(m)
		byKey[key] = append(byKey[key], m)
	}
	out := make([]Message, 0, len(expected))
	for _, m := range expected {
		normalized, err := NormalizeExpected(a, ServerToClient, m, state)
		if err != nil {
			return nil, err
		}
		key := keyed.ResponseKey(normalized)
		queue := byKey[key]
		if len(queue) == 0 {
			return nil, fmt.Errorf("%s: missing response for transaction %s", a.Name(), key)
		}
		out = append(out, queue[0])
		byKey[key] = queue[1:]
	}
	for _, queue := range byKey {
		if len(queue) > 0 {
			return nil, fmt.Errorf("%s: unexpected response transaction", a.Name())
		}
	}
	return out, nil
}
