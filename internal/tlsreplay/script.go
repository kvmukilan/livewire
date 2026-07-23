package tlsreplay

import "sort"

// ConversationOrder turns the per-direction decryption output into a bounded
// request/response script. DecryptFlow preserves record order within each
// direction but packet captures do not provide a single TLS record sequence
// number across directions, so the safe default alternates client and server
// application records and retains all leftovers.
func ConversationOrder(messages []AppMessage) []AppMessage {
	hasTimeline := false
	for _, message := range messages {
		hasTimeline = hasTimeline || message.HasCaptureTime
	}
	if hasTimeline {
		out := append([]AppMessage(nil), messages...)
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].CapturedAt != out[j].CapturedAt {
				return out[i].CapturedAt < out[j].CapturedAt
			}
			return out[i].CapturedPacket < out[j].CapturedPacket
		})
		return out
	}
	var client, server []AppMessage
	for _, m := range messages {
		if m.Role == FromClient {
			client = append(client, m)
		} else {
			server = append(server, m)
		}
	}
	out := make([]AppMessage, 0, len(messages))
	for len(client) > 0 || len(server) > 0 {
		if len(client) > 0 {
			out = append(out, client[0])
			client = client[1:]
		}
		if len(server) > 0 {
			out = append(out, server[0])
			server = server[1:]
		}
	}
	return out
}
