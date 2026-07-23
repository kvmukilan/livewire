package replay

import "fmt"

type Confidence int

type Message struct {
	Kind   string         `json:"kind"`
	Raw    []byte         `json:"-"`
	Fields map[string]any `json:"fields,omitempty"`
}

type RuntimeState struct {
	Variables map[string]string
	Learned   map[string][]byte
}

type Match struct {
	Matched bool   `json:"matched"`
	Key     string `json:"key,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type Difference struct {
	Field      string `json:"field"`
	Expected   string `json:"expected,omitempty"`
	Actual     string `json:"actual,omitempty"`
	Structural bool   `json:"structural"`
}

type VerifyMode string

const (
	VerifyOff     VerifyMode = "off"
	VerifyLenient VerifyMode = "lenient"
	VerifyStrict  VerifyMode = "strict"
)

type Adapter interface {
	Name() string
	Detect(Session) Confidence
	Decode(Direction, []byte) ([]Message, error)
	Prepare(Direction, Message, *RuntimeState) ([]byte, error)
	Correlate(expected, actual Message, state *RuntimeState) Match
	Compare(expected, actual Message, mode VerifyMode) []Difference
}

// ExchangeAwareAdapter is an optional extension for protocols whose framing
// depends on the opposite half of the exchange. HTTP HEAD and successful
// CONNECT responses are the canonical examples: their Content-Length does not
// describe bytes present on the wire.
type ExchangeAwareAdapter interface {
	DecodeExchange(Direction, []byte, []Message) ([]Message, error)
}

// PeerConsumptionAdapter reports how many opposite-direction messages a
// decoded turn completes. It lets pipelined protocols retain unmatched
// requests for the next response turn.
type PeerConsumptionAdapter interface {
	ConsumedPeers(Direction, []Message) int
}

func DecodeWithContext(adapter Adapter, direction Direction, data []byte, peers []Message) ([]Message, error) {
	if contextual, ok := adapter.(ExchangeAwareAdapter); ok {
		return contextual.DecodeExchange(direction, data, peers)
	}
	return adapter.Decode(direction, data)
}

func ConsumePeers(adapter Adapter, direction Direction, messages []Message, available int) int {
	n := len(messages)
	if contextual, ok := adapter.(PeerConsumptionAdapter); ok {
		n = contextual.ConsumedPeers(direction, messages)
	}
	if n < 0 {
		return 0
	}
	if n > available {
		return available
	}
	return n
}

// EOFFramingAdapter identifies messages whose application boundary is the
// transport close rather than an in-band length or delimiter.
type EOFFramingAdapter interface {
	RequiresEOF(Direction, Message) bool
}

// ExpectedNormalizer lets an adapter apply the same run-variable semantics to
// a captured response before correlation and comparison. This is needed when a
// request substitution is echoed by the peer (for example, a DNS question
// name) and prevents a correct live response being compared to stale capture
// values.
type ExpectedNormalizer interface {
	NormalizeExpected(Direction, Message, *RuntimeState) (Message, error)
}

func NormalizeExpected(adapter Adapter, direction Direction, message Message, state *RuntimeState) (Message, error) {
	if normalizer, ok := adapter.(ExpectedNormalizer); ok {
		return normalizer.NormalizeExpected(direction, message, state)
	}
	return message, nil
}

func NormalizeExpectedMessages(adapter Adapter, direction Direction, messages []Message, state *RuntimeState) ([]Message, error) {
	out := make([]Message, len(messages))
	for i, message := range messages {
		normalized, err := NormalizeExpected(adapter, direction, message, state)
		if err != nil {
			return nil, fmt.Errorf("normalize expected message %d: %w", i, err)
		}
		out[i] = normalized
	}
	return out, nil
}

type Registry struct {
	adapters []Adapter
}

func NewRegistry(adapters ...Adapter) *Registry {
	r := &Registry{}
	for _, a := range adapters {
		if a != nil {
			r.adapters = append(r.adapters, a)
		}
	}
	return r
}

func (r *Registry) Register(a Adapter) {
	if a != nil {
		r.adapters = append(r.adapters, a)
	}
}

func (r *Registry) Best(s Session) (Adapter, Confidence) {
	var best Adapter
	var score Confidence
	for _, a := range r.adapters {
		if c := a.Detect(s); c > score {
			best, score = a, c
		}
	}
	return best, score
}

func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a.Name())
	}
	return out
}

func (r *Registry) ByName(name string) Adapter {
	for _, a := range r.adapters {
		if a.Name() == name {
			return a
		}
	}
	return nil
}

func (m Message) String() string {
	if m.Kind != "" {
		return m.Kind
	}
	return fmt.Sprintf("%d bytes", len(m.Raw))
}
