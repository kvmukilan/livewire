package replay

// ResponseReadError identifies a failure while receiving a captured expected
// response. Dial, handshake, cancellation, maintenance, framing, and request or
// generated-control writes are deliberately excluded from this evidence type.
type ResponseReadError struct{ Err error }

func (e *ResponseReadError) Error() string { return e.Err.Error() }
func (e *ResponseReadError) Unwrap() error { return e.Err }

// peerReadError is private so idle reads can preserve errors without claiming
// that a captured response was being awaited. ReadExchange promotes it only
// while an expected response remains outstanding.
type peerReadError struct{ err error }

func (e *peerReadError) Error() string { return e.err.Error() }
func (e *peerReadError) Unwrap() error { return e.err }
