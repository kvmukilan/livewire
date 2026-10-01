// Package protofuzz drives a live Modbus/TCP endpoint with mutated application
// frames and classifies how it answers, to find framing and bounds handling a
// device gets wrong before someone else does.
//
// It is a robustness test, not a weapon: every case is derived from a seed the
// operator supplied, the engine paces itself, and it stops as soon as a liveness
// probe shows the target has stopped answering. A device that wedges is reported
// once rather than hammered, because on a plant floor the second case after a
// wedge tells you nothing the first did not.
//
// The state feedback follows AFLNet (Pham, Böhme and Roychoudhury, ICST 2020):
// a black-box network target will not hand you code coverage, but the response
// code it returns is an observable proxy for the state it is in. Seeds that
// reach a rarely-answered state get mutated more often, on the theory that the
// path behind a rare answer is the one least likely to have been exercised.
package protofuzz
