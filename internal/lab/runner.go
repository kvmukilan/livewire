package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/wire"
)

type Backends struct {
	ClientTX backend.PacketBackend
	ClientRX backend.PacketBackend
	ServerTX backend.PacketBackend
	ServerRX backend.PacketBackend
}

var acquireBackends = openBackends

func (b Backends) close() {
	seen := map[backend.PacketBackend]bool{}
	for _, x := range []backend.PacketBackend{b.ClientTX, b.ClientRX, b.ServerTX, b.ServerRX} {
		if x != nil && !seen[x] {
			_ = x.Close()
			seen[x] = true
		}
	}
}

type Config struct {
	Trace    *replay.Trace
	Plan     *replay.ReplayPlan
	Topology Topology
	Scenario Scenario
	Profile  replay.Profile
	Drain    time.Duration
	// ActorTimeout bounds how long a functional/timing/transport actor waits
	// for the preceding opposite-side frame to cross the DUT.
	ActorTimeout time.Duration
	Progress     func(Progress)
	Backends     *Backends
}

type Progress struct {
	Stage       string        `json:"stage"`
	SessionID   string        `json:"sessionId,omitempty"`
	PacketIndex int           `json:"packetIndex,omitempty"`
	At          time.Duration `json:"at"`
	Message     string        `json:"message"`
}

type NATTransformation struct {
	SessionID string `json:"sessionId"`
	Before    string `json:"before"`
	After     string `json:"after"`
}

type LinkResolution struct {
	Side       string     `json:"side"`
	Gateway    netip.Addr `json:"gateway"`
	SourceMAC  string     `json:"sourceMac"`
	NextHopMAC string     `json:"nextHopMac"`
}

type TCPClockTransformation struct {
	SessionID string `json:"sessionId"`
	Direction string `json:"direction"`
	Delta     uint32 `json:"delta"`
}

type SessionVerdict struct {
	SessionID   string           `json:"sessionId"`
	Transport   replay.Transport `json:"transport"`
	Driver      string           `json:"driver"`
	Requested   replay.Profile   `json:"requestedFidelity"`
	Achieved    replay.Fidelity  `json:"achievedFidelity"`
	Captured    int              `json:"capturedFrames"`
	Injected    int              `json:"injectedFrames"`
	Crossed     int              `json:"crossedFrames"`
	Lost        int              `json:"lostFrames"`
	Duplicates  int              `json:"duplicates"`
	Reordered   int              `json:"reordered"`
	Timeouts    int              `json:"firewallTimeouts"`
	OneWay      *DurationStats   `json:"oneWayLatency,omitempty"`
	RTT         *DurationStats   `json:"roundTripLatency,omitempty"`
	Evidence    []int            `json:"evidencePacketIndexes,omitempty"`
	Completed   bool             `json:"completed"`
	Limitations []string         `json:"limitations,omitempty"`
}

type DurationStats struct {
	Min  time.Duration `json:"min"`
	Mean time.Duration `json:"mean"`
	Max  time.Duration `json:"max"`
}

type Metrics struct {
	Injected         int           `json:"injected"`
	Crossed          int           `json:"crossed"`
	Lost             int           `json:"lost"`
	Duplicates       int           `json:"duplicates"`
	Reordered        int           `json:"reordered"`
	FirewallResets   int           `json:"firewallResets"`
	FirewallTimeouts int           `json:"firewallTimeouts"`
	MinOneWay        time.Duration `json:"minOneWay"`
	MeanOneWay       time.Duration `json:"meanOneWay"`
	MaxOneWay        time.Duration `json:"maxOneWay"`
	MinRTT           time.Duration `json:"minRtt"`
	MeanRTT          time.Duration `json:"meanRtt"`
	MaxRTT           time.Duration `json:"maxRtt"`
}

type Result struct {
	Started           time.Time                `json:"started"`
	Finished          time.Time                `json:"finished"`
	RequestedFidelity replay.Profile           `json:"requestedFidelity"`
	AchievedFidelity  replay.Fidelity          `json:"achievedFidelity"`
	Schedule          ScheduleReport           `json:"schedule"`
	NAT               []NATTransformation      `json:"natTransformations,omitempty"`
	TCPClocks         []TCPClockTransformation `json:"tcpClockTransformations,omitempty"`
	Sessions          []SessionVerdict         `json:"sessions"`
	ResolvedLinks     []LinkResolution         `json:"resolvedLinks,omitempty"`
	Metrics           Metrics                  `json:"metrics"`
	Evidence          []pcapio.Record          `json:"-"`
	Limitations       []string                 `json:"limitations,omitempty"`
	Cancelled         bool                     `json:"cancelled"`
}

func RunContext(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Trace == nil {
		return Result{}, fmt.Errorf("lab: trace is required")
	}
	if err := cfg.Topology.Validate(); err != nil {
		return Result{}, err
	}
	if err := cfg.Topology.ValidateTrace(cfg.Trace); err != nil {
		return Result{}, err
	}
	if cfg.Plan == nil {
		plan := BuildReplayPlan(cfg.Trace, cfg.Profile)
		cfg.Plan = &plan
	}
	if err := validateLabPlan(*cfg.Plan); err != nil {
		return Result{}, err
	}
	var owned bool
	backs := cfg.Backends
	if backs == nil {
		b, err := acquireBackends(cfg.Topology)
		if err != nil {
			return Result{}, err
		}
		backs, owned = &b, true
	}
	if owned {
		defer backs.close()
		resolvedTopology, resolutions, err := resolveTopologyLinks(cfg.Topology, *backs)
		if err != nil {
			return Result{}, err
		}
		cfg.Topology = resolvedTopology
		result, runErr := RunWithBackendsContext(ctx, cfg, *backs)
		result.ResolvedLinks = resolutions
		return result, runErr
	}
	return RunWithBackendsContext(ctx, cfg, *backs)
}

func resolveTopologyLinks(topology Topology, b Backends) (Topology, []LinkResolution, error) {
	type target struct {
		name string
		side *Side
		tx   backend.PacketBackend
	}
	var resolved []LinkResolution
	for _, item := range []target{{"client", &topology.Client, b.ClientTX}, {"server", &topology.Server, b.ServerTX}} {
		if !item.side.Gateway.IsValid() || item.side.SourceMAC != "" && item.side.NextHopMAC != "" {
			continue
		}
		source, next, err := backend.ResolveLink(item.side.Interface, item.side.Gateway, item.tx)
		if err != nil {
			return topology, resolved, fmt.Errorf("lab: resolve %s gateway %s: %w", item.name, item.side.Gateway, err)
		}
		if item.side.SourceMAC == "" {
			item.side.SourceMAC = net.HardwareAddr(source[:]).String()
		}
		if item.side.NextHopMAC == "" {
			item.side.NextHopMAC = net.HardwareAddr(next[:]).String()
		}
		resolved = append(resolved, LinkResolution{
			Side: item.name, Gateway: item.side.Gateway,
			SourceMAC: item.side.SourceMAC, NextHopMAC: item.side.NextHopMAC,
		})
	}
	return topology, resolved, nil
}

func openBackends(t Topology) (Backends, error) {
	var b Backends
	var err error
	fail := func(e error) (Backends, error) { b.close(); return Backends{}, e }
	if b.ClientTX, err = backend.OpenSender(t.Client.Interface); err != nil {
		return b, err
	}
	if b.ClientRX, err = backend.OpenCapture(t.Client.Interface, true); err != nil {
		return fail(err)
	}
	if b.ServerTX, err = backend.OpenSender(t.Server.Interface); err != nil {
		return fail(err)
	}
	if b.ServerRX, err = backend.OpenCapture(t.Server.Interface, true); err != nil {
		return fail(err)
	}
	return b, nil
}

func RunWithBackendsContext(ctx context.Context, cfg Config, b Backends) (Result, error) {
	if b.ClientTX == nil || b.ClientRX == nil || b.ServerTX == nil || b.ServerRX == nil {
		return Result{}, fmt.Errorf("lab: four transmit/receive backends are required")
	}
	if cfg.Plan == nil {
		plan := BuildReplayPlan(cfg.Trace, cfg.Profile)
		cfg.Plan = &plan
	}
	if err := validateLabPlan(*cfg.Plan); err != nil {
		return Result{}, err
	}
	schedule, scheduleReport, err := CompileSchedule(cfg.Trace, cfg.Scenario, cfg.Topology)
	if err != nil {
		return Result{}, err
	}
	requested := normalizedLabProfile(cfg.Profile)
	result := Result{
		Started: time.Now(), RequestedFidelity: requested, AchievedFidelity: replay.FidelityWire,
		Schedule:    scheduleReport,
		Limitations: []string{"two-sided actors preserve captured bytes and timing after endpoint rewrites; application semantics are not claimed"},
	}
	if cfg.ActorTimeout <= 0 {
		cfg.ActorTimeout = 2 * time.Second
	}
	result.Limitations = append(result.Limitations, scheduleReport.Limitations...)
	collector := newCollector(cfg.Trace, *cfg.Plan, cfg.Topology, b.ClientRX.LinkType(), b.ServerRX.LinkType())
	runCtx, cancel := context.WithCancel(ctx)
	var observers sync.WaitGroup
	observers.Add(2)
	go func() { defer observers.Done(); observe(runCtx, "client", 0, b.ClientRX, collector) }()
	go func() { defer observers.Done(); observe(runCtx, "server", 1, b.ServerRX, collector) }()
	defer func() {
		cancel()
		observers.Wait()
	}()

	sessions := map[string]*replay.Session{}
	for _, s := range cfg.Trace.Sessions {
		sessions[s.ID] = s
	}
	planModes := map[string]replay.Mode{}
	for _, entry := range cfg.Plan.Entries {
		planModes[entry.SessionID] = entry.Mode
	}
	dependencies := actorDependencies(cfg.Trace)
	scheduledPackets := map[string]map[int]bool{}
	for _, frame := range schedule {
		if scheduledPackets[frame.SessionID] == nil {
			scheduledPackets[frame.SessionID] = map[int]bool{}
		}
		scheduledPackets[frame.SessionID][frame.PacketIndex] = true
	}
	barriers := map[string]map[int]*crossingBarrier{}
	for _, sf := range schedule {
		if !waitContextUntil(ctx, result.Started.Add(sf.At)) {
			result.Cancelled = true
			cancel()
			observers.Wait()
			finishResult(&result, collector)
			return result, ctx.Err()
		}
		adaptiveActor := planModes[sf.SessionID] == replay.ModeStateful
		if adaptiveActor {
			if dependency, ok := dependencies[sf.SessionID][sf.PacketIndex]; ok {
				barrier := barriers[sf.SessionID][dependency]
				switch {
				case barrier != nil:
					if !waitCrossing(ctx, barrier.done, cfg.ActorTimeout) {
						if ctx.Err() != nil {
							result.Cancelled = true
							cancel()
							observers.Wait()
							finishResult(&result, collector)
							return result, ctx.Err()
						}
						result.Metrics.FirewallTimeouts++
						collector.actorTimeout(sf.SessionID)
						result.Limitations = appendUniqueString(result.Limitations, fmt.Sprintf("%s packet %d was not injected because dependency packet %d did not cross the DUT within %s", sf.SessionID, sf.PacketIndex, dependency, cfg.ActorTimeout))
						continue
					}
				case !scheduledPackets[sf.SessionID][dependency]:
					result.Metrics.FirewallTimeouts++
					collector.actorTimeout(sf.SessionID)
					result.Limitations = appendUniqueString(result.Limitations, fmt.Sprintf("%s packet %d was not injected because dependency packet %d was dropped by the scenario", sf.SessionID, sf.PacketIndex, dependency))
					continue
				default:
					// An explicit reorder fault moved the dependency after this
					// actor event. Preserve the requested fault rather than deadlock
					// the single monotonic scheduler.
					result.Limitations = appendUniqueString(result.Limitations, fmt.Sprintf("%s packet %d actor gating was bypassed because reorder moved dependency packet %d later", sf.SessionID, sf.PacketIndex, dependency))
				}
			}
		}
		frame, rerr := rewriteScheduled(sf, sessions[sf.SessionID], cfg.Topology, collector, adaptiveActor)
		if rerr != nil {
			cancel()
			observers.Wait()
			finishResult(&result, collector)
			return result, rerr
		}
		if len(frame) == 0 {
			continue
		}
		frames := [][]byte{frame}
		if mtu := sideFor(cfg.Topology, sf.Side).MTU; mtu > 0 {
			var limitation string
			frames, limitation = fragmentForMTU(frame, sf.LinkType, mtu, uint32(sf.PacketIndex+1))
			if limitation != "" {
				result.Limitations = appendUniqueString(result.Limitations, "topology "+sf.Side+" MTU: "+limitation)
			}
			if len(frames) > 1 {
				result.Schedule.Fragmented += len(frames) - 1
				result.Schedule.ScheduledFrames += len(frames) - 1
			}
			if len(frames) == 0 {
				result.Schedule.DroppedFrames++
				if result.Schedule.ScheduledFrames > 0 {
					result.Schedule.ScheduledFrames--
				}
				continue
			}
		}
		tx := b.ClientTX
		iface := uint32(0)
		if sf.Side == "server" {
			tx, iface = b.ServerTX, 1
		}
		barrier := newCrossingBarrier(len(frames))
		if barriers[sf.SessionID] == nil {
			barriers[sf.SessionID] = map[int]*crossingBarrier{}
		}
		if barriers[sf.SessionID][sf.PacketIndex] == nil {
			barriers[sf.SessionID][sf.PacketIndex] = barrier
		}
		for fragmentIndex, outbound := range frames {
			injectedAt := time.Now()
			// Register the expected crossing before Send. In-memory and very fast
			// backends can make the observer runnable before Send returns.
			collector.inject(sf, iface, tx.LinkType(), outbound, injectedAt, barrier)
			if err := tx.Send(outbound); err != nil {
				collector.rollbackInjection(sf, iface, tx.LinkType(), outbound, injectedAt)
				cancel()
				observers.Wait()
				finishResult(&result, collector)
				return result, fmt.Errorf("lab: send %s packet %d fragment %d: %w", sf.Side, sf.PacketIndex, fragmentIndex, err)
			}
		}
		emit(cfg, Progress{Stage: "inject", SessionID: sf.SessionID, PacketIndex: sf.PacketIndex, At: time.Since(result.Started), Message: fmt.Sprintf("%s side%s", sf.Side, faultSuffix(sf.Faults))})
	}
	if cfg.Drain <= 0 {
		cfg.Drain = 250 * time.Millisecond
	}
	t := time.NewTimer(cfg.Drain)
	select {
	case <-ctx.Done():
		result.Cancelled = true
	case <-t.C:
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	cancel()
	observers.Wait()
	finishResult(&result, collector)
	if result.Cancelled {
		return result, ctx.Err()
	}
	return result, nil
}

func actorDependencies(trace *replay.Trace) map[string]map[int]int {
	out := map[string]map[int]int{}
	for _, session := range trace.Sessions {
		out[session.ID] = map[int]int{}
		previousPacket := -1
		previousDirection := replay.DirectionUnknown
		for _, event := range session.Events {
			if event.Direction != replay.DirectionUnknown && previousDirection != replay.DirectionUnknown && event.Direction != previousDirection {
				out[session.ID][event.PacketIndex] = previousPacket
			}
			if event.Direction != replay.DirectionUnknown {
				previousPacket = event.PacketIndex
				previousDirection = event.Direction
			}
		}
	}
	return out
}

func waitCrossing(ctx context.Context, done <-chan struct{}, timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

func observe(ctx context.Context, side string, iface uint32, b backend.PacketBackend, c *collector) {
	buf := make([]byte, 65536)
	for ctx.Err() == nil {
		n, ok, err := b.Recv(buf, 50*time.Millisecond)
		if err != nil {
			c.observerError(err)
			return
		}
		if ok {
			c.observe(side, iface, b.LinkType(), append([]byte(nil), buf[:n]...), b.Now())
		}
	}
}

func waitContextUntil(ctx context.Context, target time.Time) bool {
	d := time.Until(target)
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func emit(cfg Config, p Progress) {
	if cfg.Progress != nil {
		cfg.Progress(p)
	}
}

func faultSuffix(faults []string) string {
	if len(faults) == 0 {
		return ""
	}
	return " (" + fmt.Sprint(faults) + ")"
}

type observedTuple struct {
	src, dst replay.Endpoint
}

type pendingFrame struct {
	time        time.Time
	packetIndex int
	sessionID   string
	direction   replay.Direction
	barrier     *crossingBarrier
	tcp         bool
	tcpSeq      uint32
}

type crossingBarrier struct {
	remaining int
	done      chan struct{}
	closed    bool
}

func newCrossingBarrier(frames int) *crossingBarrier {
	b := &crossingBarrier{remaining: frames, done: make(chan struct{})}
	if frames == 0 {
		close(b.done)
		b.closed = true
	}
	return b
}

type collector struct {
	mu                   sync.Mutex
	trace                *replay.Trace
	plan                 replay.ReplayPlan
	topology             Topology
	links                [2]wire.LinkType
	evidence             []pcapio.Record
	pending              map[string][]pendingFrame
	learning             map[string]observedTuple
	nat                  map[string]NATTransformation
	tcpDeltas            map[string]map[replay.Direction]uint32
	latencies            []time.Duration
	rtts                 []time.Duration
	latenciesBySession   map[string][]time.Duration
	rttsBySession        map[string][]time.Duration
	requestAt            map[string]time.Time
	observedIdxBySession map[string][]int
	injected             int
	crossed              int
	injectedBySession    map[string]int
	crossedBySession     map[string]int
	duplicates           int
	duplicatesBySession  map[string]int
	timeoutsBySession    map[string]int
	evidenceBySession    map[string]map[int]bool
	lastCrossOwner       map[string]string
	seenCross            map[string]int
	resets               int
	errors               []string
}

func newCollector(trace *replay.Trace, plan replay.ReplayPlan, topology Topology, clientLink, serverLink wire.LinkType) *collector {
	return &collector{
		trace: trace, plan: plan, topology: topology, links: [2]wire.LinkType{clientLink, serverLink},
		pending: map[string][]pendingFrame{}, learning: map[string]observedTuple{}, nat: map[string]NATTransformation{},
		tcpDeltas: map[string]map[replay.Direction]uint32{}, seenCross: map[string]int{}, requestAt: map[string]time.Time{},
		injectedBySession: map[string]int{}, crossedBySession: map[string]int{}, latenciesBySession: map[string][]time.Duration{},
		rttsBySession: map[string][]time.Duration{}, observedIdxBySession: map[string][]int{}, duplicatesBySession: map[string]int{},
		timeoutsBySession: map[string]int{}, evidenceBySession: map[string]map[int]bool{}, lastCrossOwner: map[string]string{},
	}
}

func (c *collector) inject(sf ScheduledFrame, iface uint32, link wire.LinkType, frame []byte, at time.Time, barrier *crossingBarrier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.injected++
	c.injectedBySession[sf.SessionID]++
	c.addEvidenceIndex(sf.SessionID, sf.PacketIndex)
	c.evidence = append(c.evidence, evidenceRecord(iface, link, frame, at))
	key := crossingKey(sf.Side, frame, link)
	pending := pendingFrame{time: at, packetIndex: sf.PacketIndex, sessionID: sf.SessionID, direction: sf.Direction, barrier: barrier}
	if packet, err := wire.Parse(frame, link); err == nil && packet.IsTCP() {
		pending.tcp, pending.tcpSeq = true, packet.Seq().Uint32()
	}
	c.pending[key] = append(c.pending[key], pending)
	if sf.Direction == replay.ClientToServer {
		c.requestAt[sf.SessionID] = at
	}
}

func (c *collector) rollbackInjection(sf ScheduledFrame, iface uint32, link wire.LinkType, frame []byte, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := crossingKey(sf.Side, frame, link)
	queue := c.pending[key]
	removed := false
	for i := len(queue) - 1; i >= 0; i-- {
		if queue[i].packetIndex == sf.PacketIndex && queue[i].time.Equal(at) {
			queue = append(queue[:i], queue[i+1:]...)
			c.pending[key] = queue
			removed = true
			break
		}
	}
	if !removed {
		return
	}
	if c.injected > 0 {
		c.injected--
	}
	if c.injectedBySession[sf.SessionID] > 0 {
		c.injectedBySession[sf.SessionID]--
	}
	for i := len(c.evidence) - 1; i >= 0; i-- {
		rec := c.evidence[i]
		if rec.InterfaceID == iface && rec.Time.Equal(at) && bytes.Equal(rec.Data, frame) {
			c.evidence = append(c.evidence[:i], c.evidence[i+1:]...)
			break
		}
	}
}

func (c *collector) observe(side string, iface uint32, link wire.LinkType, frame []byte, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := side + "/" + frameFingerprint(frame, link)
	queue := c.pending[key]
	p, parseErr := wire.Parse(frame, link)
	if len(queue) == 0 {
		if c.seenCross[key] > 0 {
			c.duplicates++
			if owner := c.lastCrossOwner[key]; owner != "" {
				c.duplicatesBySession[owner]++
			}
			c.evidence = append(c.evidence, evidenceRecord(iface, link, frame, at))
			return
		}
		if parseErr == nil && p.IsTCP() && p.HasFlags(wire.FlagRST) {
			c.resets++
			c.evidence = append(c.evidence, evidenceRecord(iface, link, frame, at))
		}
		return
	}
	pending := queue[0]
	c.pending[key] = queue[1:]
	if pending.tcp && parseErr == nil && p.IsTCP() {
		if c.tcpDeltas[pending.sessionID] == nil {
			c.tcpDeltas[pending.sessionID] = map[replay.Direction]uint32{}
		}
		c.tcpDeltas[pending.sessionID][pending.direction] = p.Seq().Uint32() - pending.tcpSeq
	}
	c.crossed++
	c.crossedBySession[pending.sessionID]++
	c.lastCrossOwner[key] = pending.sessionID
	c.addEvidenceIndex(pending.sessionID, pending.packetIndex)
	c.seenCross[key]++
	if pending.barrier != nil && !pending.barrier.closed {
		pending.barrier.remaining--
		if pending.barrier.remaining <= 0 {
			close(pending.barrier.done)
			pending.barrier.closed = true
		}
	}
	c.latencies = append(c.latencies, at.Sub(pending.time))
	c.latenciesBySession[pending.sessionID] = append(c.latenciesBySession[pending.sessionID], at.Sub(pending.time))
	c.observedIdxBySession[pending.sessionID] = append(c.observedIdxBySession[pending.sessionID], pending.packetIndex)
	if pending.direction == replay.ServerToClient {
		if requestAt, ok := c.requestAt[pending.sessionID]; ok && !at.Before(requestAt) {
			c.rtts = append(c.rtts, at.Sub(requestAt))
			c.rttsBySession[pending.sessionID] = append(c.rttsBySession[pending.sessionID], at.Sub(requestAt))
		}
	}
	c.evidence = append(c.evidence, evidenceRecord(iface, link, frame, at))
	if side == "server" && parseErr == nil {
		c.learnTuple(pending.sessionID, p)
	}
}

func (c *collector) addEvidenceIndex(sessionID string, packetIndex int) {
	if c.evidenceBySession[sessionID] == nil {
		c.evidenceBySession[sessionID] = map[int]bool{}
	}
	c.evidenceBySession[sessionID][packetIndex] = true
}

func (c *collector) actorTimeout(sessionID string) {
	c.mu.Lock()
	c.timeoutsBySession[sessionID]++
	c.mu.Unlock()
}

func (c *collector) learnTuple(sessionID string, p *wire.Packet) {
	var session *replay.Session
	for _, s := range c.trace.Sessions {
		if s.ID == sessionID {
			session = s
			break
		}
	}
	if session == nil {
		return
	}
	actual := observedTuple{
		src: replay.Endpoint{IP: p.SrcIP(), Port: p.SrcPort()},
		dst: replay.Endpoint{IP: p.DstIP(), Port: p.DstPort()},
	}
	c.learning[sessionID] = actual
	wantClient, ok1 := c.topology.Map("client", session.Client)
	wantServer, ok2 := c.topology.Map("server", session.Server)
	if ok1 && ok2 && (actual.src != wantClient || actual.dst != wantServer) {
		c.nat[sessionID] = NATTransformation{SessionID: sessionID, Before: wantClient.String() + " -> " + wantServer.String(), After: actual.src.String() + " -> " + actual.dst.String()}
	}
}

func (c *collector) learnedTuple(sessionID string) (observedTuple, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.learning[sessionID]
	return t, ok
}

func (c *collector) peerTCPDelta(sessionID string, direction replay.Direction) (uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	peer := replay.ClientToServer
	if direction == replay.ClientToServer {
		peer = replay.ServerToClient
	}
	deltas := c.tcpDeltas[sessionID]
	delta, ok := deltas[peer]
	return delta, ok && delta != 0
}

func (c *collector) observerError(err error) {
	c.mu.Lock()
	c.errors = append(c.errors, err.Error())
	c.mu.Unlock()
}

func evidenceRecord(iface uint32, link wire.LinkType, frame []byte, at time.Time) pcapio.Record {
	b := append([]byte(nil), frame...)
	return pcapio.Record{Time: at, CapLen: len(b), OrigLen: len(b), Data: b, LinkType: link, InterfaceID: iface}
}

func crossingKey(injectedSide string, frame []byte, link wire.LinkType) string {
	opposite := "server"
	if injectedSide == "server" {
		opposite = "client"
	}
	return opposite + "/" + frameFingerprint(frame, link)
}

func frameFingerprint(frame []byte, link wire.LinkType) string {
	p, err := wire.Parse(frame, link)
	if err != nil {
		h := sha256.Sum256(frame)
		return fmt.Sprintf("raw/%x", h[:12])
	}
	payload := p.Payload()
	if p.PayloadLen() < len(payload) {
		payload = payload[:p.PayloadLen()]
	}
	h := sha256.Sum256(payload)
	switch {
	case p.IsTCP():
		// A TCP proxy is allowed to translate sequence and acknowledgement
		// clocks. Flags, payload length, content, side, and queue order remain a
		// stable crossing key without hiding duplication or reordering.
		return fmt.Sprintf("tcp/%02x/%d/%x", p.Flags(), p.PayloadLen(), h[:8])
	case p.IsUDP():
		return fmt.Sprintf("udp/%d/%x", p.PayloadLen(), h[:8])
	case p.IsICMP():
		req, id, seq, ok := p.ICMPEcho()
		return fmt.Sprintf("icmp/%t/%d/%d/%t/%x", req, id, seq, ok, h[:8])
	default:
		h := sha256.Sum256(frame[p.L3Offset():])
		return fmt.Sprintf("ip/%d/%x", p.Proto(), h[:12])
	}
}

func rewriteScheduled(sf ScheduledFrame, session *replay.Session, topology Topology, c *collector, adaptive bool) ([]byte, error) {
	frame := append([]byte(nil), sf.Data...)
	if session == nil {
		return applySideLink(frame, sf.LinkType, sideFor(topology, sf.Side))
	}
	client, ok := topology.Map("client", session.Client)
	if !ok {
		return nil, fmt.Errorf("lab: no client mapping for %s", session.ID)
	}
	server, ok := topology.Map("server", session.Server)
	if !ok {
		return nil, fmt.Errorf("lab: no server mapping for %s", session.ID)
	}
	if adaptive && sf.Direction == replay.ServerToClient {
		if learned, ok := c.learnedTuple(session.ID); ok {
			server, client = learned.dst, learned.src
		}
	}
	frame, err := applySideLink(frame, sf.LinkType, sideFor(topology, sf.Side))
	if err != nil {
		return nil, err
	}
	p, err := wire.Parse(frame, sf.LinkType)
	if err != nil {
		return nil, fmt.Errorf("lab: parse session %s packet %d: %w", session.ID, sf.PacketIndex, err)
	}
	var source, destination replay.Endpoint
	if sf.Direction == replay.ServerToClient {
		source, destination = server, client
	} else {
		source, destination = client, server
	}
	if p.IsFragment() {
		if !p.RewriteFragmentTuple(source.IP, destination.IP, source.Port, destination.Port) {
			return nil, fmt.Errorf("lab: cannot safely retarget fragmented protocol %d for session %s packet %d", p.Proto(), session.ID, sf.PacketIndex)
		}
		return p.Buf, nil
	}
	if !p.SetSrcIP(source.IP) || !p.SetDstIP(destination.IP) {
		return nil, fmt.Errorf("lab: address family mismatch while retargeting session %s packet %d", session.ID, sf.PacketIndex)
	}
	p.SetSrcPort(source.Port)
	p.SetDstPort(destination.Port)
	if adaptive && p.IsTCP() && p.HasFlags(wire.FlagACK) {
		if delta, ok := c.peerTCPDelta(session.ID, sf.Direction); ok {
			p.SetAck(p.AckNum().AddDelta(delta))
			p.RewriteSACKEdges(func(edge uint32) uint32 { return edge + delta })
		}
	}
	p.RecalcChecksums()
	return p.Buf, nil
}

func sideFor(t Topology, side string) Side {
	if side == "server" {
		return t.Server
	}
	return t.Client
}

func applySideLink(frame []byte, link wire.LinkType, side Side) ([]byte, error) {
	if side.VLAN != 0 && link == wire.LinkEthernet {
		frame = wire.PushVLAN(wire.StripVLANs(frame), side.VLAN, 0)
	}
	p, err := wire.Parse(frame, link)
	if err != nil {
		// Raw lanes can contain ARP and other non-IP frames. MAC/VLAN edits above
		// remain valid, while IP edits are intentionally skipped.
		return frame, nil
	}
	if side.SourceMAC != "" {
		mac, _ := net.ParseMAC(side.SourceMAC)
		var m [6]byte
		copy(m[:], mac)
		p.SetSrcMAC(m)
	}
	if side.NextHopMAC != "" {
		mac, _ := net.ParseMAC(side.NextHopMAC)
		var m [6]byte
		copy(m[:], mac)
		p.SetDstMAC(m)
	}
	return p.Buf, nil
}

func finishResult(result *Result, c *collector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	result.Finished = time.Now()
	result.Evidence = append([]pcapio.Record(nil), c.evidence...)
	sort.SliceStable(result.Evidence, func(i, j int) bool { return result.Evidence[i].Time.Before(result.Evidence[j].Time) })
	result.Metrics.Injected = c.injected
	result.Metrics.Crossed = c.crossed
	result.Metrics.Lost = c.injected - c.crossed
	if result.Metrics.Lost < 0 {
		result.Metrics.Lost = 0
	}
	result.Metrics.Duplicates = c.duplicates
	result.Metrics.FirewallResets = c.resets
	result.Sessions = buildSessionVerdicts(c.trace, c.plan, c)
	result.AchievedFidelity = overallLabFidelity(result.RequestedFidelity, result.Sessions)
	for _, indexes := range c.observedIdxBySession {
		for i := 1; i < len(indexes); i++ {
			if indexes[i] < indexes[i-1] {
				result.Metrics.Reordered++
			}
		}
	}
	if len(c.latencies) > 0 {
		result.Metrics.MinOneWay = c.latencies[0]
		var total time.Duration
		for _, d := range c.latencies {
			if d < result.Metrics.MinOneWay {
				result.Metrics.MinOneWay = d
			}
			if d > result.Metrics.MaxOneWay {
				result.Metrics.MaxOneWay = d
			}
			total += d
		}
		result.Metrics.MeanOneWay = total / time.Duration(len(c.latencies))
	}
	if len(c.rtts) > 0 {
		result.Metrics.MinRTT = c.rtts[0]
		var total time.Duration
		for _, d := range c.rtts {
			if d < result.Metrics.MinRTT {
				result.Metrics.MinRTT = d
			}
			if d > result.Metrics.MaxRTT {
				result.Metrics.MaxRTT = d
			}
			total += d
		}
		result.Metrics.MeanRTT = total / time.Duration(len(c.rtts))
	}
	for _, n := range c.nat {
		result.NAT = append(result.NAT, n)
	}
	sort.Slice(result.NAT, func(i, j int) bool { return result.NAT[i].SessionID < result.NAT[j].SessionID })
	for sessionID, directions := range c.tcpDeltas {
		for direction, delta := range directions {
			if delta != 0 {
				result.TCPClocks = append(result.TCPClocks, TCPClockTransformation{SessionID: sessionID, Direction: direction.String(), Delta: delta})
			}
		}
	}
	sort.Slice(result.TCPClocks, func(i, j int) bool {
		if result.TCPClocks[i].SessionID != result.TCPClocks[j].SessionID {
			return result.TCPClocks[i].SessionID < result.TCPClocks[j].SessionID
		}
		return result.TCPClocks[i].Direction < result.TCPClocks[j].Direction
	})
	for _, err := range c.errors {
		result.Limitations = appendUniqueString(result.Limitations, "observer error: "+err)
	}
}

func buildSessionVerdicts(trace *replay.Trace, plan replay.ReplayPlan, evidence *collector) []SessionVerdict {
	var out []SessionVerdict
	captured := map[string]int{"raw-0": len(trace.Raw)}
	for _, session := range trace.Sessions {
		captured[session.ID] = len(session.Events)
	}
	for _, entry := range plan.Entries {
		verdict := SessionVerdict{
			SessionID: entry.SessionID, Transport: entry.Transport, Driver: entry.Driver,
			Requested: plan.Profile, Achieved: entry.Fidelity, Captured: captured[entry.SessionID],
			Injected: evidence.injectedBySession[entry.SessionID], Crossed: evidence.crossedBySession[entry.SessionID],
			Duplicates: evidence.duplicatesBySession[entry.SessionID], Timeouts: evidence.timeoutsBySession[entry.SessionID],
			OneWay: durationStats(evidence.latenciesBySession[entry.SessionID]), RTT: durationStats(evidence.rttsBySession[entry.SessionID]),
			Limitations: append(append([]string(nil), entry.Warnings...), entry.Blockers...),
		}
		verdict.Lost = verdict.Injected - verdict.Crossed
		if verdict.Lost < 0 {
			verdict.Lost = 0
		}
		for i := 1; i < len(evidence.observedIdxBySession[entry.SessionID]); i++ {
			indexes := evidence.observedIdxBySession[entry.SessionID]
			if indexes[i] < indexes[i-1] {
				verdict.Reordered++
			}
		}
		for packetIndex := range evidence.evidenceBySession[entry.SessionID] {
			verdict.Evidence = append(verdict.Evidence, packetIndex)
		}
		sort.Ints(verdict.Evidence)
		verdict.Completed = entry.Mode != replay.ModeBlocked && verdict.Lost == 0 && verdict.Timeouts == 0
		if verdict.Injected > verdict.Crossed {
			verdict.Limitations = append(verdict.Limitations, fmt.Sprintf("%d injected frame(s) did not cross the DUT", verdict.Injected-verdict.Crossed))
		}
		out = append(out, verdict)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out
}

func durationStats(values []time.Duration) *DurationStats {
	if len(values) == 0 {
		return nil
	}
	stats := &DurationStats{Min: values[0], Max: values[0]}
	var total time.Duration
	for _, value := range values {
		if value < stats.Min {
			stats.Min = value
		}
		if value > stats.Max {
			stats.Max = value
		}
		total += value
	}
	stats.Mean = total / time.Duration(len(values))
	return stats
}

func overallLabFidelity(requested replay.Profile, sessions []SessionVerdict) replay.Fidelity {
	if len(sessions) == 0 || requested == replay.ProfileWire {
		return replay.FidelityWire
	}
	for _, session := range sessions {
		if session.Achieved == replay.FidelityWire || session.Achieved == replay.FidelityBlocked {
			return replay.FidelityWire
		}
	}
	if requested == replay.ProfileTiming {
		return replay.FidelityTiming
	}
	return replay.FidelityTransport
}

func WriteEvidence(path string, result Result, topology Topology) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	links := [2]wire.LinkType{wire.LinkEthernet, wire.LinkEthernet}
	for _, rec := range result.Evidence {
		if rec.InterfaceID < 2 {
			links[rec.InterfaceID] = rec.LinkType
		}
	}
	w, err := pcapio.NewNgWriter(f, []pcapio.NgInterface{
		{Name: "client:" + topology.Client.Interface, LinkType: links[0]},
		{Name: "server:" + topology.Server.Interface, LinkType: links[1]},
	})
	if err != nil {
		return err
	}
	for i := range result.Evidence {
		if err := w.Write(&result.Evidence[i]); err != nil {
			return err
		}
	}
	return w.Flush()
}
