// Package session aggregates decoded events into deduplicated entries and
// passive alerts, and runs the capture loop that feeds them.
package session

import (
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// Key identifies an aggregated entry.
type Key struct {
	SrcIP    netip.Addr
	Protocol decode.Protocol
	Kind     decode.Kind
	Name     string
}

// Entry is the aggregate of all events sharing a Key.
type Entry struct {
	Key
	SrcMAC     net.HardwareAddr
	WPAD       bool
	QueryTypes []string
	Answers    []netip.Addr
	Count      uint64
	FirstSeen  time.Time
	LastSeen   time.Time
	LastDetail string
}

const maxAnswersPerEntry = 32

// Stats are counters for the whole aggregation.
type Stats struct {
	Packets      uint64
	Events       uint64
	DecodeErrors uint64
	Dropped      uint64
	UniqueHosts  int
	PerProtocol  map[decode.Protocol]uint64
	StartedAt    time.Time
}

// Snapshot is an immutable copy of the aggregator state.
type Snapshot struct {
	Entries []Entry
	Alerts  []run.Alert
	Stats   Stats
	Version uint64
	TakenAt time.Time
}

// Options tune aggregation and alerting.
type Options struct {
	// TrustedDHCPv6 lists legitimate DHCPv6 server addresses that must not
	// raise alerts.
	TrustedDHCPv6 []netip.Addr
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Aggregator is safe for concurrent use. Several capture sessions may feed
// one Aggregator (multi-interface capture).
type Aggregator struct {
	mu      sync.Mutex
	opts    Options
	entries map[Key]*Entry
	hosts   map[netip.Addr]struct{}
	stats   Stats
	dropped map[string]uint64
	alerts  *alertState
	version atomic.Uint64
}

// NewAggregator creates an empty aggregator.
func NewAggregator(opts Options) *Aggregator {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	a := &Aggregator{opts: opts}
	a.resetLocked()
	return a
}

func (a *Aggregator) resetLocked() {
	a.entries = map[Key]*Entry{}
	a.hosts = map[netip.Addr]struct{}{}
	a.dropped = map[string]uint64{}
	a.stats = Stats{PerProtocol: map[decode.Protocol]uint64{}, StartedAt: a.opts.Now()}
	a.alerts = newAlertState(a.opts.TrustedDHCPv6)
	a.version.Add(1)
}

// Reset discards all entries, alerts and counters and starts a new session.
func (a *Aggregator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resetLocked()
}

// Version increments on every change; cheap to poll.
func (a *Aggregator) Version() uint64 { return a.version.Load() }

// StartedAt returns when the current session began.
func (a *Aggregator) StartedAt() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stats.StartedAt
}

// NotePacket counts a captured frame (and optionally a decode failure).
func (a *Aggregator) NotePacket(decodeErr bool) {
	a.mu.Lock()
	a.stats.Packets++
	if decodeErr {
		a.stats.DecodeErrors++
	}
	a.mu.Unlock()
	// Packet counters alone do not bump the version: the UI refreshes on
	// entry/alert changes and reads counters when it does.
}

// SetDropped records the kernel drop counter for one interface.
func (a *Aggregator) SetDropped(iface string, n uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dropped[iface] != n {
		a.dropped[iface] = n
		a.version.Add(1)
	}
}

// Add folds one event into the aggregate and evaluates alert rules.
func (a *Aggregator) Add(ev decode.Event) {
	if !ev.SrcIP.IsValid() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	k := Key{SrcIP: ev.SrcIP, Protocol: ev.Protocol, Kind: ev.Kind, Name: ev.Name}
	e, ok := a.entries[k]
	if !ok {
		e = &Entry{Key: k, FirstSeen: ev.Time, WPAD: ev.WPAD}
		a.entries[k] = e
		a.hosts[ev.SrcIP] = struct{}{}
	}
	e.Count++
	if ev.Time.After(e.LastSeen) {
		e.LastSeen = ev.Time
	}
	if ev.Time.Before(e.FirstSeen) {
		e.FirstSeen = ev.Time
	}
	if len(ev.SrcMAC) > 0 {
		e.SrcMAC = ev.SrcMAC
	}
	e.WPAD = e.WPAD || ev.WPAD
	if ev.QueryType != "" && !slices.Contains(e.QueryTypes, ev.QueryType) {
		e.QueryTypes = append(e.QueryTypes, ev.QueryType)
		sort.Strings(e.QueryTypes)
	}
	for _, ans := range ev.Answers {
		if len(e.Answers) >= maxAnswersPerEntry {
			break
		}
		if !slices.Contains(e.Answers, ans) {
			e.Answers = append(e.Answers, ans)
		}
	}
	if ev.Detail != "" {
		e.LastDetail = ev.Detail
	}

	a.stats.Events++
	a.stats.PerProtocol[ev.Protocol]++
	a.alerts.observe(ev)
	a.version.Add(1)
}

// Snapshot copies the current state.
func (a *Aggregator) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Version: a.version.Load(), TakenAt: a.opts.Now()}
	s.Entries = make([]Entry, 0, len(a.entries))
	for _, e := range a.entries {
		c := *e
		c.QueryTypes = slices.Clone(e.QueryTypes)
		c.Answers = slices.Clone(e.Answers)
		s.Entries = append(s.Entries, c)
	}
	sort.Slice(s.Entries, func(i, j int) bool { return lessEntry(s.Entries[i], s.Entries[j]) })
	s.Alerts = a.alerts.list()
	st := a.stats
	st.PerProtocol = make(map[decode.Protocol]uint64, len(a.stats.PerProtocol))
	for k, v := range a.stats.PerProtocol {
		st.PerProtocol[k] = v
	}
	st.UniqueHosts = len(a.hosts)
	st.Dropped = 0
	for _, d := range a.dropped {
		st.Dropped += d
	}
	s.Stats = st
	return s
}

func lessEntry(a, b Entry) bool {
	if c := a.SrcIP.Compare(b.SrcIP); c != 0 {
		return c < 0
	}
	if a.Protocol != b.Protocol {
		return a.Protocol < b.Protocol
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Name < b.Name
}

// ToRun converts an entry to its file representation.
func (e Entry) ToRun() run.Entry {
	re := run.Entry{
		SourceIP: e.SrcIP.String(), Protocol: e.Protocol, Kind: e.Kind, Name: e.Name, WPAD: e.WPAD,
		QueryTypes: slices.Clone(e.QueryTypes), Count: e.Count, FirstSeen: e.FirstSeen.UTC(), LastSeen: e.LastSeen.UTC(), LastDetail: e.LastDetail,
	}
	if len(e.SrcMAC) > 0 {
		re.SourceMAC = e.SrcMAC.String()
	}
	for _, a := range e.Answers {
		re.Answers = append(re.Answers, a.String())
	}
	return re
}

// ToRun builds a run file from the snapshot.
func (s Snapshot) ToRun(tool run.ToolInfo, capInfo run.CaptureInfo) *run.Run {
	r := run.New(tool)
	capInfo.PacketsSeen = s.Stats.Packets
	capInfo.EventsSeen = s.Stats.Events
	capInfo.DecodeErrors = s.Stats.DecodeErrors
	capInfo.Dropped = s.Stats.Dropped
	if capInfo.StartedAt.IsZero() {
		capInfo.StartedAt = s.Stats.StartedAt
	}
	if capInfo.EndedAt.IsZero() {
		capInfo.EndedAt = s.TakenAt
	}
	capInfo.StartedAt = capInfo.StartedAt.UTC()
	capInfo.EndedAt = capInfo.EndedAt.UTC()
	r.Capture = capInfo
	r.Entries = make([]run.Entry, 0, len(s.Entries))
	for _, e := range s.Entries {
		r.Entries = append(r.Entries, e.ToRun())
	}
	r.Alerts = slices.Clone(s.Alerts)
	r.Sort()
	return r
}

// FromRun loads a saved run into a snapshot (read-only viewing in the GUI).
func FromRun(r *run.Run) Snapshot {
	s := Snapshot{TakenAt: r.Capture.EndedAt, Alerts: slices.Clone(r.Alerts)}
	s.Stats = Stats{Packets: r.Capture.PacketsSeen, Events: r.Capture.EventsSeen, DecodeErrors: r.Capture.DecodeErrors,
		Dropped: r.Capture.Dropped, StartedAt: r.Capture.StartedAt, PerProtocol: map[decode.Protocol]uint64{}}
	hosts := map[string]struct{}{}
	for _, re := range r.Entries {
		ip, _ := netip.ParseAddr(re.SourceIP)
		e := Entry{Key: Key{SrcIP: ip, Protocol: re.Protocol, Kind: re.Kind, Name: re.Name}, WPAD: re.WPAD,
			QueryTypes: slices.Clone(re.QueryTypes), Count: re.Count, FirstSeen: re.FirstSeen, LastSeen: re.LastSeen, LastDetail: re.LastDetail}
		if re.SourceMAC != "" {
			e.SrcMAC, _ = net.ParseMAC(re.SourceMAC)
		}
		for _, a := range re.Answers {
			if ad, err := netip.ParseAddr(a); err == nil {
				e.Answers = append(e.Answers, ad)
			}
		}
		s.Entries = append(s.Entries, e)
		s.Stats.PerProtocol[re.Protocol] += re.Count
		hosts[re.SourceIP] = struct{}{}
	}
	s.Stats.UniqueHosts = len(hosts)
	sort.Slice(s.Entries, func(i, j int) bool { return lessEntry(s.Entries[i], s.Entries[j]) })
	return s
}
