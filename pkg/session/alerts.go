package session

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// Alert rule identifiers. All rules are passive: they only look at frames
// the capture received and never cause any packet to be sent.
const (
	RuleResponder     = "llmnr-nbns-responder"
	RuleMDNSResponder = "mdns-responder"
	RuleDHCPv6Server  = "dhcpv6-server"
	RuleWPADServer    = "wpad-http-server"
)

const (
	responderWindow     = 10 * time.Minute
	responderNameLimit  = 3 // distinct LLMNR/NBNS names answered within the window
	mdnsResponderLimit  = 5 // distinct mDNS A/AAAA names answered within the window
	maxAlertNamesStored = 50
	maxQueriedNames     = 20000 // bounded set of names seen queried
	maxResponderNames   = 2000  // per responding host
	maxResponders       = 5000  // responding hosts tracked
)

type responder struct {
	names map[string]time.Time // name -> last answered
	wpad  bool
}

type alertState struct {
	trusted    map[netip.Addr]struct{}
	queried    map[string]struct{} // LLMNR/NBNS names seen queried by anyone
	responders map[netip.Addr]*responder
	mdns       map[netip.Addr]*responder
	wpadSrv    map[netip.Addr]uint64 // hosts that served wpad.dat -> request count
	alerts     map[string]*run.Alert
}

func newAlertState(trusted []netip.Addr) *alertState {
	s := &alertState{
		trusted:    map[netip.Addr]struct{}{},
		queried:    map[string]struct{}{},
		responders: map[netip.Addr]*responder{},
		mdns:       map[netip.Addr]*responder{},
		wpadSrv:    map[netip.Addr]uint64{},
		alerts:     map[string]*run.Alert{},
	}
	for _, t := range trusted {
		s.trusted[t] = struct{}{}
	}
	return s
}

func (s *alertState) list() []run.Alert {
	out := make([]run.Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		c := *a
		c.Names = slices.Clone(a.Names)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if c := run.CompareIP(a.SourceIP, b.SourceIP); c != 0 {
			return c < 0
		}
		return a.Rule < b.Rule
	})
	return out
}

// raise creates or updates an alert. Severity only ever escalates.
func (s *alertState) raise(rule string, ip netip.Addr, proto decode.Protocol, sev run.Severity, title, evidence string, name string, ts time.Time) {
	id := rule + "|" + ip.String()
	a, ok := s.alerts[id]
	if !ok {
		a = &run.Alert{ID: id, Rule: rule, SourceIP: ip.String(), Protocol: proto, FirstSeen: ts, Severity: sev}
		s.alerts[id] = a
	}
	a.Count++
	if ts.After(a.LastSeen) {
		a.LastSeen = ts
	}
	if ts.Before(a.FirstSeen) || a.FirstSeen.IsZero() {
		a.FirstSeen = ts
	}
	if sev.Rank() < a.Severity.Rank() {
		a.Severity = sev
	}
	a.Title = title
	a.Evidence = evidence
	if name != "" && !slices.Contains(a.Names, name) && len(a.Names) < maxAlertNamesStored {
		a.Names = append(a.Names, name)
		sort.Strings(a.Names)
	}
}

func recentNames(r *responder, now time.Time) int {
	n := 0
	for _, t := range r.names {
		if now.Sub(t) <= responderWindow {
			n++
		}
	}
	return n
}

// observe runs every rule against one event.
func (s *alertState) observe(ev decode.Event) {
	switch ev.Protocol {
	case decode.ProtoLLMNR, decode.ProtoNBNS:
		if ev.Kind == decode.KindQuery {
			if len(s.queried) >= maxQueriedNames {
				// Keep the set bounded; losing history only makes the
				// "nobody asked" rule more cautious, never less.
				s.queried = map[string]struct{}{}
			}
			s.queried[ev.Name] = struct{}{}
			return
		}
		s.observeResponder(ev)
	case decode.ProtoMDNS:
		if ev.Kind == decode.KindResponse {
			s.observeMDNS(ev)
		}
	case decode.ProtoDHCPv6:
		if ev.Kind == decode.KindResponse {
			s.observeDHCPv6Server(ev)
		}
	case decode.ProtoHTTP:
		if ev.WPAD && len(ev.Answers) > 0 {
			s.observeWPADServer(ev)
		}
	}
}

// track returns the responder record for ip in m, creating it within the
// configured bounds, and records name at ts.
func track(m map[netip.Addr]*responder, ip netip.Addr, name string, ts time.Time) *responder {
	r := m[ip]
	if r == nil {
		if len(m) >= maxResponders {
			return nil
		}
		r = &responder{names: map[string]time.Time{}}
		m[ip] = r
	}
	if _, known := r.names[name]; !known && len(r.names) >= maxResponderNames {
		// Evict the oldest name so the window logic keeps working.
		var oldest string
		var oldestT time.Time
		for n, t := range r.names {
			if oldest == "" || t.Before(oldestT) {
				oldest, oldestT = n, t
			}
		}
		delete(r.names, oldest)
	}
	r.names[name] = ts
	return r
}

func (s *alertState) observeResponder(ev decode.Event) {
	r := track(s.responders, ev.SrcIP, ev.Name, ev.Time)
	if r == nil {
		return
	}
	distinct := recentNames(r, ev.Time)
	_, wasQueried := s.queried[ev.Name]

	switch {
	case ev.WPAD:
		r.wpad = true
		s.raise(RuleResponder, ev.SrcIP, ev.Protocol, run.SeverityHigh,
			"Answered a WPAD name lookup",
			fmt.Sprintf("%s answered %s for %q with %s. Legitimate WPAD is served by DNS, never by LLMNR/NetBIOS; this is the Responder/Inveigh WPAD attack.",
				ev.SrcIP, ev.Protocol, ev.Name, joinAddrs(ev.Answers)),
			ev.Name, ev.Time)
	case distinct >= responderNameLimit:
		s.raise(RuleResponder, ev.SrcIP, ev.Protocol, run.SeverityHigh,
			"Answers name lookups for many different names",
			fmt.Sprintf("%s answered %s for %d distinct names within %s (%s). A real host answers only for its own name; poisoners answer everything.",
				ev.SrcIP, ev.Protocol, distinct, responderWindow, previewNames(r)),
			ev.Name, ev.Time)
	case !wasQueried:
		s.raise(RuleResponder, ev.SrcIP, ev.Protocol, run.SeverityMedium,
			"Answered a name nobody was seen asking for",
			fmt.Sprintf("%s answered %s for %q with %s but no matching query was captured. Possible unicast poisoning or capture started mid-exchange; verify the host.",
				ev.SrcIP, ev.Protocol, ev.Name, joinAddrs(ev.Answers)),
			ev.Name, ev.Time)
	default:
		// A single, queried name answered: normal LLMNR/NBNS behaviour.
		// Still remember the host for WPAD-server correlation.
	}
	s.reevaluateWPADServer(ev.SrcIP, ev.Time)
}

func (s *alertState) observeMDNS(ev decode.Event) {
	r := track(s.mdns, ev.SrcIP, ev.Name, ev.Time)
	if r == nil {
		return
	}
	distinct := recentNames(r, ev.Time)
	switch {
	case ev.WPAD:
		r.wpad = true
		s.raise(RuleMDNSResponder, ev.SrcIP, ev.Protocol, run.SeverityMedium,
			"Answered a WPAD name over mDNS",
			fmt.Sprintf("%s answered mDNS for %q with %s.", ev.SrcIP, ev.Name, joinAddrs(ev.Answers)),
			ev.Name, ev.Time)
	case distinct >= mdnsResponderLimit:
		s.raise(RuleMDNSResponder, ev.SrcIP, ev.Protocol, run.SeverityLow,
			"Answers mDNS for many different names",
			fmt.Sprintf("%s answered mDNS A/AAAA for %d distinct names within %s (%s). Bonjour gateways and some printers do this legitimately; a poisoner does too.",
				ev.SrcIP, distinct, responderWindow, previewNames(r)),
			ev.Name, ev.Time)
	}
	s.reevaluateWPADServer(ev.SrcIP, ev.Time)
}

func (s *alertState) observeDHCPv6Server(ev decode.Event) {
	if _, ok := s.trusted[ev.SrcIP]; ok {
		return
	}
	s.raise(RuleDHCPv6Server, ev.SrcIP, ev.Protocol, run.SeverityHigh,
		"Acting as a DHCPv6 server",
		fmt.Sprintf("%s sent DHCPv6 %s to %s (%s). On IPv4-only networks no host should answer DHCPv6; mitm6 does exactly this to become the victims' DNS server. If this is your real DHCPv6 server, add it with --trusted-dhcpv6.",
			ev.SrcIP, ev.QueryType, ev.DstIP, ev.Detail),
		ev.Name, ev.Time)
}

func (s *alertState) observeWPADServer(ev decode.Event) {
	srv := ev.Answers[0]
	if _, known := s.wpadSrv[srv]; !known && len(s.wpadSrv) >= maxResponders {
		return
	}
	s.wpadSrv[srv]++
	s.reevaluateWPADServer(srv, ev.Time)
}

// reevaluateWPADServer raises or escalates the wpad-http-server alert for
// ip: info when a host merely serves wpad.dat, high when that same host was
// also seen answering name lookups (classic Responder flow).
func (s *alertState) reevaluateWPADServer(ip netip.Addr, ts time.Time) {
	n, serves := s.wpadSrv[ip]
	if !serves {
		return
	}
	_, isResponder := s.responders[ip]
	_, isMDNS := s.mdns[ip]
	if isResponder || isMDNS {
		s.raise(RuleWPADServer, ip, decode.ProtoHTTP, run.SeverityHigh,
			"Serves wpad.dat and answers name lookups",
			fmt.Sprintf("%s received %d wpad.dat request(s) and also answered LLMNR/NetBIOS/mDNS lookups. This is the Responder WPAD credential-capture flow.", ip, n),
			"", ts)
		return
	}
	// Only count once per request for the info alert, keeping Count accurate.
	if a, ok := s.alerts[RuleWPADServer+"|"+ip.String()]; ok && a.Count >= n {
		a.LastSeen = ts
		return
	}
	s.raise(RuleWPADServer, ip, decode.ProtoHTTP, run.SeverityInfo,
		"Serves wpad.dat",
		fmt.Sprintf("%s received %d wpad.dat request(s). Confirm it is the sanctioned proxy auto-config server.", ip, n),
		"", ts)
}

func previewNames(r *responder) string {
	names := make([]string, 0, len(r.names))
	for n := range r.names {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(", +%d more", len(names)-5)
	}
	return strings.Join(names, ", ")
}

func joinAddrs(as []netip.Addr) string {
	if len(as) == 0 {
		return "(no address)"
	}
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}
