package session

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

var (
	t0   = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	ipA  = netip.MustParseAddr("10.0.0.5")
	ipB  = netip.MustParseAddr("10.0.0.6")
	ipR  = netip.MustParseAddr("10.0.0.66")
	ip6S = netip.MustParseAddr("fe80::bad")
	mac  = net.HardwareAddr{1, 2, 3, 4, 5, 6}
)

func query(src netip.Addr, proto decode.Protocol, name, qt string, at time.Time) decode.Event {
	return decode.Event{Time: at, SrcIP: src, DstIP: netip.MustParseAddr("224.0.0.252"), SrcMAC: mac, Protocol: proto, Kind: decode.KindQuery,
		Name: name, QueryType: qt, WPAD: decode.IsWPADName(name), Detail: "q"}
}

func response(src, dst netip.Addr, proto decode.Protocol, name string, at time.Time) decode.Event {
	return decode.Event{Time: at, SrcIP: src, DstIP: dst, Protocol: proto, Kind: decode.KindResponse,
		Name: name, QueryType: "A", Answers: []netip.Addr{src}, WPAD: decode.IsWPADName(name), Detail: "r"}
}

func newAgg() *Aggregator {
	return NewAggregator(Options{Now: func() time.Time { return t0 }})
}

func TestAggregatorDedupesAndCounts(t *testing.T) {
	a := newAgg()
	v0 := a.Version()
	a.Add(query(ipA, decode.ProtoLLMNR, "wpad", "A", t0))
	a.Add(query(ipA, decode.ProtoLLMNR, "wpad", "AAAA", t0.Add(5*time.Second)))
	a.Add(query(ipA, decode.ProtoLLMNR, "wpad", "A", t0.Add(-time.Second))) // out-of-order timestamp
	a.Add(query(ipA, decode.ProtoNBNS, "wpad<00>", "NB", t0))
	a.Add(query(ipB, decode.ProtoMDNS, "tv.local", "PTR", t0))
	a.NotePacket(false)
	a.NotePacket(true)

	s := a.Snapshot()
	if len(s.Entries) != 3 {
		t.Fatalf("entries = %d", len(s.Entries))
	}
	e := s.Entries[0] // 10.0.0.5 LLMNR sorts first
	if e.SrcIP != ipA || e.Protocol != decode.ProtoLLMNR || e.Count != 3 || !e.WPAD {
		t.Fatalf("entry0 = %+v", e)
	}
	if len(e.QueryTypes) != 2 || e.QueryTypes[0] != "A" || e.QueryTypes[1] != "AAAA" {
		t.Fatalf("query types = %v", e.QueryTypes)
	}
	if !e.FirstSeen.Equal(t0.Add(-time.Second)) || !e.LastSeen.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("first/last = %v/%v", e.FirstSeen, e.LastSeen)
	}
	if e.SrcMAC.String() != mac.String() {
		t.Fatal("mac not kept")
	}
	if s.Stats.Events != 5 || s.Stats.Packets != 2 || s.Stats.DecodeErrors != 1 || s.Stats.UniqueHosts != 2 || s.Stats.PerProtocol[decode.ProtoLLMNR] != 3 {
		t.Fatalf("stats = %+v", s.Stats)
	}
	if a.Version() <= v0 {
		t.Fatal("version must increase")
	}
	// Snapshot is a copy.
	s.Entries[0].QueryTypes[0] = "X"
	if a.Snapshot().Entries[0].QueryTypes[0] != "A" {
		t.Fatal("snapshot aliasing")
	}

	a.SetDropped("eth0", 7)
	a.SetDropped("eth1", 3)
	if a.Snapshot().Stats.Dropped != 10 {
		t.Fatal("dropped sum")
	}

	v1 := a.Version()
	a.Reset()
	if a.Version() <= v1 {
		t.Fatal("reset must bump version")
	}
	s = a.Snapshot()
	if len(s.Entries) != 0 || s.Stats.Events != 0 || s.Stats.Dropped != 0 || len(s.Alerts) != 0 {
		t.Fatalf("reset left state: %+v", s)
	}
}

func TestAggregatorConcurrent(t *testing.T) {
	a := newAgg()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				a.Add(query(ipA, decode.ProtoLLMNR, "host"+string(rune('a'+g)), "A", t0))
				if i%50 == 0 {
					_ = a.Snapshot()
				}
			}
		}(g)
	}
	wg.Wait()
	s := a.Snapshot()
	if len(s.Entries) != 8 || s.Stats.Events != 1600 {
		t.Fatalf("entries=%d events=%d", len(s.Entries), s.Stats.Events)
	}
}

func TestRunRoundTrip(t *testing.T) {
	a := newAgg()
	a.Add(query(ipA, decode.ProtoLLMNR, "wpad", "A", t0))
	a.Add(response(ipR, ipA, decode.ProtoLLMNR, "wpad", t0))
	snap := a.Snapshot()
	r := snap.ToRun(run.ToolInfo{Name: "t", Version: "v"}, run.CaptureInfo{Interfaces: []string{"eth0"}, StartedAt: t0, EndedAt: t0.Add(time.Minute)})
	if len(r.Entries) != 2 || len(r.Alerts) != 1 || r.Capture.EventsSeen != 2 || r.Entries[1].Answers[0] != "10.0.0.66" {
		t.Fatalf("run = %+v", r)
	}
	back := FromRun(r)
	if len(back.Entries) != 2 || back.Entries[1].Answers[0] != ipR || back.Stats.UniqueHosts != 2 || len(back.Alerts) != 1 {
		t.Fatalf("from run = %+v", back)
	}
}

// --- alert rules ---

func alertsByRule(a *Aggregator) map[string]run.Alert {
	m := map[string]run.Alert{}
	for _, al := range a.Snapshot().Alerts {
		m[al.Rule+"|"+al.SourceIP] = al
	}
	return m
}

func TestResponderRuleWPAD(t *testing.T) {
	a := newAgg()
	a.Add(query(ipA, decode.ProtoLLMNR, "wpad", "A", t0))
	a.Add(response(ipR, ipA, decode.ProtoLLMNR, "wpad", t0.Add(time.Millisecond)))
	al, ok := alertsByRule(a)[RuleResponder+"|10.0.0.66"]
	if !ok || al.Severity != run.SeverityHigh || al.Count != 1 || al.Names[0] != "wpad" {
		t.Fatalf("alert = %+v ok=%v", al, ok)
	}
}

func TestResponderRuleManyNames(t *testing.T) {
	a := newAgg()
	for i, n := range []string{"srv1", "srv2"} {
		a.Add(query(ipA, decode.ProtoLLMNR, n, "A", t0))
		a.Add(response(ipR, ipA, decode.ProtoLLMNR, n, t0.Add(time.Duration(i)*time.Second)))
	}
	if _, ok := alertsByRule(a)[RuleResponder+"|10.0.0.66"]; ok {
		t.Fatal("two queried names should not alert yet")
	}
	a.Add(query(ipA, decode.ProtoNBNS, "srv3<20>", "NB", t0))
	a.Add(response(ipR, ipA, decode.ProtoNBNS, "srv3<20>", t0.Add(2*time.Second)))
	al, ok := alertsByRule(a)[RuleResponder+"|10.0.0.66"]
	if !ok || al.Severity != run.SeverityHigh {
		t.Fatalf("third name across LLMNR+NBNS must raise high: %+v", al)
	}
	if len(al.Names) != 1 || al.Names[0] != "srv3<20>" {
		t.Fatalf("names = %v", al.Names)
	}
}

func TestResponderRuleWindowExpires(t *testing.T) {
	a := newAgg()
	for i, n := range []string{"a", "b", "c"} {
		a.Add(query(ipA, decode.ProtoLLMNR, n, "A", t0))
		// 11 minutes apart: never 3 within the 10 minute window.
		a.Add(response(ipR, ipA, decode.ProtoLLMNR, n, t0.Add(time.Duration(i)*11*time.Minute)))
	}
	if _, ok := alertsByRule(a)[RuleResponder+"|10.0.0.66"]; ok {
		t.Fatal("names outside the window must not alert")
	}
}

func TestResponderRuleUnqueriedName(t *testing.T) {
	a := newAgg()
	a.Add(response(ipR, ipA, decode.ProtoNBNS, "fileserver<20>", t0))
	al, ok := alertsByRule(a)[RuleResponder+"|10.0.0.66"]
	if !ok || al.Severity != run.SeverityMedium {
		t.Fatalf("unqueried answer should be medium: %+v", al)
	}
}

func TestLegitimateSingleResponderNoAlert(t *testing.T) {
	a := newAgg()
	a.Add(query(ipA, decode.ProtoLLMNR, "printer", "A", t0))
	a.Add(response(ipB, ipA, decode.ProtoLLMNR, "printer", t0.Add(time.Millisecond)))
	a.Add(response(ipB, ipA, decode.ProtoLLMNR, "printer", t0.Add(time.Second)))
	if len(a.Snapshot().Alerts) != 0 {
		t.Fatalf("a host answering for its own queried name is normal: %+v", a.Snapshot().Alerts)
	}
}

func TestMDNSResponderRule(t *testing.T) {
	a := newAgg()
	for i := 0; i < 4; i++ {
		a.Add(response(ipB, netip.MustParseAddr("224.0.0.251"), decode.ProtoMDNS, "dev"+string(rune('0'+i))+".local", t0))
	}
	if len(a.Snapshot().Alerts) != 0 {
		t.Fatal("4 names under limit")
	}
	a.Add(response(ipB, netip.MustParseAddr("224.0.0.251"), decode.ProtoMDNS, "dev9.local", t0))
	al, ok := alertsByRule(a)[RuleMDNSResponder+"|10.0.0.6"]
	if !ok || al.Severity != run.SeverityLow {
		t.Fatalf("expected low mdns alert: %+v", al)
	}
	a.Add(response(ipB, netip.MustParseAddr("224.0.0.251"), decode.ProtoMDNS, "wpad.local", t0))
	if alertsByRule(a)[RuleMDNSResponder+"|10.0.0.6"].Severity != run.SeverityMedium {
		t.Fatal("wpad over mdns must escalate to medium")
	}
}

func TestDHCPv6ServerRule(t *testing.T) {
	adv := decode.Event{Time: t0, SrcIP: ip6S, DstIP: netip.MustParseAddr("fe80::1"), Protocol: decode.ProtoDHCPv6, Kind: decode.KindResponse, Name: "(advertise)", QueryType: "Advertise", Detail: "dns=fe80::bad"}
	a := newAgg()
	a.Add(adv)
	a.Add(adv)
	al, ok := alertsByRule(a)[RuleDHCPv6Server+"|fe80::bad"]
	if !ok || al.Severity != run.SeverityHigh || al.Count != 2 {
		t.Fatalf("alert = %+v", al)
	}
	trusted := NewAggregator(Options{TrustedDHCPv6: []netip.Addr{ip6S}, Now: func() time.Time { return t0 }})
	trusted.Add(adv)
	if len(trusted.Snapshot().Alerts) != 0 {
		t.Fatal("trusted server must not alert")
	}
	// Client Solicit never alerts.
	a.Reset()
	a.Add(decode.Event{Time: t0, SrcIP: ip6S, Protocol: decode.ProtoDHCPv6, Kind: decode.KindQuery, Name: "(solicit)", QueryType: "Solicit"})
	if len(a.Snapshot().Alerts) != 0 {
		t.Fatal("solicit is a client message")
	}
}

func TestWPADServerRuleEscalates(t *testing.T) {
	get := decode.Event{Time: t0, SrcIP: ipA, DstIP: ipR, Protocol: decode.ProtoHTTP, Kind: decode.KindQuery, Name: "wpad/wpad.dat", QueryType: "GET", WPAD: true, Answers: []netip.Addr{ipR}}
	a := newAgg()
	a.Add(get)
	a.Add(get)
	al := alertsByRule(a)[RuleWPADServer+"|10.0.0.66"]
	if al.Severity != run.SeverityInfo || al.Count != 2 {
		t.Fatalf("plain wpad server should be info with count 2: %+v", al)
	}
	// Same host now answers a name lookup: escalate.
	a.Add(query(ipA, decode.ProtoLLMNR, "wpad", "A", t0))
	a.Add(response(ipR, ipA, decode.ProtoLLMNR, "wpad", t0))
	al = alertsByRule(a)[RuleWPADServer+"|10.0.0.66"]
	if al.Severity != run.SeverityHigh {
		t.Fatalf("expected escalation to high: %+v", al)
	}
	// Order reversed: responder first, then GET -> high immediately.
	b := newAgg()
	b.Add(response(ipR, ipA, decode.ProtoNBNS, "wpad<00>", t0))
	b.Add(get)
	if alertsByRule(b)[RuleWPADServer+"|10.0.0.66"].Severity != run.SeverityHigh {
		t.Fatal("responder then GET must be high")
	}
}
