package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
	"github.com/ZerkerEOD/heimdall-listener/pkg/session"
)

var t0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func entry(ip string, p decode.Protocol, k decode.Kind, name string, count uint64, last time.Duration) session.Entry {
	return session.Entry{Key: session.Key{SrcIP: netip.MustParseAddr(ip), Protocol: p, Kind: k, Name: name},
		WPAD: decode.IsWPADName(name), Count: count, FirstSeen: t0, LastSeen: t0.Add(last)}
}

func snap() session.Snapshot {
	return session.Snapshot{
		Entries: []session.Entry{
			entry("10.0.0.5", decode.ProtoLLMNR, decode.KindQuery, "wpad", 10, time.Minute),
			entry("10.0.0.5", decode.ProtoNBNS, decode.KindQuery, "nas<20>", 3, 3*time.Minute),
			entry("10.0.0.20", decode.ProtoMDNS, decode.KindQuery, "tv.local", 50, 2*time.Minute),
			entry("10.0.0.66", decode.ProtoLLMNR, decode.KindResponse, "wpad", 7, 4*time.Minute),
		},
		Alerts: []run.Alert{{ID: "r|10.0.0.66", Rule: "llmnr-nbns-responder", SourceIP: "10.0.0.66", Severity: run.SeverityHigh}},
		Stats:  session.Stats{Events: 70},
	}
}

func names(m *model) []string {
	var out []string
	for i := range m.rows {
		out = append(out, m.cellText(i, colIP)+"/"+m.cellText(i, colName))
	}
	return out
}

func TestModelDefaultSortLastSeenDesc(t *testing.T) {
	m := newModel()
	m.setSnapshot(snap())
	got := names(m)
	want := []string{"10.0.0.66/wpad", "10.0.0.5/nas<20>", "10.0.0.20/tv.local", "10.0.0.5/wpad"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rows = %v", got)
		}
	}
	if !m.dirty {
		t.Fatal("events present must mark dirty")
	}
	if m.headerText(colLast) != "Last seen ▼" || m.headerText(colIP) != "Source IP" {
		t.Fatalf("headers: %q %q", m.headerText(colLast), m.headerText(colIP))
	}
}

func TestModelFilterAndSearch(t *testing.T) {
	m := newModel()
	m.setSnapshot(snap())
	m.setFilter(filterWPAD, "")
	if len(m.rows) != 2 {
		t.Fatalf("wpad rows = %v", names(m))
	}
	m.setFilter(string(decode.ProtoMDNS), "")
	if len(m.rows) != 1 || m.rows[0].Name != "tv.local" {
		t.Fatalf("mdns rows = %v", names(m))
	}
	m.setFilter(filterAlerts, "")
	if len(m.rows) != 1 || m.rows[0].SrcIP.String() != "10.0.0.66" {
		t.Fatalf("alert rows = %v", names(m))
	}
	m.setFilter(filterAll, " NAS ")
	if len(m.rows) != 1 || m.rows[0].Name != "nas<20>" {
		t.Fatalf("search rows = %v", names(m))
	}
	m.setFilter(filterAll, "10.0.0.5")
	if len(m.rows) != 2 {
		t.Fatalf("ip search rows = %v", names(m))
	}
}

func TestModelSortToggleAndSelection(t *testing.T) {
	m := newModel()
	m.setSnapshot(snap())
	m.toggleSort(colCount) // first click on count: descending
	if m.sortAsc || m.rows[0].Count != 50 {
		t.Fatalf("count desc: %v", names(m))
	}
	m.toggleSort(colCount)
	if !m.sortAsc || m.rows[0].Count != 3 {
		t.Fatalf("count asc: %v", names(m))
	}
	m.selectRow(0) // nas<20>
	m.toggleSort(colIP)
	if e, ok := m.selectedEntry(); !ok || e.Name != "nas<20>" {
		t.Fatalf("selection lost across sort: %+v %v", e, ok)
	}
	if m.selectedRow() != 1 {
		t.Fatalf("selected row = %d (%v)", m.selectedRow(), names(m))
	}
	m.setFilter(string(decode.ProtoMDNS), "")
	if _, ok := m.selectedEntry(); ok {
		t.Fatal("selection must clear when filtered out")
	}
	m.selectRow(99)
	if m.selected != nil {
		t.Fatal("out of range select")
	}
}

func TestModelExports(t *testing.T) {
	m := newModel()
	m.setSnapshot(snap())
	m.setFilter(filterWPAD, "")
	tool := run.ToolInfo{Name: "gui", Version: "t"}
	vis := m.visibleRun(tool, run.CaptureInfo{})
	all := m.allRun(tool, run.CaptureInfo{})
	if len(vis.Entries) != 2 || len(all.Entries) != 4 || len(vis.Alerts) != 1 {
		t.Fatalf("visible=%d all=%d", len(vis.Entries), len(all.Entries))
	}
	if formatCount(1234567) != "1,234,567" || formatCount(0) != "0" || formatCount(999) != "999" {
		t.Fatal("formatCount")
	}
	if len(filterOptions()) != 3+len(decode.AllProtocols()) {
		t.Fatal("filter options")
	}
}
