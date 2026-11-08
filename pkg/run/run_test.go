package run

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
)

var t0 = time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)

func sample() *Run {
	r := New(ToolInfo{Name: "heimdall", Version: "test"})
	r.Capture = CaptureInfo{Interfaces: []string{"eth0"}, Backend: "test", StartedAt: t0, EndedAt: t0.Add(time.Minute)}
	r.Entries = []Entry{
		{SourceIP: "10.0.0.20", Protocol: decode.ProtoNBNS, Kind: decode.KindQuery, Name: "filesrv<20>", Count: 3, FirstSeen: t0, LastSeen: t0},
		{SourceIP: "10.0.0.5", Protocol: decode.ProtoLLMNR, Kind: decode.KindQuery, Name: "wpad", WPAD: true, Count: 10, FirstSeen: t0, LastSeen: t0, QueryTypes: []string{"A", "AAAA"}},
		{SourceIP: "fe80::1", Protocol: decode.ProtoDHCPv6, Kind: decode.KindQuery, Name: "(solicit)", Count: 1, FirstSeen: t0, LastSeen: t0},
		{SourceIP: "10.0.0.5", Protocol: decode.ProtoLLMNR, Kind: decode.KindQuery, Name: "printer", Count: 2, FirstSeen: t0, LastSeen: t0},
	}
	r.Alerts = []Alert{{ID: "llmnr-nbns-responder|10.0.0.66", Rule: "llmnr-nbns-responder", Severity: SeverityHigh, SourceIP: "10.0.0.66", Title: "x", Count: 4, FirstSeen: t0, LastSeen: t0}}
	return r
}

func TestWriteSortsDeterministically(t *testing.T) {
	r := sample()
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	if r.Entries[0].SourceIP != "10.0.0.5" || r.Entries[0].Name != "printer" || r.Entries[2].SourceIP != "10.0.0.20" || r.Entries[3].SourceIP != "fe80::1" {
		t.Fatalf("bad order: %+v", r.Entries)
	}
	var buf2 bytes.Buffer
	_ = Write(&buf2, sample())
	if buf.String() != buf2.String() {
		t.Fatal("output not deterministic")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")
	if err := Save(path, sample()); err != nil {
		t.Fatal(err)
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != SchemaVersion || len(got.Entries) != 4 || len(got.Alerts) != 1 || got.Capture.Interfaces[0] != "eth0" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if !got.Entries[1].WPAD || got.Entries[1].Count != 10 || len(got.Entries[1].QueryTypes) != 2 {
		t.Fatalf("entry mismatch: %+v", got.Entries[1])
	}
	// Overwrite works (rename over existing).
	if err := Save(path, sample()); err != nil {
		t.Fatal(err)
	}
}

func TestReadRejectsNewerSchemaAndGarbage(t *testing.T) {
	_, err := Read(strings.NewReader(`{"schema_version": 99, "entries": []}`))
	if !errors.Is(err, ErrSchema) {
		t.Fatalf("expected ErrSchema, got %v", err)
	}
	if _, err := Read(strings.NewReader(`{"foo": 1}`)); err == nil {
		t.Fatal("expected error for non-run JSON")
	}
	if _, err := Read(strings.NewReader(`not json`)); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestFilterAndHosts(t *testing.T) {
	r := sample()
	f := r.Filter(func(e Entry) bool { return e.WPAD })
	if len(f.Entries) != 1 || len(r.Entries) != 4 {
		t.Fatal("filter must copy")
	}
	hosts := r.Hosts()
	if len(hosts) != 3 || hosts[0] != "10.0.0.5" || hosts[1] != "10.0.0.20" || hosts[2] != "fe80::1" {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestCompareIP(t *testing.T) {
	if CompareIP("10.0.0.9", "10.0.0.10") >= 0 {
		t.Error("numeric order expected")
	}
	if CompareIP("10.0.0.1", "fe80::1") >= 0 {
		t.Error("v4 before v6")
	}
	if CompareIP("zzz", "10.0.0.1") <= 0 {
		t.Error("unparsable sorts last")
	}
}

func TestDiff(t *testing.T) {
	base := sample()
	cur := sample()
	// 10.0.0.5 stopped LLMNR for wpad but still asks for printer; a new host appeared
	// doing mDNS; fe80::1 host vanished; alert cleared and a new one raised.
	cur.Entries = []Entry{
		{SourceIP: "10.0.0.5", Protocol: decode.ProtoLLMNR, Kind: decode.KindQuery, Name: "printer", Count: 5},
		{SourceIP: "10.0.0.20", Protocol: decode.ProtoNBNS, Kind: decode.KindQuery, Name: "filesrv<20>", Count: 1},
		{SourceIP: "10.0.0.77", Protocol: decode.ProtoMDNS, Kind: decode.KindQuery, Name: "tv.local", Count: 9},
		{SourceIP: "10.0.0.20", Protocol: decode.ProtoLLMNR, Kind: decode.KindQuery, Name: "wpad", WPAD: true, Count: 1},
	}
	cur.Alerts = []Alert{{ID: "dhcpv6-server|fe80::bad", Rule: "dhcpv6-server", Severity: SeverityHigh, SourceIP: "fe80::bad"}}

	d := Diff(base, cur, "a.json", "b.json")
	if d.Baseline.Path != "a.json" || d.Current.Entries != 4 || d.Baseline.Hosts != 3 {
		t.Fatalf("refs: %+v %+v", d.Baseline, d.Current)
	}
	want := Summary{NewPairs: 2, ResolvedPairs: 1, UnchangedPairs: 2, NewHosts: 1, ResolvedHosts: 1, NewWPAD: 1, ResolvedWPAD: 0, NewAlerts: 1, ClearedAlerts: 1}
	if d.Summary != want {
		t.Fatalf("summary = %+v, want %+v", d.Summary, want)
	}
	// Pair order: 10.0.0.5 LLMNR, 10.0.0.20 LLMNR, 10.0.0.20 NetBIOS, 10.0.0.77 mDNS, fe80::1 DHCPv6
	if len(d.Pairs) != 5 || d.Pairs[0].SourceIP != "10.0.0.5" || d.Pairs[4].SourceIP != "fe80::1" {
		t.Fatalf("pairs: %+v", d.Pairs)
	}
	p0 := d.Pairs[0]
	if p0.Status != StatusUnchanged || len(p0.Names) != 2 || p0.Names[0].Name != "printer" || p0.Names[0].Status != StatusUnchanged || p0.Names[1].Name != "wpad" || p0.Names[1].Status != StatusResolved {
		t.Fatalf("pair0: %+v", p0)
	}
	if p0.BaselineCount != 12 || p0.CurrentCount != 5 || !p0.WPAD {
		t.Fatalf("pair0 counts: %+v", p0)
	}
	if d.Pairs[1].Status != StatusNew || d.Pairs[1].HostNew {
		t.Fatalf("pair1 should be new pair on existing host: %+v", d.Pairs[1])
	}
	if d.Pairs[3].Status != StatusNew || !d.Pairs[3].HostNew {
		t.Fatalf("pair3 should be a new host: %+v", d.Pairs[3])
	}
	if d.Pairs[4].Status != StatusResolved || !d.Pairs[4].HostResolved {
		t.Fatalf("pair4 should be a resolved host: %+v", d.Pairs[4])
	}
	if len(d.ByStatus(StatusResolved)) != 1 || len(d.Alerts) != 2 {
		t.Fatal("ByStatus / alerts")
	}

	// Identical runs: everything unchanged.
	same := Diff(base, sample(), "", "")
	if same.Summary.NewPairs+same.Summary.ResolvedPairs+same.Summary.NewAlerts+same.Summary.ClearedAlerts != 0 || same.Summary.UnchangedPairs != 3 {
		t.Fatalf("identical diff: %+v", same.Summary)
	}
	// Empty runs.
	empty := Diff(New(ToolInfo{}), New(ToolInfo{}), "", "")
	if len(empty.Pairs) != 0 || empty.Summary != (Summary{}) {
		t.Fatal("empty diff")
	}
}
