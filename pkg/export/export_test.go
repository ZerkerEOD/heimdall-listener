package export

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

var update = flag.Bool("update", false, "rewrite golden files")

var t0 = time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)

func baseline() *run.Run {
	r := run.New(run.ToolInfo{Name: "heimdall-cli", Version: "v2.0.0-test"})
	r.Host = run.HostInfo{Hostname: "sensor01", OS: "linux", Arch: "amd64"}
	r.Capture = run.CaptureInfo{Interfaces: []string{"eth0"}, Backend: "AF_PACKET (pure Go)", Filter: "test", Promiscuous: true,
		StartedAt: t0, EndedAt: t0.Add(30 * time.Minute), PacketsSeen: 1200, EventsSeen: 61, DecodeErrors: 1}
	r.Entries = []run.Entry{
		{SourceIP: "10.0.0.5", SourceMAC: "00:11:22:33:44:55", Protocol: decode.ProtoLLMNR, Kind: decode.KindQuery, Name: "wpad", WPAD: true, QueryTypes: []string{"A", "AAAA"}, Count: 40, FirstSeen: t0, LastSeen: t0.Add(29 * time.Minute), LastDetail: "LLMNR A query for \"wpad\""},
		{SourceIP: "10.0.0.5", SourceMAC: "00:11:22:33:44:55", Protocol: decode.ProtoNBNS, Kind: decode.KindQuery, Name: "wpad<00>", WPAD: true, QueryTypes: []string{"NB"}, Count: 12, FirstSeen: t0, LastSeen: t0.Add(29 * time.Minute)},
		{SourceIP: "10.0.0.5", SourceMAC: "00:11:22:33:44:55", Protocol: decode.ProtoLLMNR, Kind: decode.KindQuery, Name: "oldfileserver", QueryTypes: []string{"A"}, Count: 3, FirstSeen: t0.Add(time.Minute), LastSeen: t0.Add(2 * time.Minute)},
		{SourceIP: "10.0.0.20", Protocol: decode.ProtoMDNS, Kind: decode.KindQuery, Name: "_ipp._tcp.local", QueryTypes: []string{"PTR"}, Count: 5, FirstSeen: t0, LastSeen: t0.Add(10 * time.Minute)},
		{SourceIP: "fe80::1", Protocol: decode.ProtoDHCPv6, Kind: decode.KindQuery, Name: "desktop-7.corp.local", QueryTypes: []string{"Solicit"}, Count: 1, FirstSeen: t0.Add(5 * time.Minute), LastSeen: t0.Add(5 * time.Minute)},
	}
	return r
}

func current() *run.Run {
	r := baseline()
	r.Capture.StartedAt = t0.Add(24 * time.Hour)
	r.Capture.EndedAt = t0.Add(24*time.Hour + 30*time.Minute)
	// LLMNR disabled on 10.0.0.5 via GPO; NetBIOS still on. New host 10.0.0.9 appeared.
	// Responder-like host 10.0.0.66 answered wpad and served wpad.dat.
	r.Entries = []run.Entry{
		{SourceIP: "10.0.0.5", SourceMAC: "00:11:22:33:44:55", Protocol: decode.ProtoNBNS, Kind: decode.KindQuery, Name: "wpad<00>", WPAD: true, QueryTypes: []string{"NB"}, Count: 15, FirstSeen: t0.Add(24 * time.Hour), LastSeen: t0.Add(24*time.Hour + 29*time.Minute)},
		{SourceIP: "10.0.0.20", Protocol: decode.ProtoMDNS, Kind: decode.KindQuery, Name: "_ipp._tcp.local", QueryTypes: []string{"PTR"}, Count: 4, FirstSeen: t0.Add(24 * time.Hour), LastSeen: t0.Add(24 * time.Hour)},
		{SourceIP: "10.0.0.9", Protocol: decode.ProtoLLMNR, Kind: decode.KindQuery, Name: "nas", QueryTypes: []string{"A"}, Count: 2, FirstSeen: t0.Add(24 * time.Hour), LastSeen: t0.Add(24 * time.Hour)},
		{SourceIP: "10.0.0.66", Protocol: decode.ProtoNBNS, Kind: decode.KindResponse, Name: "wpad<00>", WPAD: true, QueryTypes: []string{"NB"}, Answers: []string{"10.0.0.66"}, Count: 15, FirstSeen: t0.Add(24 * time.Hour), LastSeen: t0.Add(24*time.Hour + 29*time.Minute)},
		{SourceIP: "10.0.0.5", SourceMAC: "00:11:22:33:44:55", Protocol: decode.ProtoHTTP, Kind: decode.KindQuery, Name: "wpad/wpad.dat", WPAD: true, QueryTypes: []string{"GET"}, Answers: []string{"10.0.0.66"}, Count: 15, FirstSeen: t0.Add(24 * time.Hour), LastSeen: t0.Add(24*time.Hour + 29*time.Minute)},
	}
	r.Alerts = []run.Alert{
		{ID: "llmnr-nbns-responder|10.0.0.66", Rule: "llmnr-nbns-responder", Severity: run.SeverityHigh, SourceIP: "10.0.0.66", Protocol: decode.ProtoNBNS, Title: "Answered a WPAD name lookup", Evidence: "10.0.0.66 answered NetBIOS for \"wpad<00>\" with 10.0.0.66.", Names: []string{"wpad<00>"}, FirstSeen: t0.Add(24 * time.Hour), LastSeen: t0.Add(24*time.Hour + 29*time.Minute), Count: 15},
		{ID: "wpad-http-server|10.0.0.66", Rule: "wpad-http-server", Severity: run.SeverityHigh, SourceIP: "10.0.0.66", Protocol: decode.ProtoHTTP, Title: "Serves wpad.dat and answers name lookups", Evidence: "10.0.0.66 received 15 wpad.dat request(s) and also answered lookups.", FirstSeen: t0.Add(24 * time.Hour), LastSeen: t0.Add(24*time.Hour + 29*time.Minute), Count: 15},
	}
	return r
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update): %v", path, err)
	}
	// Git may check goldens out with CRLF on Windows; compare line endings-agnostically.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from golden\n--- got ---\n%s", name, got)
	}
}

func TestWriteCSV(t *testing.T) {
	var b bytes.Buffer
	r := current()
	r.Sort()
	if err := WriteCSV(&b, r); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(b.String(), "\n"); lines != 6 {
		t.Fatalf("expected header + 5 rows, got %d lines", lines)
	}
	golden(t, "entries.csv", b.Bytes())
}

func TestSummarize(t *testing.T) {
	hosts := Summarize(current())
	if len(hosts) != 4 {
		t.Fatalf("hosts = %d", len(hosts))
	}
	if hosts[0].SourceIP != "10.0.0.66" || len(hosts[0].Alerts) != 2 || !hosts[0].Responder {
		t.Fatalf("alerting host must sort first: %+v", hosts[0])
	}
	if hosts[1].SourceIP != "10.0.0.5" || len(hosts[1].WPADNames) != 2 || hosts[1].Protocols[0] != decode.ProtoNBNS || hosts[1].Protocols[1] != decode.ProtoHTTP {
		t.Fatalf("wpad host second: %+v", hosts[1])
	}
	if hosts[2].SourceIP != "10.0.0.9" || hosts[3].SourceIP != "10.0.0.20" {
		t.Fatalf("order: %s %s", hosts[2].SourceIP, hosts[3].SourceIP)
	}
}

func TestWriteSummaryText(t *testing.T) {
	var b bytes.Buffer
	r := current()
	r.Sort()
	if err := WriteSummaryText(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"ALERTS", "[HIGH] 10.0.0.66", "Hosts to remediate", "Turn off multicast name resolution", "10.0.0.5 (00:11:22:33:44:55)", "Responder"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q", want)
		}
	}
	golden(t, "summary.txt", b.Bytes())
}

func TestWriteSummaryCSV(t *testing.T) {
	var b bytes.Buffer
	r := current()
	r.Sort()
	if err := WriteSummaryCSV(&b, r); err != nil {
		t.Fatal(err)
	}
	golden(t, "summary.csv", b.Bytes())
}

func TestDiffRenderers(t *testing.T) {
	d := run.Diff(baseline(), current(), "baseline.json", "current.json")
	var table, csvb, js bytes.Buffer
	if err := WriteDiffTable(&table, d); err != nil {
		t.Fatal(err)
	}
	if err := WriteDiffCSV(&csvb, d); err != nil {
		t.Fatal(err)
	}
	if err := WriteDiffJSON(&js, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RESOLVED", "oldfileserver, wpad", "NEW", "10.0.0.9", "(new host)", "Alerts: 2 new, 0 cleared"} {
		if !strings.Contains(table.String(), want) {
			t.Errorf("diff table missing %q\n%s", want, table.String())
		}
	}
	golden(t, "diff.txt", table.Bytes())
	golden(t, "diff.csv", csvb.Bytes())
	if !strings.Contains(js.String(), `"new_pairs": 3`) {
		t.Errorf("diff json summary wrong:\n%s", js.String())
	}
}

func TestExposureAndAdvice(t *testing.T) {
	for _, p := range decode.AllProtocols() {
		ex, ok := ExposureFor(p)
		if !ok || len(ex.Remediation) == 0 || ex.Tools == "" {
			t.Errorf("exposure for %s incomplete", p)
		}
	}
	for _, rule := range []string{"llmnr-nbns-responder", "mdns-responder", "dhcpv6-server", "wpad-http-server"} {
		if len(AlertAdvice(run.Alert{Rule: rule, SourceIP: "1.2.3.4"})) == 0 {
			t.Errorf("no advice for %s", rule)
		}
	}
	if AlertAdvice(run.Alert{Rule: "unknown"}) != nil {
		t.Error("unknown rule should have no advice")
	}
}
