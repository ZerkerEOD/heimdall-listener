package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

func writeRun(t *testing.T, dir, name string, entries ...run.Entry) string {
	t.Helper()
	r := run.New(run.ToolInfo{Name: "test", Version: "0"})
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	r.Capture = run.CaptureInfo{Interfaces: []string{"eth0"}, StartedAt: t0, EndedAt: t0.Add(time.Minute)}
	r.Entries = entries
	p := filepath.Join(dir, name)
	if err := run.Save(p, r); err != nil {
		t.Fatal(err)
	}
	return p
}

func execCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errb.String(), err
}

func TestDiffAndExportCommands(t *testing.T) {
	dir := t.TempDir()
	e1 := run.Entry{SourceIP: "10.0.0.5", Protocol: decode.ProtoLLMNR, Kind: decode.KindQuery, Name: "wpad", WPAD: true, Count: 3}
	e2 := run.Entry{SourceIP: "10.0.0.7", Protocol: decode.ProtoNBNS, Kind: decode.KindQuery, Name: "nas<20>", Count: 1}
	base := writeRun(t, dir, "a.json", e1, e2)
	cur := writeRun(t, dir, "b.json", e2)

	out, _, err := execCmd(t, "diff", base, cur)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "RESOLVED") || !strings.Contains(out, "10.0.0.5") || !strings.Contains(out, "Resolved: 1 pair(s), 1 host(s), 1 WPAD") {
		t.Fatalf("diff output:\n%s", out)
	}
	out, _, err = execCmd(t, "diff", "-f", "json", base, cur)
	if err != nil || !strings.Contains(out, `"resolved_pairs": 1`) {
		t.Fatalf("json diff: %v\n%s", err, out)
	}
	outPath := filepath.Join(dir, "diff.csv")
	if _, _, err = execCmd(t, "diff", "-f", "csv", "-o", outPath, base, cur); err != nil {
		t.Fatal(err)
	}
	if _, _, err = execCmd(t, "diff", "-f", "bogus", base, cur); err == nil {
		t.Fatal("expected format error")
	}

	out, _, err = execCmd(t, "export", base)
	if err != nil || !strings.Contains(out, "Hosts to remediate") || !strings.Contains(out, "Turn off multicast name resolution") {
		t.Fatalf("export summary: %v\n%s", err, out)
	}
	out, _, err = execCmd(t, "export", "-f", "csv", base)
	if err != nil || strings.Count(out, "\n") != 3 {
		t.Fatalf("export csv: %v\n%s", err, out)
	}
	if _, _, err = execCmd(t, "export", filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected load error")
	}
}

func TestVersionCommand(t *testing.T) {
	out, _, err := execCmd(t, "version")
	if err != nil || !strings.Contains(out, "heimdall-listener") || !strings.Contains(out, "capture backend:") {
		t.Fatalf("version: %v\n%s", err, out)
	}
}

func TestCaptureRequiresInterface(t *testing.T) {
	if _, _, err := execCmd(t, "capture"); err == nil {
		t.Fatal("capture without -i must fail")
	}
	if _, err := parseTrusted([]string{"fe80::1", "nope"}); err == nil {
		t.Fatal("bad trusted address must fail")
	}
}
