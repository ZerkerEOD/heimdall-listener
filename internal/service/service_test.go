package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

func TestWriteSnapshotAndPrune(t *testing.T) {
	dir := t.TempDir()
	r := run.New(run.ToolInfo{Name: "t"})
	var paths []string
	for i := 0; i < 4; i++ {
		// Distinct stamps: WriteSnapshot uses second resolution, so pre-create
		// older files to simulate history.
		name := filepath.Join(dir, "run-2026010"+string(rune('1'+i))+"T000000Z.json")
		if err := run.Save(name, r); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, name)
	}
	p, err := WriteSnapshot(dir, r, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "latest.json")); err != nil {
		t.Fatal("latest.json missing")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "run-*.json"))
	if len(matches) != 3 {
		t.Fatalf("expected 3 snapshots after prune, got %d: %v", len(matches), matches)
	}
	if _, err := os.Stat(paths[0]); !os.IsNotExist(err) {
		t.Fatal("oldest snapshot should be pruned")
	}
	if _, err := os.Stat(paths[1]); !os.IsNotExist(err) {
		t.Fatal("second oldest snapshot should be pruned")
	}
	// retain 0 keeps everything.
	if _, err := WriteSnapshot(dir, r, 0); err != nil {
		t.Fatal(err)
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestLoggerWritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "heimdall.log")
	log, closeFn, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hello", "k", "v")
	closeFn()
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), "hello") || !strings.Contains(string(b), "k=v") {
		t.Fatalf("log content: %q err=%v", b, err)
	}
}

func TestRunConfigDefaults(t *testing.T) {
	c := RunConfig{}.withDefaults()
	if c.SnapshotInterval != 5*time.Minute || c.OutDir == "" || c.Filter == "" {
		t.Fatalf("defaults: %+v", c)
	}
	ic := InstallConfig{}.withDefaults()
	if ic.Name != DefaultName || ic.ExePath == "" {
		t.Fatalf("install defaults: %+v", ic)
	}
}
