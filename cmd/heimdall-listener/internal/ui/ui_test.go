package ui

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/software"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

func TestAppBuildsAndRendersSnapshot(t *testing.T) {
	fy := test.NewTempApp(t)
	a := newApp(fy)
	defer a.stopTicker()

	if a.table == nil || a.status == nil || a.tabs == nil || len(a.tabs.Items) != 3 {
		t.Fatal("ui not built")
	}
	rows, cols := a.table.Length()
	if rows != 0 || cols != int(numColumns) {
		t.Fatalf("empty table length = %d,%d", rows, cols)
	}

	a.applySnapshot(snap())
	rows, _ = a.table.Length()
	if rows != 4 {
		t.Fatalf("rows after snapshot = %d", rows)
	}
	// Header shows the sort indicator on the default column.
	hb := a.table.CreateHeader().(*widget.Button)
	a.table.UpdateHeader(widget.TableCellID{Row: -1, Col: int(colLast)}, hb)
	if hb.Text != "Last seen ▼" {
		t.Fatalf("header = %q", hb.Text)
	}
	// Cell rendering through the real update callback.
	c := newCell()
	a.updateCell(widget.TableCellID{Row: 0, Col: int(colIP)}, c)
	if c.label.Text != "10.0.0.66" {
		t.Fatalf("cell text = %q", c.label.Text)
	}
	// Selection drives the detail pane.
	a.table.OnSelected(widget.TableCellID{Row: 0, Col: 0})
	if e, ok := a.m.selectedEntry(); !ok || e.SrcIP.String() != "10.0.0.66" {
		t.Fatal("selection not applied")
	}
	if a.status.Text == "" {
		t.Fatal("status empty")
	}
	// Loading a run switches to read-only viewing.
	r := a.currentRun(true)
	if len(r.Entries) != 4 || len(r.Alerts) != 1 {
		t.Fatalf("currentRun = %d entries %d alerts", len(r.Entries), len(r.Alerts))
	}
	a.loadRun(r, "saved.json")
	if !a.readOnly || a.m.loadedFile != "saved.json" || a.m.dirty {
		t.Fatal("loadRun state")
	}
	rows, _ = a.table.Length()
	if rows != 4 {
		t.Fatalf("rows after load = %d", rows)
	}
	// Clearing returns to a fresh, writable state.
	a.clearResults()
	rows, _ = a.table.Length()
	if a.readOnly || rows != 0 {
		t.Fatal("clearResults state")
	}
	_ = run.SchemaVersion
}

// TestRenderViews draws the main views with Fyne's software renderer and,
// when HEIMDALL_SNAPSHOT_DIR is set, writes them as PNG files for visual
// review. Without the variable it only asserts that rendering succeeds.
func TestRenderViews(t *testing.T) {
	dir := os.Getenv("HEIMDALL_SNAPSHOT_DIR")
	fy := test.NewTempApp(t)
	a := newApp(fy)
	defer a.stopTicker()
	a.win.Resize(fyne.NewSize(1100, 700))

	a.applySnapshot(snap())
	a.table.Select(widget.TableCellID{Row: 0, Col: 0})
	a.table.OnSelected(widget.TableCellID{Row: 0, Col: 0})
	save := func(name string) {
		img := software.RenderCanvas(a.win.Canvas(), theme.DefaultTheme())
		if img.Bounds().Dx() == 0 {
			t.Fatalf("%s rendered empty", name)
		}
		if dir == "" {
			return
		}
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := png.Encode(f, img); err != nil {
			t.Fatal(err)
		}
	}
	save("render-live.png")
	a.tabs.SelectIndex(1)
	save("render-alerts.png")

	// Compare: baseline = current snapshot, current = snapshot minus one pair plus a new host.
	base := a.currentRun(true)
	cur := a.currentRun(true)
	cur.Entries = append(cur.Entries[1:], run.Entry{SourceIP: "10.0.0.99", Protocol: "LLMNR", Kind: "Query", Name: "newhost", Count: 2})
	a.compare.baseline, a.compare.baselinePath = base, "baseline.json"
	a.compare.current, a.compare.currentPath, a.compare.useLive = cur, "current.json", false
	a.compare.result = run.Diff(base, cur, "baseline.json", "current.json")
	a.compare.applyFilter()
	a.compare.summary.SetText("New: 1 pair(s) · Resolved: 1 pair(s) · Unchanged: 3")
	if len(a.compare.rows) != 5 {
		t.Fatalf("compare rows = %d", len(a.compare.rows))
	}
	a.tabs.SelectIndex(2)
	save("render-compare.png")
}
