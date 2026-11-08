package ui

import (
	"fmt"
	"image/color"
	"io"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/ZerkerEOD/heimdall-listener/pkg/export"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// compareView is the Compare tab: baseline file vs. live session or file.
type compareView struct {
	app *App

	baselinePath string
	baseline     *run.Run
	currentPath  string
	current      *run.Run
	useLive      bool

	result  *run.DiffResult
	rows    []run.PairDiff
	status  string // filter: all/new/resolved/unchanged
	summary *widget.Label
	baseLbl *widget.Label
	curLbl  *widget.Label
	table   *widget.Table
	content fyne.CanvasObject
}

var compareColumns = []string{"Status", "Source IP", "Protocol", "Kind", "Names", "Baseline", "Current"}
var compareWidths = []float32{150, 150, 90, 90, 300, 80, 80}

func newCompareView(a *App) *compareView {
	v := &compareView{app: a, useLive: true, status: "All"}
	v.baseLbl = widget.NewLabel("No baseline selected")
	v.baseLbl.Truncation = fyne.TextTruncateEllipsis
	v.curLbl = widget.NewLabel("Live session")
	v.curLbl.Truncation = fyne.TextTruncateEllipsis
	v.summary = widget.NewLabel("Pick a baseline run, then Compare.")
	v.summary.Wrapping = fyne.TextWrapWord

	pickBase := widget.NewButtonWithIcon("Baseline…", iconFolderOpen(), func() {
		v.openRun(func(r *run.Run, path string) {
			v.baseline, v.baselinePath = r, path
			v.baseLbl.SetText(fmt.Sprintf("%s (%d entries)", filepath.Base(path), len(r.Entries)))
		})
	})
	pickCur := widget.NewButtonWithIcon("Current file…", iconFolderOpen(), func() {
		v.openRun(func(r *run.Run, path string) {
			v.current, v.currentPath, v.useLive = r, path, false
			v.curLbl.SetText(fmt.Sprintf("%s (%d entries)", filepath.Base(path), len(r.Entries)))
		})
	})
	useLive := widget.NewButton("Use live session", func() {
		v.useLive, v.current, v.currentPath = true, nil, ""
		v.curLbl.SetText("Live session")
	})
	compareBtn := widget.NewButtonWithIcon("Compare", iconViewRefresh(), v.compare)
	compareBtn.Importance = widget.HighImportance

	filter := widget.NewSelect([]string{"All", "New", "Resolved", "Unchanged"}, func(s string) {
		v.status = s
		v.applyFilter()
	})

	exportCSV := widget.NewButtonWithIcon("Export diff CSV", iconDocumentSave(), func() {
		v.exportDiff("csv", func(w io.Writer) error { return export.WriteDiffCSV(w, v.result) })
	})
	exportJSON := widget.NewButtonWithIcon("Export diff JSON", iconDocumentSave(), func() {
		v.exportDiff("json", func(w io.Writer) error { return export.WriteDiffJSON(w, v.result) })
	})

	v.table = widget.NewTable(
		func() (int, int) { return len(v.rows), len(compareColumns) },
		func() fyne.CanvasObject { return newCell() },
		func(id widget.TableCellID, o fyne.CanvasObject) {
			c := o.(*cell)
			if id.Row < 0 || id.Row >= len(v.rows) {
				c.set("", false, color.Transparent)
				return
			}
			p := v.rows[id.Row]
			var accent color.Color = color.Transparent
			if id.Col == 0 {
				accent = statusColor(p.Status)
			}
			c.set(v.cellText(p, id.Col), p.WPAD && id.Col == 4, accent)
		})
	v.table.ShowHeaderRow = true
	v.table.CreateHeader = func() fyne.CanvasObject { return headerButton() }
	v.table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		b := o.(*widget.Button)
		if id.Col >= 0 && id.Col < len(compareColumns) {
			b.SetText(compareColumns[id.Col])
		}
	}
	for i, w := range compareWidths {
		v.table.SetColumnWidth(i, w)
	}
	filter.SetSelected("All")

	top := container.NewVBox(
		container.NewBorder(nil, nil, container.NewHBox(pickBase), nil, v.baseLbl),
		container.NewBorder(nil, nil, container.NewHBox(pickCur, useLive), nil, v.curLbl),
		container.NewHBox(compareBtn, widget.NewLabel("Show:"), filter, exportCSV, exportJSON),
		v.summary,
	)
	v.content = container.NewBorder(top, nil, nil, nil, v.table)
	return v
}

func (v *compareView) cellText(p run.PairDiff, col int) string {
	switch col {
	case 0:
		s := string(p.Status)
		if p.HostNew {
			s += " (new host)"
		} else if p.HostResolved {
			s += " (host gone)"
		}
		return s
	case 1:
		return p.SourceIP
	case 2:
		return string(p.Protocol)
	case 3:
		return string(p.Kind)
	case 4:
		var out []string
		for _, n := range p.Names {
			switch {
			case p.Status == run.StatusUnchanged && n.Status == run.StatusNew:
				out = append(out, "+"+n.Name)
			case p.Status == run.StatusUnchanged && n.Status == run.StatusResolved:
				out = append(out, "-"+n.Name)
			default:
				out = append(out, n.Name)
			}
		}
		return joinMax(out, 6)
	case 5:
		return formatCount(p.BaselineCount)
	case 6:
		return formatCount(p.CurrentCount)
	}
	return ""
}

func joinMax(s []string, n int) string {
	if len(s) <= n {
		return join(s)
	}
	return join(s[:n]) + fmt.Sprintf(", +%d more", len(s)-n)
}

func join(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func (v *compareView) openRun(cb func(*run.Run, string)) {
	d := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, v.app.win)
			return
		}
		if rc == nil {
			return
		}
		defer rc.Close()
		r, err := run.Read(rc)
		if err != nil {
			dialog.ShowError(err, v.app.win)
			return
		}
		cb(r, rc.URI().Path())
	}, v.app.win)
	d.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
	d.Show()
}

func (v *compareView) compare() {
	if v.baseline == nil {
		dialog.ShowInformation("Compare", "Choose a baseline run file first.", v.app.win)
		return
	}
	cur, curPath := v.current, v.currentPath
	if v.useLive {
		cur, curPath = v.app.currentRun(true), ""
	}
	if cur == nil {
		dialog.ShowInformation("Compare", "Choose a current run file or use the live session.", v.app.win)
		return
	}
	base, basePath := v.baseline, v.baselinePath
	go func() {
		d := run.Diff(base, cur, basePath, curPath)
		fyne.Do(func() {
			v.result = d
			s := d.Summary
			v.summary.SetText(fmt.Sprintf("New: %d pair(s), %d host(s), %d WPAD   ·   Resolved: %d pair(s), %d host(s), %d WPAD   ·   Unchanged: %d   ·   Alerts: %d new, %d cleared",
				s.NewPairs, s.NewHosts, s.NewWPAD, s.ResolvedPairs, s.ResolvedHosts, s.ResolvedWPAD, s.UnchangedPairs, s.NewAlerts, s.ClearedAlerts))
			v.applyFilter()
		})
	}()
}

func (v *compareView) applyFilter() {
	if v.table == nil {
		return
	}
	v.rows = v.rows[:0]
	if v.result == nil {
		v.table.Refresh()
		return
	}
	for _, p := range v.result.Pairs {
		switch v.status {
		case "New":
			if p.Status != run.StatusNew {
				continue
			}
		case "Resolved":
			if p.Status != run.StatusResolved {
				continue
			}
		case "Unchanged":
			if p.Status != run.StatusUnchanged {
				continue
			}
		}
		v.rows = append(v.rows, p)
	}
	v.table.Refresh()
	v.table.ScrollToTop()
}

func (v *compareView) exportDiff(ext string, write func(io.Writer) error) {
	if v.result == nil {
		dialog.ShowInformation("Export", "Run a comparison first.", v.app.win)
		return
	}
	v.app.saveWithDialog("heimdall-diff-"+timestamp()+"."+ext, []string{"." + ext}, write)
}
