package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
	"github.com/ZerkerEOD/heimdall-listener/pkg/export"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
	"github.com/ZerkerEOD/heimdall-listener/pkg/session"
	"github.com/ZerkerEOD/heimdall-listener/pkg/version"
)

const (
	appID          = "com.heimdall.listener"
	prefInterface  = "interface"
	prefWinW       = "window.width"
	prefWinH       = "window.height"
	refreshPeriod  = 250 * time.Millisecond
	statusPeriod   = time.Second
	defaultWinW    = 1100
	defaultWinH    = 700
	detailSplitPos = 0.68
)

// App is the desktop application.
type App struct {
	fy  fyne.App
	win fyne.Window
	m   *model
	agg *session.Aggregator

	ifaces        []capture.Interface
	ifaceByLabel  map[string]string
	selectedIface string

	sess     *session.Session
	sessions []*session.Session // all sessions of the current aggregation (for CaptureInfo)
	running  bool
	starting bool
	readOnly bool // viewing a loaded file

	table      *widget.Table
	detail     *widget.RichText
	alerts     *widget.RichText
	status     *widget.Label
	ifaceSel   *widget.Select
	filterSel  *widget.Select
	search     *widget.Entry
	exportVis  *widget.Check
	startStop  *widget.ToolbarAction
	tabs       *container.AppTabs
	compare    *compareView
	stopTicker context.CancelFunc
}

// Run builds the window and runs the event loop until the window closes.
// An optional run file given as the first argument is opened on start.
func Run(args []string) {
	fy := app.NewWithID(appID)
	a := newApp(fy)
	fy.Lifecycle().SetOnStarted(func() {
		a.startRefreshLoop()
		if len(args) > 0 && args[0] != "" {
			path := args[0]
			go func() {
				r, err := run.Load(path)
				fyne.Do(func() {
					if err != nil {
						dialog.ShowError(err, a.win)
						return
					}
					a.loadRun(r, filepath.Base(path))
				})
			}()
		}
	})
	a.win.ShowAndRun()
}

// newApp wires the UI onto fy. It is separate from Run so tests can build
// the interface with a test app.
func newApp(fy fyne.App) *App {
	a := &App{fy: fy, m: newModel(), agg: session.NewAggregator(session.Options{})}
	fy.Settings().SetTheme(heimdallTheme{})
	a.win = fy.NewWindow("Heimdall Listener")
	a.win.SetMaster()

	a.loadInterfaces()
	a.buildUI()

	w := float32(fy.Preferences().FloatWithFallback(prefWinW, defaultWinW))
	h := float32(fy.Preferences().FloatWithFallback(prefWinH, defaultWinH))
	a.win.Resize(fyne.NewSize(w, h))
	a.win.SetCloseIntercept(a.onClose)
	a.stopTicker = func() {}
	return a
}

// startRefreshLoop begins polling the aggregator. It must only be called
// once the Fyne event loop is running, otherwise fyne.Do has no loop to
// hand work to.
func (a *App) startRefreshLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	a.stopTicker = cancel
	go a.refreshLoop(ctx)
}

func (a *App) loadInterfaces() {
	ifs, err := capture.Interfaces()
	if err != nil {
		a.ifaces = nil
		a.ifaceByLabel = map[string]string{}
		return
	}
	a.ifaceByLabel = map[string]string{}
	for _, i := range ifs {
		if !i.Usable() {
			continue
		}
		a.ifaces = append(a.ifaces, i)
		a.ifaceByLabel[ifaceLabel(i)] = i.Name
	}
}

func ifaceLabel(i capture.Interface) string {
	label := i.DisplayName()
	var v4 []string
	for _, ad := range i.Addrs {
		if ad.Is4() {
			v4 = append(v4, ad.String())
		}
	}
	if len(v4) > 0 {
		label += "  (" + strings.Join(v4, ", ") + ")"
	}
	return label
}

func (a *App) buildUI() {
	// Interface selector.
	labels := make([]string, 0, len(a.ifaces))
	for _, i := range a.ifaces {
		labels = append(labels, ifaceLabel(i))
	}
	a.ifaceSel = widget.NewSelect(labels, func(s string) {
		a.selectedIface = a.ifaceByLabel[s]
		a.fy.Preferences().SetString(prefInterface, a.selectedIface)
	})
	a.ifaceSel.PlaceHolder = "Select interface"
	if last := a.fy.Preferences().StringWithFallback(prefInterface, ""); last != "" {
		for l, n := range a.ifaceByLabel {
			if n == last {
				a.ifaceSel.SetSelected(l)
			}
		}
	}
	if a.ifaceSel.Selected == "" && len(labels) > 0 {
		a.ifaceSel.SetSelected(labels[0])
	}

	// Filter + search.
	a.filterSel = widget.NewSelect(filterOptions(), func(s string) {
		a.m.setFilter(s, a.search.Text)
		a.refreshTable()
	})
	a.search = widget.NewEntry()
	a.search.PlaceHolder = "Search IP, name, MAC…"
	a.search.ActionItem = widget.NewIcon(theme.SearchIcon())
	a.search.OnChanged = func(s string) {
		a.m.setFilter(a.filterSel.Selected, s)
		a.refreshTable()
	}
	a.exportVis = widget.NewCheck("Export visible rows only", nil)

	// Toolbar.
	a.startStop = widget.NewToolbarAction(theme.MediaPlayIcon(), a.toggleCapture)
	tb := widget.NewToolbar(
		a.startStop,
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.ContentClearIcon(), a.clearResults),
		widget.NewToolbarAction(theme.DocumentSaveIcon(), a.saveRun),
		widget.NewToolbarAction(theme.FolderOpenIcon(), a.openRun),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.FileTextIcon(), a.exportCSV),
		widget.NewToolbarAction(theme.ListIcon(), a.exportSummary),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.ViewRefreshIcon(), func() { a.tabs.SelectIndex(2) }),
		widget.NewToolbarSpacer(),
		widget.NewToolbarAction(theme.InfoIcon(), a.showAbout),
	)
	controls := container.NewBorder(nil, nil,
		container.NewHBox(widget.NewLabel("Interface:"), a.ifaceSel, widget.NewSeparator(), widget.NewLabel("Show:"), a.filterSel),
		a.exportVis,
		a.search)
	top := container.NewVBox(tb, controls)

	// Live table.
	a.table = widget.NewTable(
		func() (int, int) { return len(a.m.rows), int(numColumns) },
		func() fyne.CanvasObject { return newCell() },
		a.updateCell)
	a.table.ShowHeaderRow = true
	a.table.CreateHeader = func() fyne.CanvasObject { return headerButton() }
	a.table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		b := o.(*widget.Button)
		if id.Col < 0 || id.Col >= int(numColumns) {
			b.SetText("")
			return
		}
		col := column(id.Col)
		b.SetText(a.m.headerText(col))
		b.OnTapped = func() {
			a.m.toggleSort(col)
			a.refreshTable()
		}
	}
	for c := column(0); c < numColumns; c++ {
		a.table.SetColumnWidth(int(c), columnWidths[c])
	}
	a.table.OnSelected = func(id widget.TableCellID) {
		a.m.selectRow(id.Row)
		a.refreshDetail()
	}

	a.detail = widget.NewRichTextFromMarkdown("Select a row to see details and remediation guidance.")
	a.detail.Wrapping = fyne.TextWrapWord
	split := container.NewVSplit(a.table, container.NewVScroll(a.detail))
	split.Offset = detailSplitPos

	a.alerts = widget.NewRichTextFromMarkdown(alertsMarkdown(nil))
	a.alerts.Wrapping = fyne.TextWrapWord

	a.compare = newCompareView(a)

	a.tabs = container.NewAppTabs(
		container.NewTabItemWithIcon("Live", theme.ListIcon(), split),
		container.NewTabItemWithIcon("Alerts", theme.WarningIcon(), container.NewVScroll(a.alerts)),
		container.NewTabItemWithIcon("Compare", theme.ViewRefreshIcon(), a.compare.content),
	)

	a.status = widget.NewLabel("")
	a.status.Truncation = fyne.TextTruncateEllipsis
	a.filterSel.SetSelected(filterAll)
	a.updateStatus()

	a.win.SetContent(container.NewBorder(top, a.status, nil, nil, a.tabs))

	if len(a.ifaces) == 0 {
		a.status.SetText("No usable network interfaces found. " + privilegeHint())
	}
}

func (a *App) updateCell(id widget.TableCellID, o fyne.CanvasObject) {
	c := o.(*cell)
	if id.Row < 0 || id.Row >= len(a.m.rows) {
		c.set("", false, theme.Color(theme.ColorNameBackground))
		return
	}
	e := a.m.rows[id.Row]
	col := column(id.Col)
	accent := protocolColor(e.Protocol)
	if col != colProtocol {
		accent = theme.Color(theme.ColorNameBackground)
		if col == colIP {
			if _, alerted := a.m.alertHosts[e.SrcIP.String()]; alerted {
				accent = theme.Color(theme.ColorNameError)
			}
		}
	}
	c.set(a.m.cellText(id.Row, col), e.WPAD && (col == colName || col == colIP), accent)
}

// refreshLoop is the only goroutine that touches the UI, always via fyne.Do.
func (a *App) refreshLoop(ctx context.Context) {
	tick := time.NewTicker(refreshPeriod)
	defer tick.Stop()
	status := time.NewTicker(statusPeriod)
	defer status.Stop()
	var last uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if v := a.agg.Version(); v != last {
				last = v
				snap := a.agg.Snapshot()
				fyne.Do(func() {
					if a.readOnly {
						return
					}
					a.applySnapshot(snap)
				})
			}
		case <-status.C:
			fyne.Do(a.updateStatus)
		}
	}
}

func (a *App) applySnapshot(snap session.Snapshot) {
	a.m.setSnapshot(snap)
	a.refreshTable()
	a.alerts.ParseMarkdown(alertsMarkdown(snap.Alerts))
	a.updateStatus()
}

func (a *App) refreshTable() {
	if a.table == nil {
		return
	}
	a.table.Refresh()
	a.refreshDetail()
}

func (a *App) refreshDetail() {
	if e, ok := a.m.selectedEntry(); ok {
		a.detail.ParseMarkdown(detailMarkdown(e, a.m.snap.Alerts))
	} else {
		a.detail.ParseMarkdown("Select a row to see details and remediation guidance.")
	}
}

func (a *App) updateStatus() {
	state := "Stopped"
	var elapsed time.Duration
	switch {
	case a.readOnly:
		state = "Viewing " + a.m.loadedFile
	case a.starting:
		state = "Starting"
	case a.running:
		state = "● Capturing"
		elapsed = time.Since(a.agg.StartedAt())
	}
	iface := ""
	if a.running || a.starting {
		iface = a.selectedIface
	}
	snap := a.m.snap
	if !a.readOnly {
		snap.Stats = a.agg.Snapshot().Stats
		snap.Alerts = a.m.snap.Alerts
	}
	a.status.SetText(statusText(state, iface, capture.Backend(), snap, elapsed))
}

// --- capture control ---

func (a *App) toggleCapture() {
	if a.starting {
		return
	}
	if a.running {
		a.stopCapture(nil)
		return
	}
	if a.readOnly {
		dialog.ShowInformation("Viewing a file", "Clear the loaded file first (clear button) to start a new capture.", a.win)
		return
	}
	if a.selectedIface == "" {
		dialog.ShowInformation("No interface", "Select a network interface to capture on.", a.win)
		return
	}
	a.starting = true
	a.updateStatus()
	iface := a.selectedIface
	opts := capture.DefaultOptions()
	opts.OnWarning = func(msg string) { fyne.Do(func() { a.status.SetText("Warning: " + msg) }) }
	if len(a.sessions) == 0 {
		a.agg.Reset()
	}
	go func() {
		s, err := session.Start(context.Background(), session.Config{Interface: iface, Capture: opts}, a.agg)
		fyne.Do(func() {
			a.starting = false
			if err != nil {
				a.showStartError(err)
				a.updateStatus()
				return
			}
			a.sess = s
			a.sessions = append(a.sessions, s)
			a.running = true
			a.startStop.SetIcon(theme.MediaStopIcon())
			a.ifaceSel.Disable()
			a.updateStatus()
		})
		<-s.Done()
		if e := s.Err(); e != nil {
			fyne.Do(func() {
				if a.sess == s {
					a.stopCapture(e)
				}
			})
		}
	}()
}

func (a *App) stopCapture(cause error) {
	s := a.sess
	a.sess = nil
	a.running = false
	a.startStop.SetIcon(theme.MediaPlayIcon())
	a.ifaceSel.Enable()
	a.updateStatus()
	if s != nil {
		go func() { _ = s.Stop() }()
	}
	if cause != nil {
		dialog.ShowError(fmt.Errorf("capture stopped: %w", cause), a.win)
	}
}

func (a *App) showStartError(err error) {
	if errors.Is(err, capture.ErrPermission) {
		dialog.ShowError(fmt.Errorf("%v\n\n%s", err, privilegeHint()), a.win)
		return
	}
	dialog.ShowError(err, a.win)
}

func privilegeHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Run Heimdall Listener as Administrator and make sure Npcap is installed (https://npcap.com)."
	case "darwin":
		return "Run with sudo, or install Wireshark's ChmodBPF so your user may capture."
	default:
		exe, _ := os.Executable()
		return fmt.Sprintf("Run with sudo, or grant capture rights once:\n  sudo setcap cap_net_raw,cap_net_admin+eip %s", exe)
	}
}

// --- results management ---

func (a *App) clearResults() {
	do := func() {
		if a.running {
			a.stopCapture(nil)
		}
		a.agg.Reset()
		a.sessions = nil
		a.readOnly = false
		a.m = newModel()
		a.m.setSnapshot(a.agg.Snapshot())
		a.m.dirty = false
		a.alerts.ParseMarkdown(alertsMarkdown(nil))
		a.refreshTable()
		a.updateStatus()
	}
	if a.m.dirty && !a.readOnly {
		dialog.NewConfirm("Clear results", fmt.Sprintf("Discard %d unsaved entries and start fresh?", len(a.m.snap.Entries)), func(ok bool) {
			if ok {
				do()
			}
		}, a.win).Show()
		return
	}
	do()
}

func (a *App) toolInfo() run.ToolInfo {
	v := version.Short()
	if v == "dev" && a.fy.Metadata().Version != "" {
		v = a.fy.Metadata().Version // set by `fyne package` from FyneApp.toml
	}
	return run.ToolInfo{Name: "heimdall-listener", Version: v, Commit: version.Commit}
}

// currentRun exports the current state; all=false honours the table filter.
func (a *App) currentRun(all bool) *run.Run {
	snap := a.m.snap
	ci := session.CaptureInfo(a.sessions, snap)
	if a.readOnly {
		ci = run.CaptureInfo{Interfaces: []string{a.m.loadedFile}, StartedAt: snap.Stats.StartedAt, EndedAt: snap.TakenAt}
	} else if len(a.sessions) == 0 {
		ci.Interfaces = []string{a.selectedIface}
	}
	if all {
		return a.m.allRun(a.toolInfo(), ci)
	}
	return a.m.visibleRun(a.toolInfo(), ci)
}

func timestamp() string { return time.Now().Format("20060102-150405") }

// saveWithDialog asks for a destination and streams write() into it.
func (a *App) saveWithDialog(defaultName string, exts []string, write func(io.Writer) error) {
	d := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, a.win)
			return
		}
		if wc == nil {
			return
		}
		werr := write(wc)
		cerr := wc.Close()
		if werr == nil {
			werr = cerr
		}
		if werr != nil {
			dialog.ShowError(werr, a.win)
			return
		}
		a.status.SetText("Saved " + wc.URI().Path())
	}, a.win)
	d.SetFileName(defaultName)
	d.SetFilter(storage.NewExtensionFileFilter(exts))
	d.Show()
}

func (a *App) saveRun() {
	if len(a.m.snap.Entries) == 0 {
		dialog.ShowInformation("Nothing to save", "Capture some traffic first.", a.win)
		return
	}
	r := a.currentRun(true)
	a.saveWithDialog("heimdall-run-"+timestamp()+".json", []string{".json"}, func(w io.Writer) error {
		if err := run.Write(w, r); err != nil {
			return err
		}
		a.m.dirty = false
		return nil
	})
}

func (a *App) exportCSV() {
	r := a.currentRun(!a.exportVis.Checked)
	a.saveWithDialog("heimdall-entries-"+timestamp()+".csv", []string{".csv"}, func(w io.Writer) error { return export.WriteCSV(w, r) })
}

func (a *App) exportSummary() {
	r := a.currentRun(!a.exportVis.Checked)
	a.saveWithDialog("heimdall-summary-"+timestamp()+".txt", []string{".txt"}, func(w io.Writer) error { return export.WriteSummaryText(w, r) })
}

func (a *App) openRun() {
	open := func() {
		d := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, a.win)
				return
			}
			if rc == nil {
				return
			}
			defer rc.Close()
			r, err := run.Read(rc)
			if err != nil {
				dialog.ShowError(err, a.win)
				return
			}
			a.loadRun(r, rc.URI().Name())
		}, a.win)
		d.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
		d.Show()
	}
	if a.m.dirty && !a.readOnly {
		dialog.NewConfirm("Open run", "Discard the current unsaved results and open a file?", func(ok bool) {
			if ok {
				open()
			}
		}, a.win).Show()
		return
	}
	open()
}

func (a *App) loadRun(r *run.Run, name string) {
	if a.running {
		a.stopCapture(nil)
	}
	a.sessions = nil
	a.agg.Reset()
	a.readOnly = true
	a.m = newModel()
	a.m.setSnapshot(session.FromRun(r))
	a.m.dirty = false
	a.m.loadedFile = name
	a.filterSel.SetSelected(filterAll)
	a.alerts.ParseMarkdown(alertsMarkdown(r.Alerts))
	a.refreshTable()
	a.updateStatus()
}

func (a *App) showAbout() {
	msg := version.String() + "\nBuild: " + a.toolInfo().Version + "\nCapture backend: " + capture.Backend() + "\n\n" +
		"Heimdall Listener passively identifies hosts using legacy name resolution (LLMNR, NetBIOS, mDNS), WPAD and DHCPv6, " +
		"the traffic abused by Responder, Inveigh, mitm6 and ntlmrelayx. It never transmits packets.\n\n" +
		"Tip: save a run before remediation, capture again afterwards, and use Compare to prove the change worked."
	dialog.ShowInformation("About Heimdall Listener", msg, a.win)
}

func (a *App) onClose() {
	quit := func() {
		sz := a.win.Canvas().Size()
		a.fy.Preferences().SetFloat(prefWinW, float64(sz.Width))
		a.fy.Preferences().SetFloat(prefWinH, float64(sz.Height))
		a.stopTicker()
		if a.sess != nil {
			s := a.sess
			a.sess = nil
			go func() { _ = s.Stop() }()
		}
		a.win.Close()
	}
	if a.m.dirty && !a.readOnly {
		dialog.NewConfirm("Quit", "You have unsaved results. Quit anyway?", func(ok bool) {
			if ok {
				quit()
			}
		}, a.win).Show()
		return
	}
	quit()
}
