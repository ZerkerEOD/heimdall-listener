// Package ui implements the Heimdall Listener desktop interface on Fyne.
//
// The view model in this file is plain Go so that filtering, sorting and
// export selection can be unit tested without a display.
package ui

import (
	"sort"
	"strings"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
	"github.com/ZerkerEOD/heimdall-listener/pkg/session"
)

// Table columns of the live view.
type column int

const (
	colIP column = iota
	colProtocol
	colKind
	colName
	colCount
	colFirst
	colLast
	numColumns
)

var columnTitles = [numColumns]string{"Source IP", "Protocol", "Kind", "Name", "Count", "First seen", "Last seen"}
var columnWidths = [numColumns]float32{150, 90, 90, 260, 70, 110, 110}

// Filter presets offered in the protocol selector, beyond protocol names.
const (
	filterAll    = "All"
	filterWPAD   = "WPAD"
	filterAlerts = "Alerts"
)

// filterOptions lists every selectable filter.
func filterOptions() []string {
	opts := []string{filterAll}
	for _, p := range decode.AllProtocols() {
		opts = append(opts, string(p))
	}
	return append(opts, filterWPAD, filterAlerts)
}

// model holds the GUI's view of the aggregator and the user's view settings.
type model struct {
	snap    session.Snapshot
	rows    []session.Entry // filtered and sorted
	sortCol column
	sortAsc bool
	filter  string
	search  string

	selected    *session.Key
	dirty       bool // unsaved results exist
	loadedFile  string
	alertHosts  map[string]struct{}
	timeDisplay func(time.Time) string
}

func newModel() *model {
	return &model{sortCol: colLast, sortAsc: false, filter: filterAll,
		timeDisplay: func(t time.Time) string { return t.Local().Format("15:04:05") }}
}

// setSnapshot replaces the data and re-applies filter and sort. Selection is
// preserved when the selected entry still exists.
func (m *model) setSnapshot(s session.Snapshot) {
	if s.Stats.Events > 0 && s.Stats.Events != m.snap.Stats.Events {
		m.dirty = true
	}
	m.snap = s
	m.alertHosts = map[string]struct{}{}
	for _, a := range s.Alerts {
		m.alertHosts[a.SourceIP] = struct{}{}
	}
	m.apply()
}

// setFilter changes the protocol preset and free-text search.
func (m *model) setFilter(preset, search string) {
	m.filter = preset
	m.search = strings.ToLower(strings.TrimSpace(search))
	m.apply()
}

// toggleSort sorts by c, flipping direction when c is already the sort key.
func (m *model) toggleSort(c column) {
	if m.sortCol == c {
		m.sortAsc = !m.sortAsc
	} else {
		m.sortCol = c
		m.sortAsc = c != colCount && c != colLast && c != colFirst
	}
	m.apply()
}

func (m *model) matches(e session.Entry) bool {
	switch m.filter {
	case filterAll:
	case filterWPAD:
		if !e.WPAD {
			return false
		}
	case filterAlerts:
		if _, ok := m.alertHosts[e.SrcIP.String()]; !ok {
			return false
		}
	default:
		if string(e.Protocol) != m.filter {
			return false
		}
	}
	if m.search == "" {
		return true
	}
	if strings.Contains(e.SrcIP.String(), m.search) || strings.Contains(strings.ToLower(e.Name), m.search) ||
		strings.Contains(strings.ToLower(string(e.Protocol)), m.search) || strings.Contains(strings.ToLower(e.SrcMAC.String()), m.search) {
		return true
	}
	for _, a := range e.Answers {
		if strings.Contains(a.String(), m.search) {
			return true
		}
	}
	return false
}

func (m *model) apply() {
	m.rows = m.rows[:0]
	for _, e := range m.snap.Entries {
		if m.matches(e) {
			m.rows = append(m.rows, e)
		}
	}
	col, asc := m.sortCol, m.sortAsc
	sort.SliceStable(m.rows, func(i, j int) bool {
		a, b := m.rows[i], m.rows[j]
		var less bool
		switch col {
		case colIP:
			less = a.SrcIP.Compare(b.SrcIP) < 0
		case colProtocol:
			less = a.Protocol < b.Protocol
		case colKind:
			less = a.Kind < b.Kind
		case colName:
			less = a.Name < b.Name
		case colCount:
			less = a.Count < b.Count
		case colFirst:
			less = a.FirstSeen.Before(b.FirstSeen)
		default:
			less = a.LastSeen.Before(b.LastSeen)
		}
		if !asc {
			return !less && !equalKey(a, b)
		}
		return less
	})
	if m.selected != nil && m.selectedRow() < 0 {
		m.selected = nil
	}
}

func equalKey(a, b session.Entry) bool { return a.Key == b.Key }

// selectedRow returns the row index of the selection, or -1.
func (m *model) selectedRow() int {
	if m.selected == nil {
		return -1
	}
	for i, e := range m.rows {
		if e.Key == *m.selected {
			return i
		}
	}
	return -1
}

// selectRow records the selection by key so it survives re-sorting.
func (m *model) selectRow(i int) {
	if i < 0 || i >= len(m.rows) {
		m.selected = nil
		return
	}
	k := m.rows[i].Key
	m.selected = &k
}

// selectedEntry returns the selected entry, if any.
func (m *model) selectedEntry() (session.Entry, bool) {
	i := m.selectedRow()
	if i < 0 {
		return session.Entry{}, false
	}
	return m.rows[i], true
}

// cellText renders one cell.
func (m *model) cellText(row int, c column) string {
	if row < 0 || row >= len(m.rows) {
		return ""
	}
	e := m.rows[row]
	switch c {
	case colIP:
		return e.SrcIP.String()
	case colProtocol:
		return string(e.Protocol)
	case colKind:
		return string(e.Kind)
	case colName:
		return e.Name
	case colCount:
		return formatCount(e.Count)
	case colFirst:
		return m.timeDisplay(e.FirstSeen)
	case colLast:
		return m.timeDisplay(e.LastSeen)
	}
	return ""
}

// headerText renders a column header with its sort indicator.
func (m *model) headerText(c column) string {
	t := columnTitles[c]
	if c == m.sortCol {
		if m.sortAsc {
			return t + " ▲"
		}
		return t + " ▼"
	}
	return t
}

func formatCount(n uint64) string {
	s := make([]byte, 0, 24)
	str := []byte(strings.TrimSpace(uitoa(n)))
	for i, c := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			s = append(s, ',')
		}
		s = append(s, c)
	}
	return string(s)
}

func uitoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// visibleRun exports what the table currently shows.
func (m *model) visibleRun(tool run.ToolInfo, ci run.CaptureInfo) *run.Run {
	s := m.snap
	s.Entries = append([]session.Entry(nil), m.rows...)
	return s.ToRun(tool, ci)
}

// allRun exports everything captured regardless of filter.
func (m *model) allRun(tool run.ToolInfo, ci run.CaptureInfo) *run.Run {
	return m.snap.ToRun(tool, ci)
}
