package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/session"
)

const clearScreen = "\x1b[2J\x1b[H"

// liveView renders the aggregator state as a refreshing terminal table.
type liveView struct {
	w          io.Writer
	ifaces     []string
	backend    string
	maxRows    int
	lastVer    uint64
	lastRender time.Time
}

// render redraws when the aggregator changed or every few seconds for the
// elapsed clock.
func (v *liveView) render(snap session.Snapshot, force bool) {
	if !force && snap.Version == v.lastVer && time.Since(v.lastRender) < 5*time.Second {
		return
	}
	v.lastVer = snap.Version
	v.lastRender = time.Now()

	var sb strings.Builder
	sb.WriteString(clearScreen)
	st := snap.Stats
	elapsed := time.Since(st.StartedAt).Round(time.Second)
	fmt.Fprintf(&sb, "Heimdall Listener  |  %s  |  %s  |  elapsed %s  |  Ctrl-C to stop and write results\n",
		strings.Join(v.ifaces, ","), v.backend, elapsed)
	fmt.Fprintf(&sb, "packets %d  events %d  hosts %d  drops %d  decode errors %d", st.Packets, st.Events, st.UniqueHosts, st.Dropped, st.DecodeErrors)
	var protos []string
	for _, p := range decode.AllProtocols() {
		if n := st.PerProtocol[p]; n > 0 {
			protos = append(protos, fmt.Sprintf("%s %d", p, n))
		}
	}
	if len(protos) > 0 {
		fmt.Fprintf(&sb, "  |  %s", strings.Join(protos, "  "))
	}
	sb.WriteString("\n")
	if len(snap.Alerts) > 0 {
		fmt.Fprintf(&sb, "\nALERTS (%d)\n", len(snap.Alerts))
		for i, a := range snap.Alerts {
			if i >= 5 {
				fmt.Fprintf(&sb, "  ... %d more\n", len(snap.Alerts)-5)
				break
			}
			fmt.Fprintf(&sb, "  [%s] %s  %s (x%d)\n", strings.ToUpper(string(a.Severity)), a.SourceIP, a.Title, a.Count)
		}
	}
	sb.WriteString("\n")

	entries := snap.Entries
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].WPAD != entries[j].WPAD {
			return entries[i].WPAD
		}
		return entries[i].LastSeen.After(entries[j].LastSeen)
	})
	tw := tabwriter.NewWriter(&sb, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE IP\tPROTOCOL\tKIND\tNAME\tCOUNT\tLAST SEEN")
	shown := 0
	for _, e := range entries {
		if v.maxRows > 0 && shown >= v.maxRows {
			fmt.Fprintf(tw, "...\t\t\t%d more entries\t\t\n", len(entries)-shown)
			break
		}
		name := e.Name
		if e.WPAD {
			name += "  (WPAD)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", e.SrcIP, e.Protocol, e.Kind, name, e.Count, e.LastSeen.Local().Format("15:04:05"))
		shown++
	}
	tw.Flush()
	fmt.Fprint(v.w, sb.String())
}

// statusLine is the non-interactive progress line for logs/pipes.
func statusLine(snap session.Snapshot) string {
	st := snap.Stats
	return fmt.Sprintf("%s capturing: packets=%d events=%d hosts=%d alerts=%d drops=%d elapsed=%s",
		time.Now().Format(time.RFC3339), st.Packets, st.Events, st.UniqueHosts, len(snap.Alerts), st.Dropped, time.Since(st.StartedAt).Round(time.Second))
}
