package export

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// WriteDiffJSON encodes the diff result.
func WriteDiffJSON(w io.Writer, d *run.DiffResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

// WriteDiffTable renders the diff for a terminal.
func WriteDiffTable(w io.Writer, d *run.DiffResult) error {
	bw := &errWriter{w: w}
	bw.printf("Baseline: %s  (%s, %d entries, %d hosts)\n", refName(d.Baseline), fmtTime(d.Baseline.StartedAt), d.Baseline.Entries, d.Baseline.Hosts)
	bw.printf("Current:  %s  (%s, %d entries, %d hosts)\n\n", refName(d.Current), fmtTime(d.Current.StartedAt), d.Current.Entries, d.Current.Hosts)
	s := d.Summary
	bw.printf("New: %d pair(s), %d host(s), %d WPAD    Resolved: %d pair(s), %d host(s), %d WPAD    Unchanged: %d pair(s)\n",
		s.NewPairs, s.NewHosts, s.NewWPAD, s.ResolvedPairs, s.ResolvedHosts, s.ResolvedWPAD, s.UnchangedPairs)
	bw.printf("Alerts: %d new, %d cleared\n\n", s.NewAlerts, s.ClearedAlerts)

	section := func(title string, status run.Status) {
		pairs := d.ByStatus(status)
		if len(pairs) == 0 {
			return
		}
		bw.printf("%s\n%s\n", title, strings.Repeat("-", len(title)))
		tw := tabwriter.NewWriter(bw, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SOURCE IP\tPROTOCOL\tKIND\tBASE\tNOW\tNAMES")
		for _, p := range pairs {
			var names []string
			for _, n := range p.Names {
				switch {
				case status == run.StatusUnchanged && n.Status == run.StatusNew:
					names = append(names, "+"+n.Name)
				case status == run.StatusUnchanged && n.Status == run.StatusResolved:
					names = append(names, "-"+n.Name)
				default:
					names = append(names, n.Name)
				}
			}
			flag := ""
			if p.HostNew {
				flag = " (new host)"
			} else if p.HostResolved {
				flag = " (host gone)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s%s\n", p.SourceIP, p.Protocol, p.Kind, p.BaselineCount, p.CurrentCount, truncateList(names, 8), flag)
		}
		tw.Flush()
		bw.printf("\n")
	}
	section("NEW (appeared since baseline)", run.StatusNew)
	section("RESOLVED (present in baseline, gone now)", run.StatusResolved)
	section("UNCHANGED (+name added, -name gone)", run.StatusUnchanged)

	if len(d.Alerts) > 0 {
		bw.printf("ALERTS\n------\n")
		tw := tabwriter.NewWriter(bw, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "STATUS\tSEVERITY\tSOURCE IP\tRULE\tTITLE")
		for _, a := range d.Alerts {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.Status, a.Severity, a.SourceIP, a.Rule, a.Title)
		}
		tw.Flush()
	}
	return bw.err
}

func refName(r run.Ref) string {
	if r.Path != "" {
		return r.Path
	}
	return "(live session)"
}
