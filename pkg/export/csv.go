package export

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

const timeFormat = time.RFC3339

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeFormat)
}

// WriteCSV writes one row per aggregated entry.
func WriteCSV(w io.Writer, r *run.Run) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"source_ip", "source_mac", "protocol", "kind", "name", "wpad", "query_types", "answers", "count", "first_seen", "last_seen"}); err != nil {
		return err
	}
	for _, e := range r.Entries {
		rec := []string{
			e.SourceIP, e.SourceMAC, string(e.Protocol), string(e.Kind), e.Name, strconv.FormatBool(e.WPAD),
			strings.Join(e.QueryTypes, " "), strings.Join(e.Answers, " "), strconv.FormatUint(e.Count, 10),
			fmtTime(e.FirstSeen), fmtTime(e.LastSeen),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteSummaryCSV writes one row per source host.
func WriteSummaryCSV(w io.Writer, r *run.Run) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"source_ip", "source_mac", "protocols", "wpad", "alerts", "names", "count", "first_seen", "last_seen"}); err != nil {
		return err
	}
	for _, h := range Summarize(r) {
		protos := make([]string, len(h.Protocols))
		for i, p := range h.Protocols {
			protos[i] = string(p)
		}
		alerts := make([]string, len(h.Alerts))
		for i, a := range h.Alerts {
			alerts[i] = fmt.Sprintf("%s:%s", a.Severity, a.Rule)
		}
		rec := []string{
			h.SourceIP, h.SourceMAC, strings.Join(protos, " "), strconv.FormatBool(len(h.WPADNames) > 0),
			strings.Join(alerts, " "), strings.Join(h.Names, " "), strconv.FormatUint(h.Count, 10),
			fmtTime(h.FirstSeen), fmtTime(h.LastSeen),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteDiffCSV writes one row per (host, protocol, kind) pair in the diff.
func WriteDiffCSV(w io.Writer, d *run.DiffResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"status", "source_ip", "protocol", "kind", "wpad", "host_new", "host_resolved", "names_new", "names_resolved", "names_unchanged", "baseline_count", "current_count"}); err != nil {
		return err
	}
	for _, p := range d.Pairs {
		var nn, nr, nu []string
		for _, n := range p.Names {
			switch n.Status {
			case run.StatusNew:
				nn = append(nn, n.Name)
			case run.StatusResolved:
				nr = append(nr, n.Name)
			default:
				nu = append(nu, n.Name)
			}
		}
		rec := []string{
			string(p.Status), p.SourceIP, string(p.Protocol), string(p.Kind), strconv.FormatBool(p.WPAD),
			strconv.FormatBool(p.HostNew), strconv.FormatBool(p.HostResolved),
			strings.Join(nn, " "), strings.Join(nr, " "), strings.Join(nu, " "),
			strconv.FormatUint(p.BaselineCount, 10), strconv.FormatUint(p.CurrentCount, 10),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
