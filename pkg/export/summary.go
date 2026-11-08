package export

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// HostSummary groups everything one source host did.
type HostSummary struct {
	SourceIP  string
	SourceMAC string
	Protocols []decode.Protocol // query protocols used, display order
	Names     []string          // all names involved
	WPADNames []string
	Responder bool // host answered name lookups (any protocol)
	Alerts    []run.Alert
	Count     uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// Priority ranks hosts for the report: alerts first, then WPAD exposure,
// then LLMNR/NBNS, then the rest.
func (h HostSummary) Priority() int {
	switch {
	case len(h.Alerts) > 0:
		return 0
	case len(h.WPADNames) > 0:
		return 1
	case hasProto(h.Protocols, decode.ProtoLLMNR) || hasProto(h.Protocols, decode.ProtoNBNS) || hasProto(h.Protocols, decode.ProtoDHCPv6):
		return 2
	default:
		return 3
	}
}

func hasProto(ps []decode.Protocol, p decode.Protocol) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

// Summarize groups r.Entries by source host.
func Summarize(r *run.Run) []HostSummary {
	byIP := map[string]*HostSummary{}
	for _, e := range r.Entries {
		h := byIP[e.SourceIP]
		if h == nil {
			h = &HostSummary{SourceIP: e.SourceIP, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen}
			byIP[e.SourceIP] = h
		}
		if e.SourceMAC != "" {
			h.SourceMAC = e.SourceMAC
		}
		if e.Kind == decode.KindQuery && !hasProto(h.Protocols, e.Protocol) {
			h.Protocols = append(h.Protocols, e.Protocol)
		}
		if e.Kind == decode.KindResponse {
			h.Responder = true
		}
		h.Names = appendUnique(h.Names, e.Name)
		if e.WPAD {
			h.WPADNames = appendUnique(h.WPADNames, e.Name)
		}
		h.Count += e.Count
		if !e.FirstSeen.IsZero() && (h.FirstSeen.IsZero() || e.FirstSeen.Before(h.FirstSeen)) {
			h.FirstSeen = e.FirstSeen
		}
		if e.LastSeen.After(h.LastSeen) {
			h.LastSeen = e.LastSeen
		}
	}
	for _, a := range r.Alerts {
		h := byIP[a.SourceIP]
		if h == nil {
			h = &HostSummary{SourceIP: a.SourceIP, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen}
			byIP[a.SourceIP] = h
		}
		h.Alerts = append(h.Alerts, a)
	}
	out := make([]HostSummary, 0, len(byIP))
	for _, h := range byIP {
		order := decode.AllProtocols()
		sort.SliceStable(h.Protocols, func(i, j int) bool { return indexOf(order, h.Protocols[i]) < indexOf(order, h.Protocols[j]) })
		sort.Strings(h.Names)
		sort.Strings(h.WPADNames)
		out = append(out, *h)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority() != out[j].Priority() {
			return out[i].Priority() < out[j].Priority()
		}
		return run.CompareIP(out[i].SourceIP, out[j].SourceIP) < 0
	})
	return out
}

func indexOf(ps []decode.Protocol, p decode.Protocol) int {
	for i, x := range ps {
		if x == p {
			return i
		}
	}
	return len(ps)
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// WriteSummaryText writes the human-readable remediation report.
func WriteSummaryText(w io.Writer, r *run.Run) error {
	hosts := Summarize(r)
	bw := &errWriter{w: w}

	bw.printf("Heimdall Listener report\n")
	bw.printf("========================\n")
	bw.printf("Captured on %s (%s/%s) via %s", r.Host.Hostname, r.Host.OS, r.Host.Arch, strings.Join(r.Capture.Interfaces, ", "))
	if r.Capture.Backend != "" {
		bw.printf(" [%s]", r.Capture.Backend)
	}
	bw.printf("\n")
	if !r.Capture.StartedAt.IsZero() {
		bw.printf("Window: %s to %s (%s)\n", fmtTime(r.Capture.StartedAt), fmtTime(r.Capture.EndedAt), r.Capture.Duration().Round(time.Second))
	}
	bw.printf("Packets: %d, events: %d, decode errors: %d, kernel drops: %d\n", r.Capture.PacketsSeen, r.Capture.EventsSeen, r.Capture.DecodeErrors, r.Capture.Dropped)
	bw.printf("Hosts: %d, entries: %d, alerts: %d\n\n", len(hosts), len(r.Entries), len(r.Alerts))

	// Protocol totals.
	totals := map[decode.Protocol]uint64{}
	hostsPer := map[decode.Protocol]map[string]struct{}{}
	for _, e := range r.Entries {
		if e.Kind != decode.KindQuery {
			continue
		}
		totals[e.Protocol] += e.Count
		if hostsPer[e.Protocol] == nil {
			hostsPer[e.Protocol] = map[string]struct{}{}
		}
		hostsPer[e.Protocol][e.SourceIP] = struct{}{}
	}
	bw.printf("Exposure by protocol\n--------------------\n")
	tw := tabwriter.NewWriter(bw, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PROTOCOL\tHOSTS\tREQUESTS\tABUSED BY")
	for _, p := range decode.AllProtocols() {
		if totals[p] == 0 {
			continue
		}
		ex, _ := ExposureFor(p)
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", p, len(hostsPer[p]), totals[p], ex.Tools)
	}
	tw.Flush()
	bw.printf("\n")

	if len(r.Alerts) > 0 {
		bw.printf("ALERTS (passive detections)\n---------------------------\n")
		for _, a := range r.Alerts {
			bw.printf("[%s] %s  %s\n", strings.ToUpper(string(a.Severity)), a.SourceIP, a.Title)
			bw.printf("    %s\n", a.Evidence)
			if len(a.Names) > 0 {
				bw.printf("    Names: %s\n", strings.Join(a.Names, ", "))
			}
			bw.printf("    Seen %d time(s), %s to %s\n", a.Count, fmtTime(a.FirstSeen), fmtTime(a.LastSeen))
			for _, adv := range AlertAdvice(a) {
				bw.printf("    - %s\n", adv)
			}
		}
		bw.printf("\n")
	}

	bw.printf("Hosts to remediate\n------------------\n")
	for _, h := range hosts {
		bw.printf("%s", h.SourceIP)
		if h.SourceMAC != "" {
			bw.printf(" (%s)", h.SourceMAC)
		}
		bw.printf("  %d request(s), %s to %s\n", h.Count, fmtTime(h.FirstSeen), fmtTime(h.LastSeen))
		if len(h.Alerts) > 0 {
			for _, a := range h.Alerts {
				bw.printf("    ALERT [%s] %s\n", strings.ToUpper(string(a.Severity)), a.Title)
			}
		}
		if len(h.Protocols) > 0 {
			ps := make([]string, len(h.Protocols))
			for i, p := range h.Protocols {
				ps[i] = string(p)
			}
			bw.printf("    Protocols: %s\n", strings.Join(ps, ", "))
		}
		if len(h.WPADNames) > 0 {
			bw.printf("    WPAD: %s\n", strings.Join(h.WPADNames, ", "))
		}
		if len(h.Names) > 0 {
			bw.printf("    Names: %s\n", truncateList(h.Names, 12))
		}
		for _, p := range h.Protocols {
			if ex, ok := ExposureFor(p); ok {
				bw.printf("    %s: %s\n", p, ex.Risk)
				for _, step := range ex.Remediation {
					bw.printf("      - %s\n", step)
				}
			}
		}
		bw.printf("\n")
	}
	return bw.err
}

func truncateList(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:n], ", ") + fmt.Sprintf(", +%d more", len(s)-n)
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}
