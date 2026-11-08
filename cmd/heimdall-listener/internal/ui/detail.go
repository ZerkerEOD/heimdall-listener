package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/export"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
	"github.com/ZerkerEOD/heimdall-listener/pkg/session"
)

func fmtBoth(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05 MST") + "  (" + t.UTC().Format(time.RFC3339) + ")"
}

// detailMarkdown renders the detail pane for an entry.
func detailMarkdown(e session.Entry, alerts []run.Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s  ·  %s %s\n\n", e.SrcIP, e.Protocol, e.Kind)
	if e.WPAD {
		b.WriteString("**WPAD related** — this name or request is part of Web Proxy Auto-Discovery, the highest-value target for poisoning.\n\n")
	}
	fmt.Fprintf(&b, "- **Name:** %s\n", e.Name)
	if e.Protocol == decode.ProtoNBNS {
		if i := strings.LastIndex(e.Name, "<"); i >= 0 && len(e.Name) >= i+4 {
			var suffix byte
			if _, err := fmt.Sscanf(e.Name[i+1:i+3], "%02x", &suffix); err == nil {
				fmt.Fprintf(&b, "- **NetBIOS suffix:** <%02x> %s\n", suffix, decode.NetBIOSSuffixRole(suffix))
			}
		}
	}
	if len(e.SrcMAC) > 0 {
		fmt.Fprintf(&b, "- **Source MAC:** %s\n", e.SrcMAC)
	}
	if len(e.QueryTypes) > 0 {
		fmt.Fprintf(&b, "- **Types:** %s\n", strings.Join(e.QueryTypes, ", "))
	}
	if len(e.Answers) > 0 {
		as := make([]string, len(e.Answers))
		for i, a := range e.Answers {
			as[i] = a.String()
		}
		label := "Answers"
		if e.Protocol == decode.ProtoHTTP {
			label = "Server"
		}
		fmt.Fprintf(&b, "- **%s:** %s\n", label, strings.Join(as, ", "))
	}
	fmt.Fprintf(&b, "- **Count:** %s\n", formatCount(e.Count))
	fmt.Fprintf(&b, "- **First seen:** %s\n", fmtBoth(e.FirstSeen))
	fmt.Fprintf(&b, "- **Last seen:** %s\n", fmtBoth(e.LastSeen))
	if e.LastDetail != "" {
		fmt.Fprintf(&b, "- **Last packet:** `%s`\n", e.LastDetail)
	}

	var hostAlerts []run.Alert
	for _, a := range alerts {
		if a.SourceIP == e.SrcIP.String() {
			hostAlerts = append(hostAlerts, a)
		}
	}
	if len(hostAlerts) > 0 {
		b.WriteString("\n### Alerts for this host\n\n")
		for _, a := range hostAlerts {
			fmt.Fprintf(&b, "- **%s** %s\n", alertHeading(a), a.Evidence)
		}
	}

	if e.Kind == decode.KindQuery {
		if ex, ok := export.ExposureFor(e.Protocol); ok {
			b.WriteString("\n### Why it matters\n\n")
			fmt.Fprintf(&b, "%s Abused by: %s.\n\n", ex.Risk, ex.Tools)
			b.WriteString("### How to fix\n\n")
			for _, step := range ex.Remediation {
				fmt.Fprintf(&b, "- %s\n", step)
			}
		}
	} else {
		b.WriteString("\n### What this means\n\n")
		b.WriteString("This host *answered* a name lookup. Legitimate hosts answer only for their own name; a host answering many names, or any WPAD name, is poisoning the network.\n")
	}
	return b.String()
}

// alertHeading renders "[HIGH] Title" (or just the severity and rule when
// the alert has no title).
func alertHeading(a run.Alert) string {
	title := a.Title
	if title == "" {
		title = a.Rule
	}
	return fmt.Sprintf("[%s] %s", strings.ToUpper(string(a.Severity)), title)
}

// alertsMarkdown renders the Alerts tab.
func alertsMarkdown(alerts []run.Alert) string {
	if len(alerts) == 0 {
		return "## No alerts\n\nNo host has been seen answering name lookups it should not, serving DHCPv6, or serving wpad.dat.\n\n" +
			"Note: LLMNR, NetBIOS and DHCPv6 *responses* are unicast to the victim. On a switched network this sensor only sees responses to its own lookups unless it is on a mirror/SPAN port. mDNS responses are multicast and always visible."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## %d alert(s)\n\nAll detections are passive: nothing was sent to these hosts.\n\n", len(alerts))
	for _, a := range alerts {
		fmt.Fprintf(&b, "### %s %s\n\n", a.SourceIP, alertHeading(a))
		if a.Evidence != "" {
			fmt.Fprintf(&b, "%s\n\n", a.Evidence)
		}
		if len(a.Names) > 0 {
			fmt.Fprintf(&b, "- **Names:** %s\n", strings.Join(a.Names, ", "))
		}
		if a.Count > 0 {
			fmt.Fprintf(&b, "- **Seen:** %d time(s), %s → %s\n", a.Count, fmtBoth(a.FirstSeen), fmtBoth(a.LastSeen))
		}
		if adv := export.AlertAdvice(a); len(adv) > 0 {
			b.WriteString("\n**What to do**\n\n")
			for _, s := range adv {
				fmt.Fprintf(&b, "- %s\n", s)
			}
		}
		b.WriteString("\n---\n\n")
	}
	return b.String()
}

// statusText renders the status bar.
func statusText(state string, iface string, backend string, snap session.Snapshot, elapsed time.Duration) string {
	st := snap.Stats
	var parts []string
	if iface != "" {
		parts = append(parts, fmt.Sprintf("%s on %s (%s)", state, iface, backend))
	} else {
		parts = append(parts, state)
	}
	if elapsed > 0 {
		parts = append(parts, elapsed.Round(time.Second).String())
	}
	parts = append(parts, fmt.Sprintf("packets %s", formatCount(st.Packets)), fmt.Sprintf("hosts %d", st.UniqueHosts))
	var protos []string
	for _, p := range decode.AllProtocols() {
		if n := st.PerProtocol[p]; n > 0 {
			protos = append(protos, fmt.Sprintf("%s %s", p, formatCount(n)))
		}
	}
	if len(protos) > 0 {
		parts = append(parts, strings.Join(protos, " · "))
	}
	if st.Dropped > 0 {
		parts = append(parts, fmt.Sprintf("drops %d", st.Dropped))
	}
	if n := len(snap.Alerts); n > 0 {
		parts = append(parts, fmt.Sprintf("⚠ %d alert(s)", n))
	}
	return strings.Join(parts, "   |   ")
}
