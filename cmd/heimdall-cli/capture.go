package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/export"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
	"github.com/ZerkerEOD/heimdall-listener/pkg/session"
)

type captureFlags struct {
	ifaces        []string
	duration      time.Duration
	out           outputSpec
	quiet         bool
	jsonl         bool
	noPromisc     bool
	filter        string
	trustedDHCPv6 []string
	statusEvery   time.Duration
}

func newCaptureCmd() *cobra.Command {
	var f captureFlags
	cmd := &cobra.Command{
		Use:   "capture -i IFACE [-i IFACE...] [-d DURATION] [-o run.json]",
		Short: "Capture legacy name-resolution traffic until Ctrl-C or a duration elapses",
		Long: `Capture passively listens on one or more interfaces and aggregates what it
sees per source host. On an interactive terminal a live table is shown;
otherwise a status line is logged periodically. When the capture ends
(duration elapsed, Ctrl-C or SIGTERM) the requested files are written and a
summary is printed.

Nothing is ever transmitted. Promiscuous mode is enabled by default so that
mirror/SPAN ports work; broadcast and multicast are received either way.`,
		Example: `  heimdall-cli capture -i eth0
  heimdall-cli capture -i eth0 -d 1h -o baseline.json --summary baseline.txt
  heimdall-cli capture -i "Ethernet 2" -d 30m -o run.json        (Windows friendly name)
  heimdall-cli capture -i eth0 --jsonl --quiet | tee events.jsonl`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCapture(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringSliceVarP(&f.ifaces, "interface", "i", nil, "interface to capture on (repeatable); name or Windows description")
	fl.DurationVarP(&f.duration, "duration", "d", 0, "stop after this long (e.g. 30m, 2h); 0 = until Ctrl-C")
	fl.StringVarP(&f.out.runPath, "output", "o", "", "write the run file (JSON) here; used by 'diff' and the GUI")
	fl.StringVar(&f.out.csvPath, "csv", "", "write aggregated entries as CSV")
	fl.StringVar(&f.out.summaryPath, "summary", "", "write the per-host remediation report (text)")
	fl.StringVar(&f.out.summaryCSVPath, "summary-csv", "", "write the per-host summary as CSV")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "no live table or status lines; only errors and 'wrote ...' notices")
	fl.BoolVar(&f.jsonl, "jsonl", false, "stream one JSON object per event to stdout (implies no live table)")
	fl.BoolVar(&f.noPromisc, "no-promisc", false, "do not enable promiscuous mode")
	fl.StringVar(&f.filter, "filter", capture.DefaultFilter, "libpcap filter expression (libpcap backend only)")
	fl.StringSliceVar(&f.trustedDHCPv6, "trusted-dhcpv6", nil, "IPv6 addresses of legitimate DHCPv6 servers (suppresses alerts)")
	fl.DurationVar(&f.statusEvery, "status-every", 60*time.Second, "interval for status lines when not on a terminal")
	_ = cmd.MarkFlagRequired("interface")
	return cmd
}

func parseTrusted(ss []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range ss {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("--trusted-dhcpv6 %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func captureOptions(f captureFlags, warn func(string)) capture.Options {
	o := capture.DefaultOptions()
	o.Promiscuous = !f.noPromisc
	o.Filter = f.filter
	o.OnWarning = warn
	return o
}

// startSessions resolves and opens every interface; on any failure the ones
// already opened are stopped.
func startSessions(ctx context.Context, names []string, opts capture.Options, agg *session.Aggregator, onEvent func(decode.Event), onError func(error)) ([]*session.Session, error) {
	var sessions []*session.Session
	for _, name := range names {
		iface, err := capture.ResolveInterface(name)
		if err != nil {
			// Fall back to the literal name: ResolveInterface needs enumeration,
			// which can fail where opening still works.
			iface = capture.Interface{Name: name}
		}
		s, err := session.Start(ctx, session.Config{Interface: iface.Name, Capture: opts, OnEvent: onEvent, OnError: onError}, agg)
		if err != nil {
			for _, prev := range sessions {
				_ = prev.Stop()
			}
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

func runCapture(cmd *cobra.Command, f captureFlags) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	trusted, err := parseTrusted(f.trustedDHCPv6)
	if err != nil {
		return err
	}
	warn := func(msg string) { fmt.Fprintln(stderr, "warning:", msg) }

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if f.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.duration)
		defer cancel()
	}

	agg := session.NewAggregator(session.Options{TrustedDHCPv6: trusted})

	var jl *jsonlWriter
	var onEvent func(decode.Event)
	if f.jsonl {
		jl = newJSONLWriter(stdout)
		onEvent = jl.Push
	}
	var decodeErrs uint64
	onError := func(error) { decodeErrs++ }

	sessions, err := startSessions(ctx, f.ifaces, captureOptions(f, warn), agg, onEvent, onError)
	if err != nil {
		return err
	}
	names := make([]string, len(sessions))
	for i, s := range sessions {
		names[i] = s.Interface()
	}

	interactive := !f.quiet && !f.jsonl && isTerminal(os.Stdout) && stdout == os.Stdout
	if !f.quiet && !interactive {
		fmt.Fprintf(stderr, "capturing on %s via %s; press Ctrl-C to stop\n", strings.Join(names, ","), capture.Backend())
	}

	view := &liveView{w: stdout, ifaces: names, backend: capture.Backend(), maxRows: 40}
	refresh := time.NewTicker(time.Second)
	defer refresh.Stop()
	status := time.NewTicker(f.statusEvery)
	defer status.Stop()

	// Any session ending unexpectedly (device removed) ends the capture.
	sessionDone := make(chan *session.Session, len(sessions))
	for _, s := range sessions {
		go func(s *session.Session) { <-s.Done(); sessionDone <- s }(s)
	}

	if interactive {
		view.render(agg.Snapshot(), true)
	}
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case s := <-sessionDone:
			if e := s.Err(); e != nil {
				runErr = e
				break loop
			}
		case <-refresh.C:
			if interactive {
				view.render(agg.Snapshot(), false)
			}
		case <-status.C:
			if !interactive && !f.quiet {
				fmt.Fprintln(stderr, statusLine(agg.Snapshot()))
			}
		}
	}
	stop()
	for _, s := range sessions {
		if e := s.Stop(); e != nil && runErr == nil && !errors.Is(e, context.Canceled) {
			runErr = e
		}
	}
	if jl != nil {
		if n := jl.Close(); n > 0 {
			fmt.Fprintf(stderr, "warning: %d event line(s) dropped (stdout too slow)\n", n)
		}
	}

	snap := agg.Snapshot()
	r := snap.ToRun(toolInfo(), session.CaptureInfo(sessions, snap))

	if interactive {
		fmt.Fprint(stdout, clearScreen)
	}
	if !f.quiet && !f.jsonl {
		if err := export.WriteSummaryText(stdout, r); err != nil {
			return err
		}
	} else if !f.quiet {
		printShortSummary(stderr, r)
	}
	if err := f.out.write(r, stderr); err != nil {
		return err
	}
	if !f.out.any() && !f.quiet && !f.jsonl {
		fmt.Fprintln(stderr, "tip: pass -o run.json to save this run for 'heimdall-cli diff' or the GUI")
	}
	return runErr
}

func printShortSummary(w interface{ Write([]byte) (int, error) }, r *run.Run) {
	fmt.Fprintf(w, "capture finished: %d packets, %d events, %d hosts, %d entries, %d alerts\n",
		r.Capture.PacketsSeen, r.Capture.EventsSeen, len(r.Hosts()), len(r.Entries), len(r.Alerts))
}
