// Package service runs Heimdall Listener as a long-lived background process
// that writes periodic run-file snapshots, and installs it as a systemd
// unit (Linux) or Windows service.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
	"github.com/ZerkerEOD/heimdall-listener/pkg/session"
)

// DefaultName is the service/unit name.
const DefaultName = "heimdall-listener"

// RunConfig configures the background runner.
type RunConfig struct {
	Interfaces       []string
	OutDir           string
	SnapshotInterval time.Duration // default 5m
	Retain           int           // snapshots to keep; 0 = unlimited
	Rollover         time.Duration // reset aggregation after this long; 0 = cumulative
	Promiscuous      bool
	Filter           string
	TrustedDHCPv6    []netip.Addr
	Tool             run.ToolInfo
}

func (c RunConfig) withDefaults() RunConfig {
	if c.SnapshotInterval <= 0 {
		c.SnapshotInterval = 5 * time.Minute
	}
	if c.OutDir == "" {
		c.OutDir = DefaultOutDir()
	}
	if c.Filter == "" {
		c.Filter = capture.DefaultFilter
	}
	return c
}

// Run captures until ctx is cancelled, writing run-<stamp>.json snapshots
// and latest.json into OutDir. A final snapshot is written on shutdown.
func Run(ctx context.Context, cfg RunConfig, log *slog.Logger) error {
	cfg = cfg.withDefaults()
	if len(cfg.Interfaces) == 0 {
		return errors.New("service: no interfaces configured")
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return fmt.Errorf("service: create %s: %w", cfg.OutDir, err)
	}

	agg := session.NewAggregator(session.Options{TrustedDHCPv6: cfg.TrustedDHCPv6})
	opts := capture.DefaultOptions()
	opts.Promiscuous = cfg.Promiscuous
	opts.Filter = cfg.Filter
	opts.OnWarning = func(msg string) { log.Warn(msg) }

	var sessions []*session.Session
	stopAll := func() {
		for _, s := range sessions {
			_ = s.Stop()
		}
	}
	sessionDone := make(chan *session.Session, len(cfg.Interfaces))
	for _, name := range cfg.Interfaces {
		s, err := session.Start(ctx, session.Config{Interface: name, Capture: opts,
			OnError: func(error) {}}, agg)
		if err != nil {
			stopAll()
			return err
		}
		sessions = append(sessions, s)
		go func(s *session.Session) { <-s.Done(); sessionDone <- s }(s)
	}
	log.Info("capture started", "interfaces", strings.Join(cfg.Interfaces, ","), "backend", capture.Backend(),
		"out_dir", cfg.OutDir, "snapshot_interval", cfg.SnapshotInterval.String(), "rollover", cfg.Rollover.String())

	snapshot := func(reason string) {
		snap := agg.Snapshot()
		r := snap.ToRun(cfg.Tool, session.CaptureInfo(sessions, snap))
		path, err := WriteSnapshot(cfg.OutDir, r, cfg.Retain)
		if err != nil {
			log.Error("snapshot failed", "err", err)
			return
		}
		log.Info("snapshot written", "reason", reason, "path", path, "entries", len(r.Entries), "alerts", len(r.Alerts),
			"packets", r.Capture.PacketsSeen, "hosts", len(r.Hosts()))
	}

	tick := time.NewTicker(cfg.SnapshotInterval)
	defer tick.Stop()
	var rollover <-chan time.Time
	var rollTicker *time.Ticker
	if cfg.Rollover > 0 {
		rollTicker = time.NewTicker(cfg.Rollover)
		defer rollTicker.Stop()
		rollover = rollTicker.C
	}

	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case s := <-sessionDone:
			if err := s.Err(); err != nil {
				runErr = err
				log.Error("capture ended unexpectedly", "interface", s.Interface(), "err", err)
			} else {
				log.Warn("capture ended", "interface", s.Interface())
			}
			break loop
		case <-tick.C:
			snapshot("interval")
		case <-rollover:
			snapshot("rollover")
			agg.Reset()
			log.Info("aggregation reset (rollover)")
		}
	}
	stopAll()
	snapshot("shutdown")
	log.Info("capture stopped")
	return runErr
}

// WriteSnapshot writes r as run-<UTC stamp>.json plus latest.json in dir and
// prunes old snapshots beyond retain (0 keeps all). It returns the snapshot path.
func WriteSnapshot(dir string, r *run.Run, retain int) (string, error) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	path := filepath.Join(dir, "run-"+stamp+".json")
	if err := run.Save(path, r); err != nil {
		return "", err
	}
	if err := run.Save(filepath.Join(dir, "latest.json"), r); err != nil {
		return path, err
	}
	if retain > 0 {
		if err := Prune(dir, retain); err != nil {
			return path, err
		}
	}
	return path, nil
}

// Prune deletes the oldest run-*.json files so at most retain remain.
func Prune(dir string, retain int) error {
	matches, err := filepath.Glob(filepath.Join(dir, "run-*.json"))
	if err != nil {
		return err
	}
	sort.Strings(matches) // UTC stamps sort chronologically
	if len(matches) <= retain {
		return nil
	}
	var errs []string
	for _, old := range matches[:len(matches)-retain] {
		if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("prune: %s", strings.Join(errs, "; "))
	}
	return nil
}

// NewLogger logs to the file at path (created if needed) and, when echo is
// set, also to stderr.
func NewLogger(path string, echo bool) (*slog.Logger, func(), error) {
	var writers []slog.Handler
	closeFn := func() {}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, err
		}
		closeFn = func() { _ = f.Close() }
		writers = append(writers, slog.NewTextHandler(f, nil))
	}
	if echo || len(writers) == 0 {
		writers = append(writers, slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(multiHandler(writers)), closeFn, nil
}

type multiHandler []slog.Handler

func (m multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for _, h := range m {
		if err := h.Handle(ctx, r.Clone()); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithGroup(name)
	}
	return out
}

// InstallConfig describes the service to register.
type InstallConfig struct {
	Name    string
	ExePath string
	Args    []string // arguments after the executable, e.g. service run -i eth0 ...
	Force   bool     // overwrite an existing unit/service
	UnitDir string   // Linux: systemd unit directory (default /etc/systemd/system)
}

func (c InstallConfig) withDefaults() InstallConfig {
	if c.Name == "" {
		c.Name = DefaultName
	}
	if c.ExePath == "" {
		c.ExePath, _ = os.Executable()
	}
	if c.UnitDir == "" {
		c.UnitDir = "/etc/systemd/system"
	}
	return c
}
