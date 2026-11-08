//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// DefaultOutDir is where snapshots go when unspecified.
func DefaultOutDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "HeimdallListener")
}

// DefaultLogPath is the default log file location.
func DefaultLogPath(outDir string) string { return filepath.Join(outDir, "heimdall.log") }

// IsService reports whether we were started by the Service Control Manager.
func IsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// handler adapts Run to the SCM protocol.
type handler struct {
	cfg  RunConfig
	log  *slog.Logger
	elog *eventlog.Log
	run  func(context.Context, RunConfig, *slog.Logger) error
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- h.run(ctx, h.cfg, h.log) }()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	h.event("started")
	for {
		select {
		case err := <-errc:
			if err != nil {
				h.event("capture failed: " + err.Error())
				s <- svc.Status{State: svc.StopPending}
				return true, 1
			}
			s <- svc.Status{State: svc.StopPending}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending, WaitHint: 10000}
				cancel()
				select {
				case <-errc:
				case <-time.After(15 * time.Second):
				}
				h.event("stopped")
				return false, 0
			}
		}
	}
}

func (h *handler) event(msg string) {
	if h.elog != nil {
		_ = h.elog.Info(1, "Heimdall Listener: "+msg)
	}
}

// RunAsService hands control to the SCM. It blocks until the service stops.
func RunAsService(name string, cfg RunConfig, logPath string) error {
	log, closeLog, err := NewLogger(logPath, false)
	if err != nil {
		return err
	}
	defer closeLog()
	elog, _ := eventlog.Open(name)
	if elog != nil {
		defer elog.Close()
	}
	return svc.Run(name, &handler{cfg: cfg, log: log, elog: elog, run: Run})
}

// Install registers the Windows service and its event log source.
func Install(cfg InstallConfig) (path string, next []string, err error) {
	cfg = cfg.withDefaults()
	m, err := mgr.Connect()
	if err != nil {
		return "", nil, fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(cfg.Name); err == nil {
		s.Close()
		if !cfg.Force {
			return cfg.Name, nil, fmt.Errorf("service %s already exists (use --force to replace)", cfg.Name)
		}
		if err := removeService(m, cfg.Name); err != nil {
			return cfg.Name, nil, err
		}
	}
	conf := mgr.Config{
		DisplayName:  "Heimdall Listener",
		Description:  "Passive monitor for legacy name-resolution traffic (LLMNR, NetBIOS, mDNS, WPAD, DHCPv6). Never transmits.",
		StartType:    mgr.StartAutomatic,
		Dependencies: []string{"npcap"},
	}
	s, err := m.CreateService(cfg.Name, cfg.ExePath, conf, cfg.Args...)
	if err != nil {
		return cfg.Name, nil, fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)
	if err := eventlog.InstallAsEventCreate(cfg.Name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		if !errors.Is(err, os.ErrExist) {
			_ = s.Delete()
			return cfg.Name, nil, fmt.Errorf("register event log source: %w", err)
		}
	}
	next = []string{"sc start " + cfg.Name, "sc query " + cfg.Name}
	return cfg.Name, next, nil
}

func removeService(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return nil
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err == nil {
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				if st, err := s.Query(); err != nil || st.State == svc.Stopped {
					break
				}
				time.Sleep(300 * time.Millisecond)
			}
		}
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	_ = eventlog.Remove(name)
	return nil
}

// Uninstall stops and deletes the service.
func Uninstall(cfg InstallConfig) (next []string, err error) {
	cfg = cfg.withDefaults()
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	return nil, removeService(m, cfg.Name)
}
