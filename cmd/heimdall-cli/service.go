package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZerkerEOD/heimdall-listener/internal/service"
	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
)

type serviceFlags struct {
	ifaces        []string
	outDir        string
	logFile       string
	interval      time.Duration
	retain        int
	rollover      time.Duration
	noPromisc     bool
	filter        string
	trustedDHCPv6 []string
	name          string
	force         bool
	exePath       string
	unitDir       string
}

func addServiceCaptureFlags(cmd *cobra.Command, f *serviceFlags) {
	fl := cmd.Flags()
	fl.StringSliceVarP(&f.ifaces, "interface", "i", nil, "interface to capture on (repeatable)")
	fl.StringVar(&f.outDir, "out-dir", service.DefaultOutDir(), "directory for run-<stamp>.json snapshots and latest.json")
	fl.StringVar(&f.logFile, "log-file", "", "log file (default <out-dir>/heimdall.log)")
	fl.DurationVar(&f.interval, "snapshot-interval", 5*time.Minute, "how often to write a snapshot")
	fl.IntVar(&f.retain, "retain", 48, "snapshots to keep (0 = unlimited)")
	fl.DurationVar(&f.rollover, "rollover", 0, "reset the aggregation after this long (e.g. 24h); 0 = cumulative")
	fl.BoolVar(&f.noPromisc, "no-promisc", false, "do not enable promiscuous mode")
	fl.StringVar(&f.filter, "filter", capture.DefaultFilter, "libpcap filter expression (libpcap backend only)")
	fl.StringSliceVar(&f.trustedDHCPv6, "trusted-dhcpv6", nil, "IPv6 addresses of legitimate DHCPv6 servers")
	_ = cmd.MarkFlagRequired("interface")
}

func (f serviceFlags) runConfig() (service.RunConfig, error) {
	trusted, err := parseTrusted(f.trustedDHCPv6)
	if err != nil {
		return service.RunConfig{}, err
	}
	return service.RunConfig{Interfaces: f.ifaces, OutDir: f.outDir, SnapshotInterval: f.interval, Retain: f.retain,
		Rollover: f.rollover, Promiscuous: !f.noPromisc, Filter: f.filter, TrustedDHCPv6: trusted, Tool: toolInfo()}, nil
}

func (f serviceFlags) logPath() string {
	if f.logFile != "" {
		return f.logFile
	}
	return service.DefaultLogPath(f.outDir)
}

// serviceArgs reproduces the capture flags as a `service run` command line.
func (f serviceFlags) serviceArgs() []string {
	args := []string{"service", "run"}
	for _, i := range f.ifaces {
		args = append(args, "-i", i)
	}
	args = append(args, "--out-dir", f.outDir, "--snapshot-interval", f.interval.String(), "--retain", fmt.Sprint(f.retain))
	if f.rollover > 0 {
		args = append(args, "--rollover", f.rollover.String())
	}
	if f.noPromisc {
		args = append(args, "--no-promisc")
	}
	if f.filter != capture.DefaultFilter {
		args = append(args, "--filter", f.filter)
	}
	if len(f.trustedDHCPv6) > 0 {
		args = append(args, "--trusted-dhcpv6", strings.Join(f.trustedDHCPv6, ","))
	}
	if f.logFile != "" {
		args = append(args, "--log-file", f.logFile)
	}
	return args
}

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Run as a long-lived background service writing periodic snapshots",
		Long: `Service mode keeps capturing and writes a run file snapshot at a fixed interval:
  <out-dir>/run-<UTC stamp>.json   one per interval (pruned to --retain)
  <out-dir>/latest.json            always the most recent snapshot

'service run' is the foreground process (what systemd or the Windows SCM
starts). 'service install' registers it: on Linux it writes a systemd unit
that runs as a dynamic user with only CAP_NET_RAW/CAP_NET_ADMIN; on Windows
it creates an automatic-start service that depends on Npcap.`,
	}
	cmd.AddCommand(newServiceRunCmd(), newServiceInstallCmd(), newServiceUninstallCmd())
	return cmd
}

func newServiceRunCmd() *cobra.Command {
	var f serviceFlags
	cmd := &cobra.Command{
		Use:   "run -i IFACE [--out-dir DIR] [--snapshot-interval 5m]",
		Short: "Run the capture service in the foreground (used by systemd / the Windows SCM)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := f.runConfig()
			if err != nil {
				return err
			}
			if service.IsService() {
				return service.RunAsService(f.name, cfg, f.logPath())
			}
			log, closeLog, err := service.NewLogger(f.logPath(), isTerminal(os.Stderr))
			if err != nil {
				return err
			}
			defer closeLog()
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return service.Run(ctx, cfg, log)
		},
	}
	addServiceCaptureFlags(cmd, &f)
	cmd.Flags().StringVar(&f.name, "name", service.DefaultName, "service name (Windows)")
	return cmd
}

func newServiceInstallCmd() *cobra.Command {
	var f serviceFlags
	cmd := &cobra.Command{
		Use:   "install -i IFACE [--out-dir DIR] [--snapshot-interval 5m]",
		Short: "Register the service (systemd unit on Linux, Windows service on Windows)",
		Example: `  sudo heimdall-cli service install -i eth0
  heimdall-cli service install -i "Ethernet0" --snapshot-interval 15m   (elevated prompt on Windows)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := f.runConfig(); err != nil {
				return err
			}
			exe := f.exePath
			if exe == "" {
				exe, _ = os.Executable()
				exe, _ = filepath.Abs(exe)
			}
			path, next, err := service.Install(service.InstallConfig{Name: f.name, ExePath: exe, Args: f.serviceArgs(), Force: f.force, UnitDir: f.unitDir})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed %s\n", path)
			if len(next) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "next steps:")
				for _, n := range next {
					fmt.Fprintln(cmd.OutOrStdout(), "  "+n)
				}
			}
			return nil
		},
	}
	addServiceCaptureFlags(cmd, &f)
	cmd.Flags().StringVar(&f.name, "name", service.DefaultName, "service / unit name")
	cmd.Flags().BoolVar(&f.force, "force", false, "replace an existing unit/service")
	cmd.Flags().StringVar(&f.exePath, "exe", "", "path to the heimdall-cli binary the service should run (default: this binary)")
	cmd.Flags().StringVar(&f.unitDir, "unit-dir", "", "systemd unit directory (Linux, default /etc/systemd/system)")
	return cmd
}

func newServiceUninstallCmd() *cobra.Command {
	var f serviceFlags
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the service registration (snapshots are kept)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			next, err := service.Uninstall(service.InstallConfig{Name: f.name, UnitDir: f.unitDir})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed service %s\n", f.name)
			for _, n := range next {
				fmt.Fprintln(cmd.OutOrStdout(), "  "+n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&f.name, "name", service.DefaultName, "service / unit name")
	cmd.Flags().StringVar(&f.unitDir, "unit-dir", "", "systemd unit directory (Linux)")
	return cmd
}
