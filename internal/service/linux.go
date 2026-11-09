//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultOutDir is where snapshots go when unspecified.
func DefaultOutDir() string { return "/var/lib/" + DefaultName }

// DefaultLogPath is the default log file location.
func DefaultLogPath(outDir string) string { return filepath.Join(outDir, "heimdall.log") }

// SystemdUnit renders the unit file. The service runs as a dynamic user with
// only the capabilities packet capture needs.
func SystemdUnit(cfg InstallConfig) string {
	cfg = cfg.withDefaults()
	exec := shellQuote(cfg.ExePath)
	for _, a := range cfg.Args {
		exec += " " + shellQuote(a)
	}
	return fmt.Sprintf(`[Unit]
Description=Heimdall Listener - passive legacy name-resolution monitor
Documentation=https://github.com/ZerkerEOD/heimdall-listener
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5
DynamicUser=yes
StateDirectory=%s
StateDirectoryMode=0750
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_PACKET AF_NETLINK AF_UNIX AF_INET AF_INET6
LockPersonality=yes

[Install]
WantedBy=multi-user.target
`, exec, cfg.Name)
}

// shellQuote quotes a systemd ExecStart argument when needed.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Install writes the systemd unit and returns its path plus the commands
// the operator still has to run.
func Install(cfg InstallConfig) (path string, next []string, err error) {
	cfg = cfg.withDefaults()
	path = filepath.Join(cfg.UnitDir, cfg.Name+".service")
	if _, statErr := os.Stat(path); statErr == nil && !cfg.Force {
		return path, nil, fmt.Errorf("%s already exists (use --force to overwrite)", path)
	}
	if err := os.WriteFile(path, []byte(SystemdUnit(cfg)), 0o644); err != nil {
		return path, nil, err
	}
	next = []string{
		"systemctl daemon-reload",
		"systemctl enable --now " + cfg.Name,
		"systemctl status " + cfg.Name,
	}
	return path, next, nil
}

// Uninstall removes the unit file.
func Uninstall(cfg InstallConfig) (next []string, err error) {
	cfg = cfg.withDefaults()
	path := filepath.Join(cfg.UnitDir, cfg.Name+".service")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return []string{"systemctl disable --now " + cfg.Name, "systemctl daemon-reload"}, nil
}

// IsService reports whether the process was started by the service manager.
// systemd needs no special handling: Run is used as-is.
func IsService() bool { return false }

// RunAsService is a no-op on Linux: systemd runs the foreground command.
func RunAsService(name string, cfg RunConfig, logPath string) error {
	return errors.New("service: RunAsService is Windows-only")
}
