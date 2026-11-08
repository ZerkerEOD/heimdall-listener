//go:build linux

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdUnit(t *testing.T) {
	u := SystemdUnit(InstallConfig{ExePath: "/usr/local/bin/heimdall-cli",
		Args: []string{"service", "run", "-i", "eth0", "--out-dir", "/var/lib/heimdall-listener", "--filter", "udp port 5355"}})
	for _, want := range []string{
		`ExecStart=/usr/local/bin/heimdall-cli service run -i eth0 --out-dir /var/lib/heimdall-listener --filter "udp port 5355"`,
		"AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN",
		"DynamicUser=yes",
		"StateDirectory=heimdall-listener",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q:\n%s", want, u)
		}
	}
}

func TestInstallUninstallUnit(t *testing.T) {
	dir := t.TempDir()
	cfg := InstallConfig{UnitDir: dir, ExePath: "/opt/heimdall-cli", Args: []string{"service", "run", "-i", "eth0"}}
	path, next, err := Install(cfg)
	if err != nil || len(next) == 0 || filepath.Base(path) != "heimdall-listener.service" {
		t.Fatalf("install: %v %v %s", err, next, path)
	}
	if _, _, err := Install(cfg); err == nil {
		t.Fatal("second install without --force must fail")
	}
	cfg.Force = true
	if _, _, err := Install(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unit not removed")
	}
	if _, err := Uninstall(cfg); err != nil {
		t.Fatal("uninstall must be idempotent")
	}
}
