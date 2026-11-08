//go:build !linux && !windows

package service

import (
	"errors"
	"path/filepath"
)

// DefaultOutDir is where snapshots go when unspecified.
func DefaultOutDir() string { return "/var/lib/" + DefaultName }

// DefaultLogPath is the default log file location.
func DefaultLogPath(outDir string) string { return filepath.Join(outDir, "heimdall.log") }

// IsService is always false on platforms without service integration.
func IsService() bool { return false }

// RunAsService is not supported here.
func RunAsService(string, RunConfig, string) error {
	return errors.New("service mode is supported on Linux (systemd) and Windows only")
}

// Install is not supported here.
func Install(InstallConfig) (string, []string, error) {
	return "", nil, errors.New("service install is supported on Linux (systemd) and Windows only")
}

// Uninstall is not supported here.
func Uninstall(InstallConfig) ([]string, error) {
	return nil, errors.New("service uninstall is supported on Linux (systemd) and Windows only")
}
