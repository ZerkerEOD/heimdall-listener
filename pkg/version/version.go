// Package version exposes build information for both binaries.
// Values are injected at build time via -ldflags (see Makefile); when built
// with plain `go build`, Version falls back to the module version recorded by
// the Go toolchain.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set via -ldflags "-X github.com/ZerkerEOD/heimdall-listener/pkg/version.Version=...".
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

const Name = "heimdall-listener"

// String returns a human-readable version line such as
// "heimdall-listener v2.0.0 (abc1234, 2026-11-08) go1.25.0 linux/amd64".
func String() string {
	v := Version
	if v == "" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		} else {
			v = "dev"
		}
	}
	meta := ""
	switch {
	case Commit != "" && Date != "":
		meta = fmt.Sprintf(" (%s, %s)", Commit, Date)
	case Commit != "":
		meta = fmt.Sprintf(" (%s)", Commit)
	}
	return fmt.Sprintf("%s %s%s %s %s/%s", Name, v, meta, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// Short returns just the version string (e.g. "v2.0.0" or "dev").
func Short() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
