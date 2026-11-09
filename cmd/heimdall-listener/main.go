// Command heimdall-listener is the desktop GUI for Heimdall Listener. The
// headless equivalent is cmd/heimdall-cli; both share the pkg/ core.
package main

import (
	"fmt"
	"os"

	"github.com/ZerkerEOD/heimdall-listener/cmd/heimdall-listener/internal/ui"
)

func main() {
	if msg := ui.DisplayProblem(); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	defer func() {
		// Fyne panics when no window system is reachable; turn that into
		// actionable advice instead of a stack trace.
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Heimdall Listener could not open a window: %v\n\n%s\n", r, ui.DisplayHint())
			os.Exit(1)
		}
	}()
	ui.Run(os.Args[1:])
}
