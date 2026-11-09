// Command heimdall-cli is the headless Heimdall Listener: it captures legacy
// name-resolution traffic on servers without a GUI, writes run files, and
// compares runs. It never transmits packets.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
)

// Exit statuses beyond the generic 1.
const (
	exitPermission = 2
	exitHighAlert  = 3
)

// exitCodeError carries a specific exit status without printing anything.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		var ec exitCodeError
		if errors.As(err, &ec) {
			os.Exit(ec.code)
		}
		code := 1
		if errors.Is(err, capture.ErrPermission) {
			code = exitPermission
			fmt.Fprintln(os.Stderr, privilegeHint())
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(code)
	}
}
