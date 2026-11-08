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

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		code := 1
		if errors.Is(err, capture.ErrPermission) {
			code = 2
			fmt.Fprintln(os.Stderr, privilegeHint())
		}
		os.Exit(code)
	}
}
