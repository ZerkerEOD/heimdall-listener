// Command heimdall-listener is the desktop GUI for Heimdall Listener. The
// headless equivalent is cmd/heimdall-cli; both share the pkg/ core.
package main

import (
	"os"

	"github.com/ZerkerEOD/heimdall-listener/cmd/heimdall-listener/internal/ui"
)

func main() {
	ui.Run(os.Args[1:])
}
