package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
	"github.com/ZerkerEOD/heimdall-listener/pkg/version"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "heimdall-cli",
		Short: "Passive listener for legacy name-resolution traffic (LLMNR, NetBIOS, mDNS, WPAD, DHCPv6)",
		Long: `heimdall-cli passively captures the broadcast and multicast traffic that
Responder, Inveigh, mitm6 and ntlmrelayx abuse, and reports which hosts emit
it so you can turn the protocols off. It never sends a packet.

Typical workflow:
  heimdall-cli interfaces
  heimdall-cli capture -i eth0 -d 30m -o baseline.json --summary baseline.txt
  ... remediate ...
  heimdall-cli capture -i eth0 -d 30m -o after.json
  heimdall-cli diff baseline.json after.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newInterfacesCmd(), newCaptureCmd(), newDiffCmd(), newExportCmd(), newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and capture backend",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
			fmt.Fprintln(cmd.OutOrStdout(), "capture backend:", capture.Backend())
		},
	}
}

// privilegeHint explains how to obtain capture rights on this OS.
func privilegeHint() string {
	switch runtime.GOOS {
	case "linux":
		exe, _ := os.Executable()
		return fmt.Sprintf("Capturing needs CAP_NET_RAW. Either run with sudo, or grant it once:\n  sudo setcap cap_net_raw,cap_net_admin+eip %s", exe)
	case "windows":
		return "Capturing needs an elevated (Administrator) prompt and Npcap installed (https://npcap.com)."
	case "darwin":
		return "Capturing needs root: run with sudo (or install Wireshark's ChmodBPF to allow your user)."
	default:
		return "Capturing needs elevated privileges on this platform."
	}
}

// isTerminal reports whether f is attached to a character device.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
