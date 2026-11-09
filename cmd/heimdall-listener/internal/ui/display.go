package ui

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// DisplayProblem returns a message when the process obviously cannot open a
// window, so the user gets advice instead of a GLFW panic. Empty means "try".
func DisplayProblem() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		if os.Getenv("SUDO_USER") != "" {
			return "No display environment: running under sudo dropped DISPLAY/WAYLAND_DISPLAY.\n\n" + DisplayHint()
		}
		return "No display found (DISPLAY and WAYLAND_DISPLAY are unset).\n\n" +
			"On a headless server use the command-line version instead:\n  heimdall-cli capture -i <interface>\n"
	}
	return ""
}

// DisplayHint explains how to run the GUI with capture rights on Linux
// without starting it as root.
func DisplayHint() string {
	exe, _ := os.Executable()
	var b strings.Builder
	if os.Getenv("SUDO_USER") != "" || os.Geteuid() == 0 {
		b.WriteString("Running a desktop application with sudo usually breaks access to your session's display.\n")
	}
	fmt.Fprintf(&b, "Recommended: grant the binary capture rights once, then run it as your normal user:\n\n")
	fmt.Fprintf(&b, "  sudo setcap cap_net_raw,cap_net_admin+eip %s\n  %s\n\n", exe, exe)
	b.WriteString("Alternatives: on X11, `xhost +SI:localuser:root` then `sudo -E " + exe + "`;\n")
	b.WriteString("on Wayland, `sudo -E env XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR " + exe + "`.\n")
	b.WriteString("To only view a saved run no privileges are needed: " + exe + " run.json\n")
	return b.String()
}
