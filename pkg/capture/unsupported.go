//go:build !cgo && !linux && !windows

package capture

// Open is unavailable: this platform needs libpcap, which requires cgo.
func Open(name string, o Options) (Handle, error) { return nil, ErrUnsupported }

// Interfaces enumerates interfaces with the standard library.
func Interfaces() ([]Interface, error) { return netInterfaces() }

// Backend reports the compiled-in capture backend.
func Backend() string { return "none (build with cgo for libpcap)" }
