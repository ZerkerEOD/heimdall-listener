//go:build linux && !cgo

package capture

// Open opens name with the pure-Go AF_PACKET backend.
func Open(name string, o Options) (Handle, error) { return openAFPacket(name, o) }

// Interfaces enumerates interfaces with the standard library.
func Interfaces() ([]Interface, error) { return netInterfaces() }

// Backend reports the compiled-in capture backend.
func Backend() string { return "AF_PACKET (pure Go)" }
