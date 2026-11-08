// Package capture opens network interfaces for passive packet capture.
//
// Two backends exist: libpcap/Npcap via gopacket/pcap (used wherever cgo is
// available and on Windows, where the gopacket fork loads wpcap.dll at run
// time without cgo) and a pure-Go AF_PACKET backend via gopacket/pcapgo on
// Linux when built with CGO_ENABLED=0. The backend is chosen at build time;
// Backend() reports which one is compiled in.
//
// The package never transmits: handles are opened read-only.
package capture

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Handle is an open, read-only capture on one interface.
type Handle interface {
	// ReadPacketData returns the next frame. ErrTimeout means no frame
	// arrived within the read timeout and the caller should retry (after
	// checking for cancellation). ErrClosed means the handle was interrupted
	// or closed and the read loop must exit.
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	// LinkType reports the link-layer type of returned frames.
	LinkType() layers.LinkType
	// Interrupt wakes a blocked read from any goroutine. Subsequent reads
	// return ErrClosed. Safe to call more than once.
	Interrupt()
	// Close releases the handle. Call it from the reader goroutine after the
	// read loop has exited; it is idempotent.
	Close() error
	// Stats returns packets received and dropped by the kernel/driver.
	Stats() (received, dropped uint64, err error)
}

// Options control how an interface is opened.
type Options struct {
	// SnapLen is the maximum bytes captured per frame. 0 means 65535.
	SnapLen int
	// Promiscuous requests promiscuous mode. Broadcast and multicast traffic
	// is received either way; promiscuous mode additionally captures unicast
	// traffic to other hosts (needed on mirror/SPAN ports).
	Promiscuous bool
	// Filter is a libpcap filter expression. Empty disables filtering. The
	// AF_PACKET backend supports only DefaultFilter (or none).
	Filter string
	// ReadTimeout bounds how long a read blocks before returning ErrTimeout
	// (libpcap backend). 0 means 250ms.
	ReadTimeout time.Duration
	// OnWarning, if set, receives non-fatal messages such as "promiscuous
	// mode unavailable".
	OnWarning func(string)
}

// DefaultOptions returns the options both binaries use by default.
func DefaultOptions() Options {
	return Options{SnapLen: 65535, Promiscuous: true, Filter: DefaultFilter, ReadTimeout: 250 * time.Millisecond}
}

func (o Options) withDefaults() Options {
	if o.SnapLen <= 0 {
		o.SnapLen = 65535
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 250 * time.Millisecond
	}
	return o
}

func (o Options) warn(msg string) {
	if o.OnWarning != nil {
		o.OnWarning(msg)
	}
}

// Interface describes a capturable network interface.
type Interface struct {
	// Name is the OS/libpcap device name, e.g. "eth0" or "\Device\NPF_{...}".
	Name string
	// Description is a friendly name where the OS provides one (Windows).
	Description string
	Addrs       []netip.Addr
	Up          bool
	Loopback    bool
}

// DisplayName returns Description when present, otherwise Name.
func (i Interface) DisplayName() string {
	if i.Description != "" {
		return i.Description
	}
	return i.Name
}

// Usable reports whether the interface is a sensible capture target: not
// loopback and carrying at least one non-link-local address.
func (i Interface) Usable() bool {
	if i.Loopback {
		return false
	}
	for _, a := range i.Addrs {
		if !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

var (
	ErrTimeout     = errors.New("capture: read timeout")
	ErrClosed      = errors.New("capture: handle closed")
	ErrUnsupported = errors.New("capture: not supported on this platform/build")
	ErrPermission  = errors.New("capture: insufficient privileges to open interface")
	ErrNoInterface = errors.New("capture: interface not found")
)

// ResolveInterface accepts an interface name or (on Windows) its friendly
// description, case-insensitively, and returns the matching Interface.
func ResolveInterface(nameOrDescription string) (Interface, error) {
	ifs, err := Interfaces()
	if err != nil {
		return Interface{}, err
	}
	want := strings.TrimSpace(nameOrDescription)
	for _, i := range ifs {
		if i.Name == want {
			return i, nil
		}
	}
	for _, i := range ifs {
		if strings.EqualFold(i.Name, want) || strings.EqualFold(i.Description, want) {
			return i, nil
		}
	}
	var partial []Interface
	for _, i := range ifs {
		if i.Description != "" && strings.Contains(strings.ToLower(i.Description), strings.ToLower(want)) {
			partial = append(partial, i)
		}
	}
	if len(partial) == 1 {
		return partial[0], nil
	}
	names := make([]string, 0, len(ifs))
	for _, i := range ifs {
		names = append(names, i.DisplayName())
	}
	return Interface{}, fmt.Errorf("%w: %q (available: %s)", ErrNoInterface, nameOrDescription, strings.Join(names, ", "))
}

// wrapOpenError maps OS permission failures onto ErrPermission so callers
// can print a targeted hint.
func wrapOpenError(name string, err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "permission") || strings.Contains(msg, "not permitted") ||
		strings.Contains(msg, "access is denied") || strings.Contains(msg, "root") {
		return fmt.Errorf("%w (%s): %v", ErrPermission, name, err)
	}
	return fmt.Errorf("capture: open %s: %w", name, err)
}
