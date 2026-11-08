//go:build linux

package capture

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/bpf"
)

type afHandle struct {
	h         *pcapgo.EthernetHandle
	closed    atomic.Bool
	closeOnce sync.Once
}

// openAFPacket opens name with a raw AF_PACKET socket (pure Go).
func openAFPacket(name string, o Options) (Handle, error) {
	o = o.withDefaults()
	h, err := pcapgo.NewEthernetHandle(name)
	if err != nil {
		return nil, wrapOpenError(name, err)
	}
	if err := h.SetCaptureLength(o.SnapLen); err != nil {
		h.Close()
		return nil, wrapOpenError(name, err)
	}
	if o.Promiscuous {
		if err := h.SetPromiscuous(true); err != nil {
			o.warn(fmt.Sprintf("promiscuous mode unavailable on %s (%v); broadcast and multicast traffic is still captured", name, err))
		}
	}
	switch o.Filter {
	case "":
		// no filter
	case DefaultFilter:
		raw, err := bpf.Assemble(DefaultProgram())
		if err != nil {
			h.Close()
			return nil, fmt.Errorf("capture: assemble filter: %w", err)
		}
		if err := h.SetBPF(raw); err != nil {
			h.Close()
			return nil, wrapOpenError(name, err)
		}
	default:
		h.Close()
		return nil, fmt.Errorf("%w: custom filter expressions require the libpcap backend", ErrUnsupported)
	}
	return &afHandle{h: h}, nil
}

func (a *afHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if a.closed.Load() {
		return nil, gopacket.CaptureInfo{}, ErrClosed
	}
	data, ci, err := a.h.ReadPacketData()
	if err == nil {
		return data, ci, nil
	}
	if a.closed.Load() || errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EBADF) {
		return nil, ci, ErrClosed
	}
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
		return nil, ci, ErrTimeout
	}
	return nil, ci, err
}

func (a *afHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

// Interrupt closes the socket, which unblocks a pending read.
func (a *afHandle) Interrupt() {
	a.closed.Store(true)
	a.closeOnce.Do(func() { _ = a.h.Close() })
}

func (a *afHandle) Close() error {
	a.closed.Store(true)
	a.closeOnce.Do(func() { _ = a.h.Close() })
	return nil
}

func (a *afHandle) Stats() (uint64, uint64, error) {
	s, err := a.h.Stats()
	if err != nil {
		return 0, 0, err
	}
	return uint64(s.Packets), uint64(s.Drops), nil
}
