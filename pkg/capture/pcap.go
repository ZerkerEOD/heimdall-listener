//go:build cgo || windows

package capture

import (
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// libpcap interface flags (pcap.h).
const (
	pcapIfLoopback = 0x1
	pcapIfUp       = 0x2
)

type pcapHandle struct {
	h           *pcap.Handle
	interrupted atomic.Bool
	closeOnce   sync.Once
}

// Open opens name with libpcap/Npcap.
func Open(name string, o Options) (Handle, error) {
	o = o.withDefaults()
	ih, err := pcap.NewInactiveHandle(name)
	if err != nil {
		return nil, wrapOpenError(name, err)
	}
	defer ih.CleanUp()
	if err := ih.SetSnapLen(o.SnapLen); err != nil {
		return nil, wrapOpenError(name, err)
	}
	if err := ih.SetPromisc(o.Promiscuous); err != nil {
		return nil, wrapOpenError(name, err)
	}
	if err := ih.SetTimeout(o.ReadTimeout); err != nil {
		return nil, wrapOpenError(name, err)
	}
	if err := ih.SetImmediateMode(true); err != nil {
		o.warn("immediate mode unavailable: " + err.Error())
	}
	h, err := ih.Activate()
	if err != nil {
		return nil, wrapOpenError(name, err)
	}
	if o.Filter != "" {
		if err := h.SetBPFFilter(o.Filter); err != nil {
			h.Close()
			return nil, wrapOpenError(name, err)
		}
	}
	return &pcapHandle{h: h}, nil
}

func (p *pcapHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if p.interrupted.Load() {
		return nil, gopacket.CaptureInfo{}, ErrClosed
	}
	data, ci, err := p.h.ReadPacketData()
	switch {
	case err == nil:
		return data, ci, nil
	case errors.Is(err, pcap.NextErrorTimeoutExpired):
		if p.interrupted.Load() {
			return nil, ci, ErrClosed
		}
		return nil, ci, ErrTimeout
	case errors.Is(err, io.EOF):
		return nil, ci, ErrClosed
	default:
		return nil, ci, err
	}
}

func (p *pcapHandle) LinkType() layers.LinkType { return p.h.LinkType() }

func (p *pcapHandle) Interrupt() { p.interrupted.Store(true) }

func (p *pcapHandle) Close() error {
	p.closeOnce.Do(p.h.Close)
	return nil
}

func (p *pcapHandle) Stats() (uint64, uint64, error) {
	s, err := p.h.Stats()
	if err != nil {
		return 0, 0, err
	}
	return uint64(s.PacketsReceived), uint64(s.PacketsDropped + s.PacketsIfDropped), nil
}

// Interfaces enumerates devices with libpcap, which on Windows is the only
// way to obtain the \Device\NPF_{GUID} names Npcap expects.
func Interfaces() ([]Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, wrapOpenError("(enumerate)", err)
	}
	out := make([]Interface, 0, len(devs))
	for _, d := range devs {
		i := Interface{Name: d.Name, Description: d.Description,
			Up: d.Flags&pcapIfUp != 0, Loopback: d.Flags&pcapIfLoopback != 0}
		for _, a := range d.Addresses {
			if na, ok := netip.AddrFromSlice(a.IP); ok {
				i.Addrs = append(i.Addrs, na.Unmap())
				if na.IsLoopback() {
					i.Loopback = true
				}
			}
		}
		out = append(out, i)
	}
	return out, nil
}

// Backend reports the compiled-in capture backend.
func Backend() string { return "libpcap (" + pcap.Version() + ")" }
