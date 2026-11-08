package capture

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// DefaultFilter is the libpcap expression used by default. It admits only
// the traffic the decoder understands:
//
//   - LLMNR (udp 5355), mDNS (udp 5353) and NetBIOS-NS (udp 137), both
//     directions so responses (poisoners) are seen as well as queries;
//   - unicast DNS queries (udp dst 53) for WPAD lookups;
//   - DHCPv6 (udp 547, both directions: client Solicit and server Advertise);
//   - HTTP requests (tcp dst 80) for wpad.dat.
const DefaultFilter = "udp port 5355 or udp port 5353 or udp port 137 or udp dst port 53 or udp port 547 or tcp dst port 80"

// udpAnyPorts are matched as either source or destination port.
var udpAnyPorts = []uint32{5355, 5353, 137, 547}

// udpDstPorts are matched as destination port only.
var udpDstPorts = []uint32{53}

// tcpDstPorts are matched as destination port only.
var tcpDstPorts = []uint32{80}

// DefaultProgram returns a classic BPF program for Ethernet frames that is
// equivalent to DefaultFilter. It is used by the pure-Go AF_PACKET backend,
// which cannot compile filter expressions. The equivalence is asserted by a
// cgo-tagged test against libpcap. Limitations: VLAN-tagged frames are only
// matched when the kernel has stripped the tag (AF_PACKET does this), and
// IPv6 extension headers are not traversed.
func DefaultProgram() []bpf.Instruction {
	a := newAssembler()

	const (
		ethType   = 12 // EtherType offset
		ip4Hdr    = 14
		ip4Frag   = ip4Hdr + 6
		ip4Proto  = ip4Hdr + 9
		ip6Next   = ip4Hdr + 6
		ip6L4     = ip4Hdr + 40
		protoTCP  = 6
		protoUDP  = 17
		etherIPv4 = 0x0800
		etherIPv6 = 0x86dd
	)

	a.ins(bpf.LoadAbsolute{Off: ethType, Size: 2})
	a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherIPv6}, "v6", "")
	a.jmp(bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherIPv4}, "drop", "")

	// IPv4: drop non-first fragments (no L4 header), then dispatch on protocol.
	a.ins(bpf.LoadAbsolute{Off: ip4Frag, Size: 2})
	a.jmp(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, "drop", "")
	a.ins(bpf.LoadAbsolute{Off: ip4Proto, Size: 1})
	a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoTCP}, "v4tcp", "")
	a.jmp(bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoUDP}, "drop", "")
	a.ins(bpf.LoadMemShift{Off: ip4Hdr}) // X = IHL*4
	a.ins(bpf.LoadIndirect{Off: ip4Hdr + 0, Size: 2})
	for _, p := range udpAnyPorts {
		a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: p}, "accept", "")
	}
	a.ins(bpf.LoadIndirect{Off: ip4Hdr + 2, Size: 2})
	for _, p := range append(append([]uint32{}, udpAnyPorts...), udpDstPorts...) {
		a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: p}, "accept", "")
	}
	a.jmp(bpf.Jump{}, "drop", "")

	a.label("v4tcp")
	a.ins(bpf.LoadMemShift{Off: ip4Hdr})
	a.ins(bpf.LoadIndirect{Off: ip4Hdr + 2, Size: 2})
	for _, p := range tcpDstPorts {
		a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: p}, "accept", "")
	}
	a.jmp(bpf.Jump{}, "drop", "")

	// IPv6: fixed 40-byte header; next header must be UDP or TCP directly.
	a.label("v6")
	a.ins(bpf.LoadAbsolute{Off: ip6Next, Size: 1})
	a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoTCP}, "v6tcp", "")
	a.jmp(bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoUDP}, "drop", "")
	a.ins(bpf.LoadAbsolute{Off: ip6L4 + 0, Size: 2})
	for _, p := range udpAnyPorts {
		a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: p}, "accept", "")
	}
	a.ins(bpf.LoadAbsolute{Off: ip6L4 + 2, Size: 2})
	for _, p := range append(append([]uint32{}, udpAnyPorts...), udpDstPorts...) {
		a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: p}, "accept", "")
	}
	a.jmp(bpf.Jump{}, "drop", "")

	a.label("v6tcp")
	a.ins(bpf.LoadAbsolute{Off: ip6L4 + 2, Size: 2})
	for _, p := range tcpDstPorts {
		a.jmp(bpf.JumpIf{Cond: bpf.JumpEqual, Val: p}, "accept", "")
	}
	a.jmp(bpf.Jump{}, "drop", "")

	a.label("accept")
	a.ins(bpf.RetConstant{Val: 65535})
	a.label("drop")
	a.ins(bpf.RetConstant{Val: 0})

	prog, err := a.assemble()
	if err != nil {
		panic("capture: DefaultProgram: " + err.Error())
	}
	return prog
}

// assembler resolves symbolic jump targets into BPF skip counts.
type assembler struct {
	items  []asmItem
	labels map[string]int
}

type asmItem struct {
	ins    bpf.Instruction
	jt, jf string
}

func newAssembler() *assembler { return &assembler{labels: map[string]int{}} }

func (a *assembler) ins(i bpf.Instruction) { a.items = append(a.items, asmItem{ins: i}) }

// jmp records a jump whose SkipTrue/SkipFalse (or Jump.Skip) are filled from
// labels. An empty label means "fall through".
func (a *assembler) jmp(i bpf.Instruction, jt, jf string) {
	a.items = append(a.items, asmItem{ins: i, jt: jt, jf: jf})
}

func (a *assembler) label(name string) { a.labels[name] = len(a.items) }

func (a *assembler) assemble() ([]bpf.Instruction, error) {
	out := make([]bpf.Instruction, len(a.items))
	skip := func(from int, label string) (uint8, error) {
		if label == "" {
			return 0, nil
		}
		to, ok := a.labels[label]
		if !ok {
			return 0, fmt.Errorf("unknown label %q", label)
		}
		d := to - (from + 1)
		if d < 0 || d > 255 {
			return 0, fmt.Errorf("jump from %d to %q (%d) out of range", from, label, d)
		}
		return uint8(d), nil
	}
	for idx, it := range a.items {
		switch ins := it.ins.(type) {
		case bpf.JumpIf:
			t, err := skip(idx, it.jt)
			if err != nil {
				return nil, err
			}
			f, err := skip(idx, it.jf)
			if err != nil {
				return nil, err
			}
			ins.SkipTrue, ins.SkipFalse = t, f
			out[idx] = ins
		case bpf.Jump:
			t, err := skip(idx, it.jt)
			if err != nil {
				return nil, err
			}
			ins.Skip = uint32(t)
			out[idx] = ins
		default:
			out[idx] = it.ins
		}
	}
	return out, nil
}
