package decode

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func init() {
	// LLMNR, mDNS and NetBIOS-NS all use the DNS wire format but are not
	// registered with gopacket by default.
	layers.RegisterUDPPortLayerType(5355, layers.LayerTypeDNS)
	layers.RegisterUDPPortLayerType(5353, layers.LayerTypeDNS)
	layers.RegisterUDPPortLayerType(137, layers.LayerTypeDNS)
}

// Decoder parses frames into Events. It reuses its layer buffers between
// calls and is therefore not safe for concurrent use: create one per
// capture goroutine.
type Decoder struct {
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	eth     layers.Ethernet
	dot1q   layers.Dot1Q
	sll     layers.LinuxSLL
	sll2    layers.LinuxSLL2
	ip4     layers.IPv4
	ip6     layers.IPv6
	udp     layers.UDP
	tcp     layers.TCP
	dns     layers.DNS
	dhcp    layers.DHCPv6
	payload gopacket.Payload
}

// NewDecoder creates a Decoder for frames of the given link type. Ethernet,
// Linux cooked capture (SLL, SLL2) and raw IP link types are supported;
// anything else is treated as Ethernet. IPv6 extension headers are not
// followed; such packets are ignored.
func NewDecoder(lt layers.LinkType) *Decoder {
	d := &Decoder{}
	var first gopacket.LayerType
	switch lt {
	case layers.LinkTypeLinuxSLL:
		first = layers.LayerTypeLinuxSLL
	case layers.LinkTypeLinuxSLL2:
		first = layers.LayerTypeLinuxSLL2
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		first = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		first = layers.LayerTypeIPv6
	default:
		first = layers.LayerTypeEthernet
	}
	d.parser = gopacket.NewDecodingLayerParser(first,
		&d.eth, &d.dot1q, &d.sll, &d.sll2,
		&d.ip4, &d.ip6,
		&d.udp, &d.tcp, &d.dns, &d.dhcp, &d.payload)
	d.parser.IgnoreUnsupported = true
	d.decoded = make([]gopacket.LayerType, 0, 8)
	return d
}

// Decode parses one frame captured at ts. It returns nil, nil for frames
// that are not relevant (non-IP, other ports, DNS responses with no address
// records, ...). A non-nil error means the frame looked relevant but was
// malformed or truncated; callers should count it and carry on.
func (d *Decoder) Decode(data []byte, ts time.Time) ([]Event, error) {
	d.decoded = d.decoded[:0]
	perr := d.parser.DecodeLayers(data, &d.decoded)

	var haveEth, haveIP4, haveIP6, haveUDP, haveTCP, haveDNS, haveDHCP bool
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeEthernet:
			haveEth = true
		case layers.LayerTypeIPv4:
			haveIP4 = true
		case layers.LayerTypeIPv6:
			haveIP6 = true
		case layers.LayerTypeUDP:
			haveUDP = true
		case layers.LayerTypeTCP:
			haveTCP = true
		case layers.LayerTypeDNS:
			haveDNS = true
		case layers.LayerTypeDHCPv6:
			haveDHCP = true
		}
	}
	if !haveIP4 && !haveIP6 {
		return nil, nil
	}

	base := Event{Time: ts}
	if haveEth {
		base.SrcMAC = d.eth.SrcMAC
	}
	if haveIP4 {
		base.SrcIP, _ = netip.AddrFromSlice(d.ip4.SrcIP)
		base.DstIP, _ = netip.AddrFromSlice(d.ip4.DstIP)
	} else {
		base.SrcIP, _ = netip.AddrFromSlice(d.ip6.SrcIP)
		base.DstIP, _ = netip.AddrFromSlice(d.ip6.DstIP)
	}
	base.SrcIP = base.SrcIP.Unmap()
	base.DstIP = base.DstIP.Unmap()

	switch {
	case haveUDP:
		proto := protocolForPorts(d.udp.SrcPort, d.udp.DstPort)
		if proto == "" {
			return nil, nil
		}
		if perr != nil {
			// Relevant port but the application layer failed to decode.
			return nil, fmt.Errorf("%s from %s: %w", proto, base.SrcIP, perr)
		}
		switch proto {
		case ProtoDHCPv6:
			if !haveDHCP || !haveIP6 {
				return nil, nil
			}
			return d.dhcpv6Event(base), nil
		default:
			if !haveDNS {
				return nil, nil
			}
			return d.dnsEvents(proto, base), nil
		}
	case haveTCP:
		if d.tcp.DstPort != 80 || len(d.tcp.Payload) == 0 {
			return nil, nil
		}
		return httpWPADEvent(d.tcp.Payload, base), nil
	}
	return nil, nil
}

// protocolForPorts maps a UDP port pair to the protocol it carries. The
// destination port is preferred (queries); the source port covers responses
// sent back to an ephemeral port.
func protocolForPorts(src, dst layers.UDPPort) Protocol {
	if p := protocolForPort(dst); p != "" {
		return p
	}
	return protocolForPort(src)
}

func protocolForPort(p layers.UDPPort) Protocol {
	switch p {
	case 5355:
		return ProtoLLMNR
	case 5353:
		return ProtoMDNS
	case 137:
		return ProtoNBNS
	case 53:
		return ProtoDNS
	case 546, 547:
		return ProtoDHCPv6
	}
	return ""
}
