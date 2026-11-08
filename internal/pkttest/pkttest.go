// Package pkttest builds synthetic frames for tests across packages.
// It is test support code and must not be imported by production code.
package pkttest

import (
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
)

var (
	MACA = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	MACB = net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}

	Host4   = netip.MustParseAddr("192.168.1.10")
	Other4  = netip.MustParseAddr("192.168.1.20")
	Bcast4  = netip.MustParseAddr("192.168.1.255")
	LLMNR4  = netip.MustParseAddr("224.0.0.252")
	MDNS4   = netip.MustParseAddr("224.0.0.251")
	DNSSrv4 = netip.MustParseAddr("192.168.1.1")

	Host6    = netip.MustParseAddr("fe80::1")
	Other6   = netip.MustParseAddr("fe80::2")
	LLMNR6   = netip.MustParseAddr("ff02::1:3")
	MDNS6    = netip.MustParseAddr("ff02::fb")
	DHCPv6MA = netip.MustParseAddr("ff02::1:2")
)

// Frame serialises Ethernet(+optional 802.1Q) + IPv4/IPv6 + l4 + payload.
func Frame(src, dst netip.Addr, l4 gopacket.SerializableLayer, payload []byte, vlan uint16) []byte {
	eth := &layers.Ethernet{SrcMAC: MACA, DstMAC: MACB}
	var (
		ip      gopacket.NetworkLayer
		stk     []gopacket.SerializableLayer
		etyp    layers.EthernetType
		ipProto layers.IPProtocol
	)
	switch l4.(type) {
	case *layers.UDP:
		ipProto = layers.IPProtocolUDP
	case *layers.TCP:
		ipProto = layers.IPProtocolTCP
	default:
		panic("pkttest: unsupported transport layer")
	}
	if src.Is4() {
		etyp = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: ipProto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		ip = ip4
		stk = append(stk, ip4)
	} else {
		etyp = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{Version: 6, HopLimit: 255, NextHeader: ipProto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		ip = ip6
		stk = append(stk, ip6)
	}
	if vlan != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stk = append([]gopacket.SerializableLayer{eth, &layers.Dot1Q{VLANIdentifier: vlan, Type: etyp}}, stk...)
	} else {
		eth.EthernetType = etyp
		stk = append([]gopacket.SerializableLayer{eth}, stk...)
	}
	switch l := l4.(type) {
	case *layers.UDP:
		_ = l.SetNetworkLayerForChecksum(ip)
	case *layers.TCP:
		_ = l.SetNetworkLayerForChecksum(ip)
	}
	stk = append(stk, l4, gopacket.Payload(payload))
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stk...); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// UDP builds an untagged UDP frame.
func UDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	return Frame(src, dst, &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}, payload, 0)
}

// TCP builds an untagged TCP PSH/ACK frame carrying payload.
func TCP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	return Frame(src, dst, &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), PSH: true, ACK: true, Seq: 1, Window: 1024}, payload, 0)
}

// IPv4Fragment builds a non-first IPv4 UDP fragment (offset > 0).
func IPv4Fragment(src, dst netip.Addr) []byte {
	ip4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src.AsSlice(), DstIP: dst.AsSlice(), FragOffset: 185, Id: 7}
	eth := &layers.Ethernet{SrcMAC: MACA, DstMAC: MACB, EthernetType: layers.EthernetTypeIPv4}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip4, gopacket.Payload(make([]byte, 32))); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// ARP builds a minimal ARP request frame.
func ARP() []byte {
	eth := &layers.Ethernet{SrcMAC: MACA, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: MACA, SourceProtAddress: Host4.AsSlice(), DstHwAddress: make([]byte, 6), DstProtAddress: Other4.AsSlice()}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// DNSQuery serialises a single-question DNS message.
func DNSQuery(id uint16, name string, qtype layers.DNSType, class layers.DNSClass) []byte {
	return serializeDNS(&layers.DNS{ID: id, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: qtype, Class: class}}})
}

// DNSResponse serialises an authoritative response with A/AAAA answers.
func DNSResponse(id uint16, name string, addrs ...netip.Addr) []byte {
	d := &layers.DNS{ID: id, QR: true, AA: true, OpCode: layers.DNSOpCodeQuery}
	for _, a := range addrs {
		rr := layers.DNSResourceRecord{Name: []byte(name), Class: layers.DNSClassIN, TTL: 30, IP: a.AsSlice(), Type: layers.DNSTypeA}
		if a.Is6() {
			rr.Type = layers.DNSTypeAAAA
		}
		d.Answers = append(d.Answers, rr)
	}
	return serializeDNS(d)
}

func serializeDNS(d *layers.DNS) []byte {
	buf := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// NBNSQuery builds a NetBIOS name query (opcode 0, type NB) for name<suffix>.
func NBNSQuery(id uint16, name string, suffix byte) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0110) // RD + B
	binary.BigEndian.PutUint16(b[4:], 1)
	b = append(b, 0x20)
	b = append(b, decode.EncodeNetBIOSName(name, suffix)...)
	b = append(b, 0x00, 0x00, 0x20, 0x00, 0x01)
	return b
}

// NBNSResponse builds a positive name query response.
func NBNSResponse(id uint16, name string, suffix byte, addrs ...netip.Addr) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x8500)
	binary.BigEndian.PutUint16(b[6:], 1)
	b = append(b, 0x20)
	b = append(b, decode.EncodeNetBIOSName(name, suffix)...)
	b = append(b, 0x00, 0x00, 0x20, 0x00, 0x01)
	b = binary.BigEndian.AppendUint32(b, 300000)
	b = binary.BigEndian.AppendUint16(b, uint16(6*len(addrs)))
	for _, a := range addrs {
		b = append(b, 0x00, 0x00)
		b = append(b, a.AsSlice()...)
	}
	return b
}

// DHCPv6 serialises a DHCPv6 message with a client ID and optional options.
func DHCPv6(mt layers.DHCPv6MsgType, extra ...layers.DHCPv6Option) []byte {
	m := &layers.DHCPv6{MsgType: mt, TransactionID: []byte{0x01, 0x02, 0x03}}
	m.Options = append(m.Options, layers.NewDHCPv6Option(layers.DHCPv6OptClientID, []byte{0, 1, 0, 1, 0xde, 0xad, 0xbe, 0xef, 0, 0x11, 0x22, 0x33, 0x44, 0x55}))
	m.Options = append(m.Options, extra...)
	buf := gopacket.NewSerializeBuffer()
	if err := m.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// Corpus is a labelled set of frames with the expected filter verdict.
type Sample struct {
	Name   string
	Frame  []byte
	Accept bool
}

// Corpus returns frames covering every protocol the capture filter must
// pass, plus traffic it must drop.
func Corpus() []Sample {
	return []Sample{
		{"llmnr-query-v4", UDP(Host4, LLMNR4, 51000, 5355, DNSQuery(1, "wpad", layers.DNSTypeA, layers.DNSClassIN)), true},
		{"llmnr-query-v6", UDP(Host6, LLMNR6, 51000, 5355, DNSQuery(1, "wpad", layers.DNSTypeAAAA, layers.DNSClassIN)), true},
		{"llmnr-response-v4", UDP(Other4, Host4, 5355, 51000, DNSResponse(1, "wpad", Other4)), true},
		{"llmnr-response-v6", UDP(Other6, Host6, 5355, 51000, DNSResponse(1, "wpad", Other6)), true},
		{"mdns-query-v4", UDP(Host4, MDNS4, 5353, 5353, DNSQuery(0, "printer.local", layers.DNSTypePTR, layers.DNSClassIN)), true},
		{"mdns-query-v6", UDP(Host6, MDNS6, 5353, 5353, DNSQuery(0, "printer.local", layers.DNSTypePTR, layers.DNSClassIN)), true},
		{"nbns-query", UDP(Host4, Bcast4, 137, 137, NBNSQuery(1, "FILESRV", 0x20)), true},
		{"nbns-response", UDP(Other4, Host4, 137, 137, NBNSResponse(1, "FILESRV", 0x20, Other4)), true},
		{"dns-query", UDP(Host4, DNSSrv4, 40000, 53, DNSQuery(7, "wpad.corp.local", layers.DNSTypeA, layers.DNSClassIN)), true},
		{"dns-response-dropped", UDP(DNSSrv4, Host4, 53, 40000, DNSResponse(7, "wpad.corp.local", Other4)), false},
		{"dhcpv6-solicit", UDP(Host6, DHCPv6MA, 546, 547, DHCPv6(layers.DHCPv6MsgTypeSolicit)), true},
		{"dhcpv6-advertise", UDP(Other6, Host6, 547, 546, DHCPv6(layers.DHCPv6MsgTypeAdvertise)), true},
		{"http-wpad", TCP(Host4, Other4, 50000, 80, []byte("GET /wpad.dat HTTP/1.1\r\nHost: wpad\r\n\r\n")), true},
		{"http-other-port-dropped", TCP(Host4, Other4, 50000, 8080, []byte("GET /wpad.dat HTTP/1.1\r\nHost: wpad\r\n\r\n")), false},
		{"https-dropped", TCP(Host4, Other4, 50000, 443, []byte{0x16, 0x03, 0x01}), false},
		{"ntp-dropped", UDP(Host4, Other4, 123, 123, make([]byte, 48)), false},
		{"ssdp-dropped", UDP(Host4, netip.MustParseAddr("239.255.255.250"), 1900, 1900, []byte("M-SEARCH * HTTP/1.1\r\n")), false},
		{"ipv4-fragment-dropped", IPv4Fragment(Host4, LLMNR4), false},
		{"arp-dropped", ARP(), false},
		{"vlan-llmnr", Frame(Host4, LLMNR4, &layers.UDP{SrcPort: 51000, DstPort: 5355}, DNSQuery(1, "wpad", layers.DNSTypeA, layers.DNSClassIN), 10), false},
	}
}
