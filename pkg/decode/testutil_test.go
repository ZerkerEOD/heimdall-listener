package decode

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	macA = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	macB = net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}

	host4   = netip.MustParseAddr("192.168.1.10")
	other4  = netip.MustParseAddr("192.168.1.20")
	bcast4  = netip.MustParseAddr("192.168.1.255")
	llmnr4  = netip.MustParseAddr("224.0.0.252")
	mdns4   = netip.MustParseAddr("224.0.0.251")
	dnssrv4 = netip.MustParseAddr("192.168.1.1")

	host6    = netip.MustParseAddr("fe80::1")
	other6   = netip.MustParseAddr("fe80::2")
	llmnr6   = netip.MustParseAddr("ff02::1:3")
	dhcpv6ma = netip.MustParseAddr("ff02::1:2")
)

type frameOpts struct {
	vlan uint16 // 0 = untagged
}

// buildFrame serialises Ethernet + IPv4/IPv6 + UDP/TCP + payload.
func buildFrame(t *testing.T, src, dst netip.Addr, l4 gopacket.SerializableLayer, payload []byte, o frameOpts) []byte {
	t.Helper()
	var (
		ip   gopacket.NetworkLayer
		stk  []gopacket.SerializableLayer
		eth  = &layers.Ethernet{SrcMAC: macA, DstMAC: macB}
		etyp layers.EthernetType
	)
	var ipProto layers.IPProtocol
	switch l4.(type) {
	case *layers.UDP:
		ipProto = layers.IPProtocolUDP
	case *layers.TCP:
		ipProto = layers.IPProtocolTCP
	default:
		t.Fatalf("unsupported l4 %T", l4)
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
	if o.vlan != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stk = append([]gopacket.SerializableLayer{eth, &layers.Dot1Q{VLANIdentifier: o.vlan, Type: etyp}}, stk...)
	} else {
		eth.EthernetType = etyp
		stk = append([]gopacket.SerializableLayer{eth}, stk...)
	}
	switch l := l4.(type) {
	case *layers.UDP:
		if err := l.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
	case *layers.TCP:
		if err := l.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
	}
	stk = append(stk, l4, gopacket.Payload(payload))
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stk...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func udpFrame(t *testing.T, src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	return buildFrame(t, src, dst, &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}, payload, frameOpts{})
}

func tcpFrame(t *testing.T, src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	return buildFrame(t, src, dst, &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), PSH: true, ACK: true, Seq: 1, Window: 1024}, payload, frameOpts{})
}

func serializeDNS(t *testing.T, d *layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dnsQuery(t *testing.T, id uint16, name string, qtype layers.DNSType, class layers.DNSClass) []byte {
	t.Helper()
	return serializeDNS(t, &layers.DNS{ID: id, RD: false, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: qtype, Class: class}}})
}

func dnsResponse(t *testing.T, id uint16, name string, addrs ...netip.Addr) []byte {
	t.Helper()
	d := &layers.DNS{ID: id, QR: true, OpCode: layers.DNSOpCodeQuery, AA: true}
	for _, a := range addrs {
		rr := layers.DNSResourceRecord{Name: []byte(name), Class: layers.DNSClassIN, TTL: 30, IP: a.AsSlice()}
		if a.Is4() {
			rr.Type = layers.DNSTypeA
		} else {
			rr.Type = layers.DNSTypeAAAA
		}
		d.Answers = append(d.Answers, rr)
	}
	return serializeDNS(t, d)
}

// nbnsQuery builds a NetBIOS-NS query by hand (RFC 1002 §4.2.12).
func nbnsQuery(t *testing.T, id uint16, name string, suffix byte, qtype uint16, opcode uint8, broadcast bool) []byte {
	t.Helper()
	flags := uint16(opcode&0xf) << 11
	flags |= 1 << 8 // RD
	if broadcast {
		flags |= 1 << 4 // B
	}
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1) // QDCOUNT
	if opcode == 5 {
		binary.BigEndian.PutUint16(b[10:], 1) // ARCOUNT for registration
	}
	b = append(b, 0x20)
	b = append(b, EncodeNetBIOSName(name, suffix)...)
	b = append(b, 0x00)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	if opcode == 5 {
		// Additional RR: pointer to question name, NB, IN, TTL, RDLEN 6, flags+IP
		b = append(b, 0xc0, 0x0c)
		b = binary.BigEndian.AppendUint16(b, 0x20)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, 300000)
		b = binary.BigEndian.AppendUint16(b, 6)
		b = binary.BigEndian.AppendUint16(b, 0x0000)
		b = append(b, host4.AsSlice()...)
	}
	return b
}

// nbnsResponse builds a positive NetBIOS name query response.
func nbnsResponse(t *testing.T, id uint16, name string, suffix byte, addrs ...netip.Addr) []byte {
	t.Helper()
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x8500) // QR, AA, RD
	binary.BigEndian.PutUint16(b[6:], 1)      // ANCOUNT
	b = append(b, 0x20)
	b = append(b, EncodeNetBIOSName(name, suffix)...)
	b = append(b, 0x00)
	b = binary.BigEndian.AppendUint16(b, 0x20) // NB
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 300000)
	b = binary.BigEndian.AppendUint16(b, uint16(6*len(addrs)))
	for _, a := range addrs {
		b = binary.BigEndian.AppendUint16(b, 0x0000)
		b = append(b, a.AsSlice()...)
	}
	return b
}

func encodeLabels(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, name[start:i]...)
			start = i + 1
		}
	}
	return append(out, 0)
}

func dhcpv6Msg(t *testing.T, mt layers.DHCPv6MsgType, fqdn string, extra ...layers.DHCPv6Option) []byte {
	t.Helper()
	m := &layers.DHCPv6{MsgType: mt, TransactionID: []byte{0x01, 0x02, 0x03}}
	m.Options = append(m.Options, layers.NewDHCPv6Option(layers.DHCPv6OptClientID, []byte{0, 1, 0, 1, 0xde, 0xad, 0xbe, 0xef, 0, 0x11, 0x22, 0x33, 0x44, 0x55}))
	m.Options = append(m.Options, layers.NewDHCPv6Option(layers.DHCPv6OptElapsedTime, []byte{0, 0}))
	if fqdn != "" {
		m.Options = append(m.Options, layers.NewDHCPv6Option(layers.DHCPv6OptClientFQDN, append([]byte{0x00}, encodeLabels(fqdn)...)))
	}
	m.Options = append(m.Options, extra...)
	buf := gopacket.NewSerializeBuffer()
	if err := m.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decodeOne(t *testing.T, frame []byte) []Event {
	t.Helper()
	d := NewDecoder(layers.LinkTypeEthernet)
	evs, err := d.Decode(frame, testTime)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return evs
}

func mustOne(t *testing.T, evs []Event) Event {
	t.Helper()
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d: %+v", len(evs), evs)
	}
	return evs[0]
}
