package decode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// dhcpv6Event converts a DHCPv6 message into an Event. Client messages
// (Solicit, Request, ...) are Queries; server messages (Advertise, Reply)
// are Responses. A Solicit means the host would accept a rogue DHCPv6
// server (mitm6); an Advertise/Reply identifies a host acting as a server.
func (d *Decoder) dhcpv6Event(base Event) []Event {
	m := &d.dhcp
	ev := base
	ev.Protocol = ProtoDHCPv6
	ev.QueryType = m.MsgType.String()

	switch m.MsgType {
	case layers.DHCPv6MsgTypeSolicit, layers.DHCPv6MsgTypeRequest, layers.DHCPv6MsgTypeConfirm,
		layers.DHCPv6MsgTypeRenew, layers.DHCPv6MsgTypeRebind, layers.DHCPv6MsgTypeInformationRequest:
		ev.Kind = KindQuery
	case layers.DHCPv6MsgTypeAdvertise, layers.DHCPv6MsgTypeReply, layers.DHCPv6MsgTypeReconfigure:
		ev.Kind = KindResponse
	default:
		return nil // Release, Decline, relay messages: not interesting
	}

	var fqdn, duid string
	var dnsServers, leased []netip.Addr
	for i := range m.Options {
		opt := &m.Options[i]
		switch opt.Code {
		case layers.DHCPv6OptClientFQDN:
			if len(opt.Data) > 1 {
				fqdn = decodeDNSLabels(opt.Data[1:]) // first byte is flags
			}
		case layers.DHCPv6OptClientID:
			if ev.Kind == KindQuery {
				duid = hex.EncodeToString(opt.Data)
			}
		case layers.DHCPv6OptServerID:
			if ev.Kind == KindResponse {
				duid = hex.EncodeToString(opt.Data)
			}
		case layers.DHCPv6OptDNSServers:
			for b := opt.Data; len(b) >= 16; b = b[16:] {
				if a, ok := netip.AddrFromSlice(b[:16]); ok {
					dnsServers = append(dnsServers, a)
				}
			}
		case layers.DHCPv6OptIANA:
			// IAID(4) T1(4) T2(4) then sub-options
			if len(opt.Data) > 12 {
				leased = append(leased, iaAddrs(opt.Data[12:])...)
			}
		case layers.DHCPv6OptIATA:
			if len(opt.Data) > 4 {
				leased = append(leased, iaAddrs(opt.Data[4:])...)
			}
		}
	}

	if fqdn != "" {
		ev.Name = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	} else {
		ev.Name = "(" + strings.ToLower(ev.QueryType) + ")"
	}
	ev.Answers = leased

	var sb strings.Builder
	fmt.Fprintf(&sb, "DHCPv6 %s (xid %s) %s -> %s", ev.QueryType, hex.EncodeToString(m.TransactionID), base.SrcIP, base.DstIP)
	if fqdn != "" {
		fmt.Fprintf(&sb, " fqdn=%s", ev.Name)
	}
	if duid != "" {
		fmt.Fprintf(&sb, " duid=%s", duid)
	}
	if len(leased) > 0 {
		fmt.Fprintf(&sb, " addr=%s", joinAddrs(leased))
	}
	if len(dnsServers) > 0 {
		fmt.Fprintf(&sb, " dns=%s", joinAddrs(dnsServers))
	}
	ev.Detail = sb.String()
	return []Event{ev}
}

// iaAddrs extracts IAADDR (option 5) addresses from IA_NA/IA_TA sub-options.
func iaAddrs(b []byte) []netip.Addr {
	var out []netip.Addr
	for len(b) >= 4 {
		code := binary.BigEndian.Uint16(b[:2])
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+l {
			break
		}
		if code == uint16(layers.DHCPv6OptIAAddr) && l >= 16 {
			if a, ok := netip.AddrFromSlice(b[4:20]); ok {
				out = append(out, a)
			}
		}
		b = b[4+l:]
	}
	return out
}

// decodeDNSLabels decodes an uncompressed DNS wire-format name.
func decodeDNSLabels(b []byte) string {
	var parts []string
	for len(b) > 0 {
		l := int(b[0])
		if l == 0 || l > 63 || len(b) < 1+l {
			break
		}
		parts = append(parts, string(b[1:1+l]))
		b = b[1+l:]
	}
	return strings.Join(parts, ".")
}
