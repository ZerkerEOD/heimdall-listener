package decode

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// dnsEvents converts a decoded DNS-format message (LLMNR, mDNS, NBNS or
// unicast DNS) into Events. Queries yield one Event per question; responses
// yield one Event per answered name carrying its A/AAAA/NB addresses.
func (d *Decoder) dnsEvents(proto Protocol, base Event) []Event {
	dns := &d.dns
	var out []Event

	if !dns.QR {
		for i := range dns.Questions {
			q := &dns.Questions[i]
			ev := base
			ev.Protocol = proto
			ev.Kind = KindQuery
			if proto == ProtoNBNS {
				ev.Name, _ = nbnsDisplayName(q.Name)
				ev.QueryType = nbnsQueryType(dns.OpCode, q.Type)
			} else {
				ev.Name = normalizeName(q.Name)
				ev.QueryType = dnsTypeString(q.Type)
			}
			ev.WPAD = IsWPADName(ev.Name)
			if proto == ProtoDNS && !ev.WPAD {
				continue // unicast DNS is only interesting for WPAD
			}
			ev.Detail = fmt.Sprintf("%s %s query for %q (id 0x%04x) %s -> %s",
				proto, ev.QueryType, ev.Name, dns.ID, base.SrcIP, base.DstIP)
			out = append(out, ev)
		}
		return out
	}

	// Response: group answers by name.
	type acc struct {
		idx int
	}
	byName := map[string]acc{}
	for i := range dns.Answers {
		rr := &dns.Answers[i]
		var addrs []netip.Addr
		var qt string
		switch {
		case rr.Type == layers.DNSTypeA || rr.Type == layers.DNSTypeAAAA:
			if a, ok := netip.AddrFromSlice(rr.IP); ok {
				addrs = append(addrs, a.Unmap())
			}
			qt = dnsTypeString(rr.Type)
		case proto == ProtoNBNS && rr.Type == nbnsTypeNB:
			addrs = nbnsAnswerAddrs(rr.Data)
			qt = "NB"
		default:
			continue
		}
		var name string
		if proto == ProtoNBNS {
			name, _ = nbnsDisplayName(rr.Name)
		} else {
			name = normalizeName(rr.Name)
		}
		if a, ok := byName[name]; ok {
			out[a.idx].Answers = append(out[a.idx].Answers, addrs...)
			continue
		}
		ev := base
		ev.Protocol = proto
		ev.Kind = KindResponse
		ev.Name = name
		ev.QueryType = qt
		ev.Answers = addrs
		ev.WPAD = IsWPADName(name)
		if proto == ProtoDNS && !ev.WPAD {
			continue
		}
		byName[name] = acc{idx: len(out)}
		out = append(out, ev)
	}
	for i := range out {
		out[i].Detail = fmt.Sprintf("%s response: %q is at %s (id 0x%04x) %s -> %s",
			proto, out[i].Name, joinAddrs(out[i].Answers), dns.ID, base.SrcIP, base.DstIP)
	}
	return out
}

func dnsTypeString(t layers.DNSType) string {
	switch t {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSRV:
		return "SRV"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

func joinAddrs(as []netip.Addr) string {
	if len(as) == 0 {
		return "(no address)"
	}
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}
