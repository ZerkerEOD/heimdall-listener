// Package decode turns raw link-layer frames into protocol Events describing
// legacy name-resolution traffic (LLMNR, mDNS, NetBIOS-NS), unicast DNS and
// HTTP requests related to WPAD, and DHCPv6 client/server messages.
//
// The package is strictly passive: it only parses bytes handed to it and
// never performs I/O. It is shared by the GUI and the CLI.
package decode

import (
	"net"
	"net/netip"
	"time"
)

// Protocol identifies the application protocol an Event was decoded from.
type Protocol string

const (
	ProtoLLMNR  Protocol = "LLMNR"
	ProtoMDNS   Protocol = "mDNS"
	ProtoNBNS   Protocol = "NetBIOS"
	ProtoDNS    Protocol = "DNS"
	ProtoDHCPv6 Protocol = "DHCPv6"
	ProtoHTTP   Protocol = "HTTP"
)

// AllProtocols returns every protocol the decoder can emit, in display order.
func AllProtocols() []Protocol {
	return []Protocol{ProtoLLMNR, ProtoNBNS, ProtoMDNS, ProtoDNS, ProtoDHCPv6, ProtoHTTP}
}

// Kind distinguishes a client asking for something (Query) from a host
// answering or offering something (Response). Responses are what passive
// poisoner detection keys on.
type Kind string

const (
	KindQuery    Kind = "Query"
	KindResponse Kind = "Response"
)

// Event is a single decoded observation. One frame may yield several Events
// (for example a DNS response with multiple answers).
type Event struct {
	Time   time.Time
	SrcIP  netip.Addr
	DstIP  netip.Addr
	SrcMAC net.HardwareAddr

	Protocol Protocol
	Kind     Kind

	// Name is the normalized name involved: lowercase, no trailing dot.
	// NetBIOS names carry their suffix as "name<20>". DHCPv6 uses the client
	// FQDN when present, otherwise a placeholder such as "(solicit)".
	Name string

	// QueryType is the record or message type: A, AAAA, ANY, PTR, NB, NBSTAT,
	// Registration, Solicit, Advertise, Reply, GET, ...
	QueryType string

	// Answers holds addresses claimed for Name in a Response (A/AAAA/NB
	// records, DHCPv6 leased addresses). For HTTP WPAD requests it holds the
	// server address the client contacted.
	Answers []netip.Addr

	// WPAD marks events that relate to Web Proxy Auto-Discovery: a query or
	// answer for a name whose first label is "wpad", or an HTTP request for
	// wpad.dat.
	WPAD bool

	// Detail is a one-line human-readable description for detail panes/logs.
	Detail string
}
