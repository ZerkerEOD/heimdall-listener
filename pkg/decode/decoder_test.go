package decode

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

var testTime = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func TestLLMNRQueryIPv4(t *testing.T) {
	f := udpFrame(t, host4, llmnr4, 51000, 5355, dnsQuery(t, 0x1234, "FileServer01", layers.DNSTypeA, layers.DNSClassIN))
	ev := mustOne(t, decodeOne(t, f))
	want := Event{Time: testTime, SrcIP: host4, DstIP: llmnr4, SrcMAC: macA, Protocol: ProtoLLMNR, Kind: KindQuery, Name: "fileserver01", QueryType: "A"}
	assertEvent(t, ev, want)
	if ev.WPAD {
		t.Error("unexpected WPAD flag")
	}
}

func TestLLMNRQueryIPv6AAAA(t *testing.T) {
	f := udpFrame(t, host6, llmnr6, 51000, 5355, dnsQuery(t, 1, "wpad", layers.DNSTypeAAAA, layers.DNSClassIN))
	ev := mustOne(t, decodeOne(t, f))
	assertEvent(t, ev, Event{Time: testTime, SrcIP: host6, DstIP: llmnr6, SrcMAC: macA, Protocol: ProtoLLMNR, Kind: KindQuery, Name: "wpad", QueryType: "AAAA", WPAD: true})
}

func TestLLMNRResponse(t *testing.T) {
	// Responder answering "wpad" from port 5355 back to the querier's port.
	f := udpFrame(t, other4, host4, 5355, 51000, dnsResponse(t, 1, "wpad", other4))
	ev := mustOne(t, decodeOne(t, f))
	assertEvent(t, ev, Event{Time: testTime, SrcIP: other4, DstIP: host4, SrcMAC: macA, Protocol: ProtoLLMNR, Kind: KindResponse, Name: "wpad", QueryType: "A", WPAD: true, Answers: []netip.Addr{other4}})
}

func TestMDNSQueryWithQUBit(t *testing.T) {
	f := udpFrame(t, host4, mdns4, 5353, 5353, dnsQuery(t, 0, "printer.local", layers.DNSTypePTR, layers.DNSClass(0x8001)))
	ev := mustOne(t, decodeOne(t, f))
	assertEvent(t, ev, Event{Time: testTime, SrcIP: host4, DstIP: mdns4, SrcMAC: macA, Protocol: ProtoMDNS, Kind: KindQuery, Name: "printer.local", QueryType: "PTR"})
}

func TestMDNSResponseGroupsAnswersByName(t *testing.T) {
	f := udpFrame(t, other4, mdns4, 5353, 5353, dnsResponse(t, 0, "Laptop.local.", other4, other6))
	ev := mustOne(t, decodeOne(t, f))
	if ev.Name != "laptop.local" || ev.Kind != KindResponse || ev.Protocol != ProtoMDNS {
		t.Fatalf("bad event %+v", ev)
	}
	if len(ev.Answers) != 2 || ev.Answers[0] != other4 || ev.Answers[1] != other6 {
		t.Fatalf("answers = %v", ev.Answers)
	}
}

func TestNBNSQueryFileServer(t *testing.T) {
	f := udpFrame(t, host4, bcast4, 137, 137, nbnsQuery(t, 0x8000, "FILESRV", 0x20, 0x20, 0, true))
	ev := mustOne(t, decodeOne(t, f))
	assertEvent(t, ev, Event{Time: testTime, SrcIP: host4, DstIP: bcast4, SrcMAC: macA, Protocol: ProtoNBNS, Kind: KindQuery, Name: "filesrv<20>", QueryType: "NB"})
}

func TestNBNSQueryWPAD(t *testing.T) {
	f := udpFrame(t, host4, bcast4, 137, 137, nbnsQuery(t, 1, "WPAD", 0x00, 0x20, 0, true))
	ev := mustOne(t, decodeOne(t, f))
	if ev.Name != "wpad<00>" || !ev.WPAD {
		t.Fatalf("got %+v", ev)
	}
}

func TestNBNSNodeStatusWildcard(t *testing.T) {
	f := udpFrame(t, host4, other4, 137, 137, nbnsQuery(t, 1, "*", 0x00, 0x21, 0, false))
	ev := mustOne(t, decodeOne(t, f))
	if ev.Name != "*<00>" || ev.QueryType != "NBSTAT" {
		t.Fatalf("got %+v", ev)
	}
}

func TestNBNSRegistration(t *testing.T) {
	f := udpFrame(t, host4, bcast4, 137, 137, nbnsQuery(t, 1, "WORKSTATION1", 0x00, 0x20, 5, true))
	ev := mustOne(t, decodeOne(t, f))
	if ev.Name != "workstation1<00>" || ev.QueryType != "Registration" || ev.Kind != KindQuery {
		t.Fatalf("got %+v", ev)
	}
}

func TestNBNSResponse(t *testing.T) {
	f := udpFrame(t, other4, host4, 137, 137, nbnsResponse(t, 1, "WPAD", 0x00, other4))
	ev := mustOne(t, decodeOne(t, f))
	assertEvent(t, ev, Event{Time: testTime, SrcIP: other4, DstIP: host4, SrcMAC: macA, Protocol: ProtoNBNS, Kind: KindResponse, Name: "wpad<00>", QueryType: "NB", WPAD: true, Answers: []netip.Addr{other4}})
}

func TestUnicastDNSOnlyWPAD(t *testing.T) {
	f := udpFrame(t, host4, dnssrv4, 40000, 53, dnsQuery(t, 7, "wpad.corp.local", layers.DNSTypeA, layers.DNSClassIN))
	ev := mustOne(t, decodeOne(t, f))
	if ev.Protocol != ProtoDNS || ev.Name != "wpad.corp.local" || !ev.WPAD {
		t.Fatalf("got %+v", ev)
	}
	f = udpFrame(t, host4, dnssrv4, 40000, 53, dnsQuery(t, 8, "www.example.com", layers.DNSTypeA, layers.DNSClassIN))
	if evs := decodeOne(t, f); len(evs) != 0 {
		t.Fatalf("expected no events for ordinary DNS, got %+v", evs)
	}
}

func TestDHCPv6Solicit(t *testing.T) {
	f := udpFrame(t, host6, dhcpv6ma, 546, 547, dhcpv6Msg(t, layers.DHCPv6MsgTypeSolicit, "Desktop-7.corp.local"))
	ev := mustOne(t, decodeOne(t, f))
	assertEvent(t, ev, Event{Time: testTime, SrcIP: host6, DstIP: dhcpv6ma, SrcMAC: macA, Protocol: ProtoDHCPv6, Kind: KindQuery, Name: "desktop-7.corp.local", QueryType: "Solicit"})
}

func TestDHCPv6SolicitWithoutFQDN(t *testing.T) {
	f := udpFrame(t, host6, dhcpv6ma, 546, 547, dhcpv6Msg(t, layers.DHCPv6MsgTypeSolicit, ""))
	ev := mustOne(t, decodeOne(t, f))
	if ev.Name != "(solicit)" {
		t.Fatalf("name = %q", ev.Name)
	}
}

func TestDHCPv6AdvertiseIsResponseWithDNSServer(t *testing.T) {
	rogueDNS := netip.MustParseAddr("fe80::bad")
	leased := netip.MustParseAddr("fd00::1234")
	iaaddr := append(append([]byte{0, 5, 0, 24}, leased.AsSlice()...), 0, 0, 0, 60, 0, 0, 0, 120)
	iana := append([]byte{0, 0, 0, 1, 0, 0, 0, 30, 0, 0, 0, 60}, iaaddr...)
	f := udpFrame(t, other6, host6, 547, 546, dhcpv6Msg(t, layers.DHCPv6MsgTypeAdvertise, "",
		layers.NewDHCPv6Option(layers.DHCPv6OptDNSServers, rogueDNS.AsSlice()),
		layers.NewDHCPv6Option(layers.DHCPv6OptIANA, iana)))
	ev := mustOne(t, decodeOne(t, f))
	if ev.Kind != KindResponse || ev.QueryType != "Advertise" || ev.Name != "(advertise)" {
		t.Fatalf("got %+v", ev)
	}
	if len(ev.Answers) != 1 || ev.Answers[0] != leased {
		t.Fatalf("answers = %v", ev.Answers)
	}
	if !contains(ev.Detail, "dns=fe80::bad") {
		t.Fatalf("detail missing dns server: %s", ev.Detail)
	}
}

func TestHTTPWPADRequest(t *testing.T) {
	req := []byte("GET /wpad.dat HTTP/1.1\r\nHost: wpad\r\nUser-Agent: WinHttp-Autoproxy-Service/5.1\r\n\r\n")
	f := tcpFrame(t, host4, other4, 50000, 80, req)
	ev := mustOne(t, decodeOne(t, f))
	assertEvent(t, ev, Event{Time: testTime, SrcIP: host4, DstIP: other4, SrcMAC: macA, Protocol: ProtoHTTP, Kind: KindQuery, Name: "wpad/wpad.dat", QueryType: "GET", WPAD: true, Answers: []netip.Addr{other4}})

	f = tcpFrame(t, host4, other4, 50000, 80, []byte("GET /index.html HTTP/1.1\r\nHost: intranet\r\n\r\n"))
	if evs := decodeOne(t, f); len(evs) != 0 {
		t.Fatalf("expected no events for ordinary HTTP, got %+v", evs)
	}
}

func TestVLANTaggedFrame(t *testing.T) {
	f := buildFrame(t, host4, llmnr4, &layers.UDP{SrcPort: 51000, DstPort: 5355}, dnsQuery(t, 1, "wpad", layers.DNSTypeA, layers.DNSClassIN), frameOpts{vlan: 10})
	ev := mustOne(t, decodeOne(t, f))
	if ev.Protocol != ProtoLLMNR || ev.Name != "wpad" {
		t.Fatalf("got %+v", ev)
	}
}

func TestIrrelevantTrafficIgnored(t *testing.T) {
	f := udpFrame(t, host4, other4, 40000, 123, []byte{0x1b, 0, 0, 0})
	if evs := decodeOne(t, f); len(evs) != 0 {
		t.Fatalf("NTP should be ignored, got %+v", evs)
	}
	arp := []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1}
	d := NewDecoder(layers.LinkTypeEthernet)
	evs, err := d.Decode(arp, testTime)
	if err != nil || len(evs) != 0 {
		t.Fatalf("ARP: evs=%v err=%v", evs, err)
	}
}

func TestTruncatedAndGarbageDoNotPanic(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	full := udpFrame(t, host4, llmnr4, 51000, 5355, dnsQuery(t, 1, "server.corp.local", layers.DNSTypeA, layers.DNSClassIN))
	for n := 0; n < len(full); n++ {
		_, _ = d.Decode(full[:n], testTime)
	}
	// Relevant port, unparsable payload must surface as an error.
	bad := udpFrame(t, host4, llmnr4, 51000, 5355, []byte{0xff, 0xff, 0x01})
	if _, err := d.Decode(bad, testTime); err == nil {
		t.Fatal("expected decode error for malformed LLMNR")
	}
	// Reuse after errors must still work.
	if evs, err := d.Decode(full, testTime); err != nil || len(evs) != 1 {
		t.Fatalf("decoder unusable after error: evs=%v err=%v", evs, err)
	}
}

func TestNetBIOSNameRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		suffix byte
	}{{"WPAD", 0x00}, {"FILESRV", 0x20}, {"*", 0x00}, {"A", 0x1c}, {"FIFTEENCHARSXXX", 0x03}, {"lower", 0x00}}
	for _, c := range cases {
		enc := EncodeNetBIOSName(c.name, c.suffix)
		if len(enc) != 32 {
			t.Fatalf("%s: encoded length %d", c.name, len(enc))
		}
		got, suf, err := DecodeNetBIOSName([]byte(enc))
		if err != nil {
			t.Fatal(err)
		}
		want := c.name
		if want != "*" {
			want = toUpper(want)
		}
		if got != want || suf != c.suffix {
			t.Errorf("%s<%02x>: got %q<%02x>", c.name, c.suffix, got, suf)
		}
	}
	if _, _, err := DecodeNetBIOSName([]byte("not-a-netbios-name")); err == nil {
		t.Error("expected error for non-NetBIOS label")
	}
	if _, _, err := DecodeNetBIOSName([]byte("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")); err == nil {
		t.Error("expected error for out-of-range characters")
	}
}

func TestIsWPADName(t *testing.T) {
	for name, want := range map[string]bool{
		"wpad": true, "WPAD": true, "wpad.corp.local": true, "wpad<00>": true,
		"wpadserver": false, "notwpad": false, "corp.wpad.local": false, "": false,
	} {
		if got := IsWPADName(name); got != want {
			t.Errorf("IsWPADName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNetBIOSSuffixRole(t *testing.T) {
	if NetBIOSSuffixRole(0x20) != "File server service" || NetBIOSSuffixRole(0x1c) != "Domain controllers" {
		t.Fatal("suffix roles wrong")
	}
	if !contains(NetBIOSSuffixRole(0x42), "Unknown") {
		t.Fatal("unknown suffix")
	}
}

func assertEvent(t *testing.T, got, want Event) {
	t.Helper()
	if !got.Time.Equal(want.Time) || got.SrcIP != want.SrcIP || got.DstIP != want.DstIP ||
		got.SrcMAC.String() != want.SrcMAC.String() || got.Protocol != want.Protocol || got.Kind != want.Kind ||
		got.Name != want.Name || got.QueryType != want.QueryType || got.WPAD != want.WPAD {
		t.Fatalf("event mismatch\n got: %+v\nwant: %+v", got, want)
	}
	if len(got.Answers) != len(want.Answers) {
		t.Fatalf("answers = %v, want %v", got.Answers, want.Answers)
	}
	for i := range want.Answers {
		if got.Answers[i] != want.Answers[i] {
			t.Fatalf("answers = %v, want %v", got.Answers, want.Answers)
		}
	}
	if got.Detail == "" {
		t.Fatal("detail must not be empty")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
