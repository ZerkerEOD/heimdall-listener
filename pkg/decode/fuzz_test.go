package decode

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// FuzzDecode guards the one place untrusted bytes enter the program: no
// input may panic the decoder, and the decoder must stay usable afterwards.
func FuzzDecode(f *testing.F) {
	f.Add(udpFrame(&testing.T{}, host4, llmnr4, 51000, 5355, dnsQuery(&testing.T{}, 1, "wpad", layers.DNSTypeA, layers.DNSClassIN)))
	f.Add(udpFrame(&testing.T{}, host4, bcast4, 137, 137, nbnsQuery(&testing.T{}, 1, "WPAD", 0, 0x20, 0, true)))
	f.Add(udpFrame(&testing.T{}, host6, dhcpv6ma, 546, 547, dhcpv6Msg(&testing.T{}, layers.DHCPv6MsgTypeSolicit, "a.b")))
	f.Add(tcpFrame(&testing.T{}, host4, other4, 50000, 80, []byte("GET /wpad.dat HTTP/1.1\r\nHost: wpad\r\n\r\n")))
	f.Add([]byte{})
	d := NewDecoder(layers.LinkTypeEthernet)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = d.Decode(data, testTime)
	})
}
