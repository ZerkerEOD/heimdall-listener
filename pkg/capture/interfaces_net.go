package capture

import (
	"net"
	"net/netip"
)

// netInterfaces enumerates interfaces with the standard library. It is the
// only option without libpcap and is also used to fill gaps in pcap data.
func netInterfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifs))
	for _, i := range ifs {
		ni := Interface{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if na, ok := netip.AddrFromSlice(ip); ok {
				ni.Addrs = append(ni.Addrs, na.Unmap())
			}
		}
		out = append(out, ni)
	}
	return out, nil
}
