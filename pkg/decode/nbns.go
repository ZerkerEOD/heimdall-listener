package decode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// NetBIOS-NS record types (RFC 1002 §4.2.1.1).
const (
	nbnsTypeNB     layers.DNSType = 0x20
	nbnsTypeNBSTAT layers.DNSType = 0x21
)

// ErrNotNetBIOSName is returned when a label is not a 32-character
// first-level-encoded NetBIOS name.
var ErrNotNetBIOSName = errors.New("not a first-level encoded NetBIOS name")

// EncodeNetBIOSName applies RFC 1001 first-level encoding to a NetBIOS name
// and suffix, producing the 32-character label found on the wire. Names
// longer than 15 characters are truncated; shorter names are space padded.
// The wildcard name "*" is padded with NUL bytes as Windows does.
func EncodeNetBIOSName(name string, suffix byte) string {
	raw := make([]byte, 16)
	pad := byte(' ')
	if name == "*" {
		pad = 0
	}
	for i := range 15 {
		raw[i] = pad
	}
	upper := strings.ToUpper(name)
	copy(raw[:15], upper)
	raw[15] = suffix
	out := make([]byte, 32)
	for i, b := range raw {
		out[2*i] = 'A' + (b >> 4)
		out[2*i+1] = 'A' + (b & 0x0f)
	}
	return string(out)
}

// DecodeNetBIOSName reverses first-level encoding. label is the first DNS
// label of an NBNS name (32 characters in 'A'..'P'). It returns the trimmed
// name (for example "FILESRV" or "*") and the 16th-byte suffix.
func DecodeNetBIOSName(label []byte) (name string, suffix byte, err error) {
	if len(label) != 32 {
		return "", 0, ErrNotNetBIOSName
	}
	raw := make([]byte, 16)
	for i := 0; i < 32; i += 2 {
		hi, lo := label[i], label[i+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return "", 0, ErrNotNetBIOSName
		}
		raw[i/2] = (hi-'A')<<4 | (lo - 'A')
	}
	suffix = raw[15]
	name = strings.TrimRight(string(raw[:15]), " \x00")
	return name, suffix, nil
}

// NetBIOSSuffixRole describes the well-known NetBIOS name suffixes.
func NetBIOSSuffixRole(suffix byte) string {
	switch suffix {
	case 0x00:
		return "Workstation service"
	case 0x03:
		return "Messenger service"
	case 0x06:
		return "RAS server"
	case 0x1b:
		return "Domain master browser"
	case 0x1c:
		return "Domain controllers"
	case 0x1d:
		return "Master browser"
	case 0x1e:
		return "Browser service elections"
	case 0x20:
		return "File server service"
	case 0x21:
		return "RAS client"
	case 0xbe:
		return "Network monitor agent"
	case 0xbf:
		return "Network monitor application"
	default:
		return fmt.Sprintf("Unknown suffix 0x%02x", suffix)
	}
}

// nbnsDisplayName turns the wire label into the normalized display form
// "name<xx>". Non-NetBIOS labels are returned lowercased unchanged.
func nbnsDisplayName(wire []byte) (string, bool) {
	label := wire
	if i := indexByte(wire, '.'); i >= 0 {
		label = wire[:i]
	}
	name, suffix, err := DecodeNetBIOSName(label)
	if err != nil {
		return normalizeName(wire), false
	}
	return fmt.Sprintf("%s<%02x>", strings.ToLower(name), suffix), true
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// nbnsQueryType names the question type / opcode combination.
func nbnsQueryType(op layers.DNSOpCode, t layers.DNSType) string {
	switch op {
	case 5:
		return "Registration"
	case 6:
		return "Release"
	case 7:
		return "WACK"
	case 8:
		return "Refresh"
	case 9:
		return "Refresh"
	}
	switch t {
	case nbnsTypeNB:
		return "NB"
	case nbnsTypeNBSTAT:
		return "NBSTAT"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

// nbnsAnswerAddrs parses NB record RDATA: repeated (2-byte NB_FLAGS, 4-byte
// IPv4 address) entries.
func nbnsAnswerAddrs(rdata []byte) []netip.Addr {
	var out []netip.Addr
	for len(rdata) >= 6 {
		_ = binary.BigEndian.Uint16(rdata[:2]) // NB_FLAGS: group/node type, unused
		if a, ok := netip.AddrFromSlice(rdata[2:6]); ok {
			out = append(out, a)
		}
		rdata = rdata[6:]
	}
	return out
}
