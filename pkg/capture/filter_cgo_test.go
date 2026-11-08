//go:build cgo && !windows

package capture

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/bpf"

	"github.com/ZerkerEOD/heimdall-listener/internal/pkttest"
)

// TestDefaultProgramMatchesLibpcap guards against the pure-Go program and
// the libpcap expression drifting apart.
func TestDefaultProgramMatchesLibpcap(t *testing.T) {
	compiled, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, DefaultFilter)
	if err != nil {
		t.Fatalf("libpcap rejected DefaultFilter: %v", err)
	}
	vm, err := bpf.NewVM(DefaultProgram())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range pkttest.Corpus() {
		ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(s.Frame), Length: len(s.Frame)}
		lib := compiled.Matches(ci, s.Frame)
		n, err := vm.Run(s.Frame)
		if err != nil {
			t.Fatal(err)
		}
		if ours := n > 0; ours != lib {
			t.Errorf("%s: pure-Go=%v libpcap=%v", s.Name, ours, lib)
		}
		if lib != s.Accept {
			t.Errorf("%s: libpcap=%v but corpus expects %v", s.Name, lib, s.Accept)
		}
	}
}
