//go:build linux

package capture

import (
	"net"
	"os"
	"testing"
	"time"
)

// TestLiveLoopback opens the loopback interface with the compiled-in backend
// and reads back a self-sent LLMNR-port datagram. It needs CAP_NET_RAW and
// is therefore gated behind HEIMDALL_LIVE_TESTS=1.
func TestLiveLoopback(t *testing.T) {
	if os.Getenv("HEIMDALL_LIVE_TESTS") != "1" {
		t.Skip("set HEIMDALL_LIVE_TESTS=1 (requires CAP_NET_RAW) to run")
	}
	o := DefaultOptions()
	o.Promiscuous = false
	o.Filter = "" // loopback uses a different link type under libpcap; keep it simple
	h, err := Open("lo", o)
	if err != nil {
		t.Fatalf("open lo: %v (backend %s)", err, Backend())
	}
	defer h.Close()

	done := make(chan struct{})
	var got int
	go func() {
		defer close(done)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			data, _, err := h.ReadPacketData()
			if err == ErrClosed {
				return
			}
			if err == nil && len(data) > 0 {
				got++
				return
			}
		}
	}()
	conn, err := net.Dial("udp", "127.0.0.1:5355")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 'w', 'p', 'a', 'd', 0, 0, 1, 0, 1})
	conn.Close()
	<-done
	h.Interrupt()
	if got == 0 {
		t.Fatalf("no frame read from lo via %s", Backend())
	}
}
