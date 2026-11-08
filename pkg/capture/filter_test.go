package capture

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/ZerkerEOD/heimdall-listener/internal/pkttest"
)

func TestDefaultProgramVerdicts(t *testing.T) {
	vm, err := bpf.NewVM(DefaultProgram())
	if err != nil {
		t.Fatalf("program does not validate: %v", err)
	}
	for _, s := range pkttest.Corpus() {
		n, err := vm.Run(s.Frame)
		if err != nil {
			t.Fatalf("%s: vm error %v", s.Name, err)
		}
		if got := n > 0; got != s.Accept {
			t.Errorf("%s: accept=%v want %v", s.Name, got, s.Accept)
		}
	}
}

func TestDefaultProgramAssembles(t *testing.T) {
	raw, err := bpf.Assemble(DefaultProgram())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(raw) > 4096 {
		t.Fatalf("unexpected program length %d", len(raw))
	}
}

func TestAssemblerRejectsUnknownLabel(t *testing.T) {
	a := newAssembler()
	a.jmp(bpf.Jump{}, "nowhere", "")
	if _, err := a.assemble(); err == nil {
		t.Fatal("expected error for unknown label")
	}
}

func TestInterfaceUsable(t *testing.T) {
	cases := []struct {
		i    Interface
		want bool
	}{
		{Interface{Name: "lo", Loopback: true, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, false},
		{Interface{Name: "eth0", Up: true, Addrs: []netip.Addr{netip.MustParseAddr("fe80::1")}}, false},
		{Interface{Name: "eth0", Up: true, Addrs: []netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("10.0.0.5")}}, true},
		{Interface{Name: "eth1", Up: true}, false},
	}
	for _, c := range cases {
		if got := c.i.Usable(); got != c.want {
			t.Errorf("%s usable=%v want %v", c.i.Name, got, c.want)
		}
	}
	if (Interface{Name: "x", Description: "Intel"}).DisplayName() != "Intel" || (Interface{Name: "x"}).DisplayName() != "x" {
		t.Error("DisplayName")
	}
}

func TestWrapOpenError(t *testing.T) {
	if !errors.Is(wrapOpenError("eth0", errors.New("eth0: You don't have permission to capture on that device (socket: Operation not permitted)")), ErrPermission) {
		t.Error("libpcap permission text not mapped")
	}
	if !errors.Is(wrapOpenError("eth0", errors.New("Access is denied.")), ErrPermission) {
		t.Error("windows permission text not mapped")
	}
	if errors.Is(wrapOpenError("eth0", errors.New("No such device exists")), ErrPermission) {
		t.Error("unrelated error mapped to permission")
	}
	if wrapOpenError("eth0", nil) != nil {
		t.Error("nil must stay nil")
	}
}
