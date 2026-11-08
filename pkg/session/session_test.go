package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/ZerkerEOD/heimdall-listener/internal/pkttest"
	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
)

type fakeHandle struct {
	frames chan []byte
	closed chan struct{}
	once   sync.Once
	reads  atomic.Int64
	recv   uint64
	drop   uint64
}

func newFake() *fakeHandle {
	return &fakeHandle{frames: make(chan []byte, 64), closed: make(chan struct{})}
}

func (f *fakeHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	f.reads.Add(1)
	select {
	case <-f.closed:
		return nil, gopacket.CaptureInfo{}, capture.ErrClosed
	default:
	}
	select {
	case fr := <-f.frames:
		f.recv++
		return fr, gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(fr), Length: len(fr)}, nil
	case <-f.closed:
		return nil, gopacket.CaptureInfo{}, capture.ErrClosed
	case <-time.After(5 * time.Millisecond):
		return nil, gopacket.CaptureInfo{}, capture.ErrTimeout
	}
}
func (f *fakeHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (f *fakeHandle) Interrupt()                { f.once.Do(func() { close(f.closed) }) }
func (f *fakeHandle) Close() error              { f.Interrupt(); return nil }
func (f *fakeHandle) Stats() (uint64, uint64, error) {
	return f.recv, f.drop, nil
}

func startFake(t *testing.T, fh *fakeHandle, agg *Aggregator, onEvent func(decode.Event)) *Session {
	t.Helper()
	cfg := Config{Interface: "fake0", Capture: capture.DefaultOptions(), OnEvent: onEvent,
		open: func(string, capture.Options) (capture.Handle, error) { return fh, nil }}
	s, err := Start(context.Background(), cfg, agg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestSessionFeedsAggregatorAndStops(t *testing.T) {
	fh := newFake()
	fh.drop = 4
	agg := newAgg()
	var events atomic.Int64
	s := startFake(t, fh, agg, func(decode.Event) { events.Add(1) })

	fh.frames <- pkttest.UDP(pkttest.Host4, pkttest.LLMNR4, 51000, 5355, pkttest.DNSQuery(1, "wpad", layers.DNSTypeA, layers.DNSClassIN))
	fh.frames <- pkttest.UDP(pkttest.Host4, pkttest.Bcast4, 137, 137, pkttest.NBNSQuery(2, "FILESRV", 0x20))
	fh.frames <- pkttest.UDP(pkttest.Host4, pkttest.Other4, 123, 123, make([]byte, 48)) // ignored
	fh.frames <- pkttest.UDP(pkttest.Host4, pkttest.LLMNR4, 51000, 5355, []byte{0xff})  // decode error

	waitFor(t, func() bool { return agg.Snapshot().Stats.Packets == 4 })
	snap := agg.Snapshot()
	if len(snap.Entries) != 2 || snap.Stats.Events != 2 || snap.Stats.DecodeErrors != 1 || events.Load() != 2 {
		t.Fatalf("snapshot = %+v events=%d", snap.Stats, events.Load())
	}

	start := time.Now()
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("stop took %s", time.Since(start))
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("done not closed")
	}
	if s.Ended().IsZero() {
		t.Fatal("ended not set")
	}
	if agg.Snapshot().Stats.Dropped != 4 {
		t.Fatalf("drops not recorded: %d", agg.Snapshot().Stats.Dropped)
	}
	// Stop is idempotent.
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	ci := CaptureInfo([]*Session{s}, agg.Snapshot())
	if len(ci.Interfaces) != 1 || ci.Interfaces[0] != "fake0" || ci.PacketsSeen != 4 || ci.Dropped != 4 || ci.EndedAt.IsZero() {
		t.Fatalf("capture info = %+v", ci)
	}
}

func TestSessionContextCancel(t *testing.T) {
	fh := newFake()
	agg := newAgg()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := Config{Interface: "fake0", open: func(string, capture.Options) (capture.Handle, error) { return fh, nil }}
	s, err := Start(ctx, cfg, agg)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("session did not stop on context cancel")
	}
	if s.Err() != nil {
		t.Fatalf("unexpected error: %v", s.Err())
	}
}

func TestSessionOpenErrorSurfacesImmediately(t *testing.T) {
	cfg := Config{Interface: "nope", open: func(string, capture.Options) (capture.Handle, error) {
		return nil, capture.ErrPermission
	}}
	if _, err := Start(context.Background(), cfg, newAgg()); !errors.Is(err, capture.ErrPermission) {
		t.Fatalf("expected ErrPermission, got %v", err)
	}
	if _, err := Start(context.Background(), Config{Interface: "x"}, nil); err == nil {
		t.Fatal("nil aggregator must error")
	}
}

type errHandle struct{ fakeHandle }

func (e *errHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, errors.New("device went away")
}

func TestSessionReadErrorEndsSession(t *testing.T) {
	eh := &errHandle{*newFake()}
	cfg := Config{Interface: "fake0", open: func(string, capture.Options) (capture.Handle, error) { return eh, nil }}
	s, err := Start(context.Background(), cfg, newAgg())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("session did not end on read error")
	}
	if s.Err() == nil || !errors.Is(s.Stop(), s.Err()) {
		t.Fatalf("err = %v", s.Err())
	}
}
