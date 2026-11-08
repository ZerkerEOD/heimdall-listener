package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// Config describes one capture session.
type Config struct {
	Interface string
	Capture   capture.Options
	// OnEvent, if set, is called synchronously on the reader goroutine for
	// every event after aggregation. It must be fast and must not block.
	OnEvent func(decode.Event)
	// OnError, if set, receives decode errors (malformed packets).
	OnError func(error)

	open func(string, capture.Options) (capture.Handle, error) // test hook
}

// Session is a running capture on one interface feeding an Aggregator.
type Session struct {
	cfg    Config
	agg    *Aggregator
	h      capture.Handle
	cancel context.CancelFunc
	done   chan struct{}

	mu        sync.Mutex
	closed    bool
	started   time.Time
	ended     time.Time
	err       error
	finalRecv uint64
	finalDrop uint64
}

// Start opens the interface synchronously (so permission and device errors
// surface immediately) and begins reading in the background. The session
// stops when ctx is cancelled or Stop is called.
func Start(ctx context.Context, cfg Config, agg *Aggregator) (*Session, error) {
	if agg == nil {
		return nil, errors.New("session: nil aggregator")
	}
	open := cfg.open
	if open == nil {
		open = capture.Open
	}
	h, err := open(cfg.Interface, cfg.Capture)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Session{cfg: cfg, agg: agg, h: h, cancel: cancel, done: make(chan struct{}), started: time.Now()}
	go s.readLoop(ctx)
	go func() {
		<-ctx.Done()
		h.Interrupt()
	}()
	return s, nil
}

func (s *Session) readLoop(ctx context.Context) {
	defer close(s.done)
	dec := decode.NewDecoder(s.h.LinkType())
	var readErr error
	var n uint64
loop:
	for {
		data, ci, err := s.h.ReadPacketData()
		if err != nil {
			switch {
			case errors.Is(err, capture.ErrTimeout):
				if ctx.Err() != nil {
					break loop
				}
				continue
			case errors.Is(err, capture.ErrClosed), ctx.Err() != nil:
				break loop
			default:
				readErr = fmt.Errorf("session: read %s: %w", s.cfg.Interface, err)
				break loop
			}
		}
		ts := ci.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		evs, derr := dec.Decode(data, ts)
		s.agg.NotePacket(derr != nil)
		if derr != nil && s.cfg.OnError != nil {
			s.cfg.OnError(derr)
		}
		for _, ev := range evs {
			s.agg.Add(ev)
			if s.cfg.OnEvent != nil {
				s.cfg.OnEvent(ev)
			}
		}
		n++
		if n%256 == 0 {
			s.refreshStats()
		}
	}
	s.mu.Lock()
	recv, drop, serr := s.h.Stats()
	if serr == nil {
		s.finalRecv, s.finalDrop = recv, drop
		s.agg.SetDropped(s.cfg.Interface, drop)
	}
	_ = s.h.Close()
	s.closed = true
	s.ended = time.Now()
	s.err = readErr
	s.mu.Unlock()
}

func (s *Session) refreshStats() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if recv, drop, err := s.h.Stats(); err == nil {
		s.finalRecv, s.finalDrop = recv, drop
		s.agg.SetDropped(s.cfg.Interface, drop)
	}
}

// Stop cancels the session and waits for the reader to exit.
func (s *Session) Stop() error {
	s.cancel()
	<-s.done
	return s.Err()
}

// Done is closed when the reader goroutine has exited.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns the read error that ended the session, if any.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Interface returns the interface name.
func (s *Session) Interface() string { return s.cfg.Interface }

// Started returns when the session started.
func (s *Session) Started() time.Time { return s.started }

// Ended returns when the reader exited (zero while running).
func (s *Session) Ended() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ended
}

// Stats returns the kernel receive/drop counters last observed.
func (s *Session) Stats() (received, dropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finalRecv, s.finalDrop
}

// CaptureInfo summarises one or more sessions sharing an aggregator into
// the metadata stored in a run file. Counters come from the snapshot.
func CaptureInfo(sessions []*Session, snap Snapshot) run.CaptureInfo {
	ci := run.CaptureInfo{Backend: capture.Backend(), StartedAt: snap.Stats.StartedAt, EndedAt: snap.TakenAt}
	for _, s := range sessions {
		ci.Interfaces = append(ci.Interfaces, s.Interface())
		ci.Filter = s.cfg.Capture.Filter
		ci.Promiscuous = s.cfg.Capture.Promiscuous
		if s.started.Before(ci.StartedAt) || ci.StartedAt.IsZero() {
			ci.StartedAt = s.started
		}
		if e := s.Ended(); !e.IsZero() && e.After(ci.EndedAt) {
			ci.EndedAt = e
		}
	}
	ci.PacketsSeen = snap.Stats.Packets
	ci.EventsSeen = snap.Stats.Events
	ci.DecodeErrors = snap.Stats.DecodeErrors
	ci.Dropped = snap.Stats.Dropped
	return ci
}
