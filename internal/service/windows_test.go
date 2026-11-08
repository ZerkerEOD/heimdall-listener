//go:build windows

package service

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestHandlerStopsOnSCMRequest(t *testing.T) {
	stopped := make(chan struct{})
	h := &handler{log: slog.New(slog.NewTextHandler(os.Stderr, nil)), run: func(ctx context.Context, _ RunConfig, _ *slog.Logger) error {
		<-ctx.Done()
		close(stopped)
		return nil
	}}
	req := make(chan svc.ChangeRequest)
	status := make(chan svc.Status, 8)
	done := make(chan struct{})
	go func() { h.Execute(nil, req, status); close(done) }()
	if s := <-status; s.State != svc.StartPending {
		t.Fatalf("first status %v", s.State)
	}
	if s := <-status; s.State != svc.Running || s.Accepts&svc.AcceptStop == 0 {
		t.Fatalf("second status %+v", s)
	}
	req <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}
	if s := <-status; s.State != svc.Running {
		t.Fatalf("interrogate echo %v", s.State)
	}
	req <- svc.ChangeRequest{Cmd: svc.Stop}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("run not cancelled")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}
}
