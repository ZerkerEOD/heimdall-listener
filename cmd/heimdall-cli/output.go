package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/export"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
	"github.com/ZerkerEOD/heimdall-listener/pkg/version"
)

// toolInfo stamps run files produced by this binary.
func toolInfo() run.ToolInfo {
	return run.ToolInfo{Name: "heimdall-cli", Version: version.Short(), Commit: version.Commit}
}

// jsonEvent is the line format emitted by --jsonl.
type jsonEvent struct {
	Time      time.Time `json:"time"`
	SourceIP  string    `json:"source_ip"`
	DestIP    string    `json:"dest_ip,omitempty"`
	SourceMAC string    `json:"source_mac,omitempty"`
	Protocol  string    `json:"protocol"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	QueryType string    `json:"query_type,omitempty"`
	Answers   []string  `json:"answers,omitempty"`
	WPAD      bool      `json:"wpad"`
	Detail    string    `json:"detail,omitempty"`
}

func toJSONEvent(ev decode.Event) jsonEvent {
	je := jsonEvent{Time: ev.Time.UTC(), SourceIP: ev.SrcIP.String(), Protocol: string(ev.Protocol), Kind: string(ev.Kind),
		Name: ev.Name, QueryType: ev.QueryType, WPAD: ev.WPAD, Detail: ev.Detail}
	if ev.DstIP.IsValid() {
		je.DestIP = ev.DstIP.String()
	}
	if len(ev.SrcMAC) > 0 {
		je.SourceMAC = ev.SrcMAC.String()
	}
	for _, a := range ev.Answers {
		je.Answers = append(je.Answers, a.String())
	}
	return je
}

// jsonlWriter streams events to w from a bounded queue so a slow sink never
// stalls capture. Dropped lines are counted.
type jsonlWriter struct {
	ch      chan decode.Event
	done    chan struct{}
	dropped atomic.Uint64
}

func newJSONLWriter(w io.Writer) *jsonlWriter {
	j := &jsonlWriter{ch: make(chan decode.Event, 4096), done: make(chan struct{})}
	go func() {
		defer close(j.done)
		enc := json.NewEncoder(w)
		for ev := range j.ch {
			_ = enc.Encode(toJSONEvent(ev))
		}
	}()
	return j
}

// Push enqueues an event without blocking.
func (j *jsonlWriter) Push(ev decode.Event) {
	select {
	case j.ch <- ev:
	default:
		j.dropped.Add(1)
	}
}

// Close flushes the queue and waits for the writer.
func (j *jsonlWriter) Close() uint64 {
	close(j.ch)
	<-j.done
	return j.dropped.Load()
}

// outputSpec lists the files a capture should produce.
type outputSpec struct {
	runPath, csvPath, summaryPath, summaryCSVPath string
}

func (o outputSpec) any() bool {
	return o.runPath != "" || o.csvPath != "" || o.summaryPath != "" || o.summaryCSVPath != ""
}

// write produces every requested file. Errors are collected so one failure
// does not lose the other outputs.
func (o outputSpec) write(r *run.Run, stderr io.Writer) error {
	var errs []string
	try := func(path string, fn func(io.Writer) error) {
		if path == "" {
			return
		}
		if err := writeFile(path, fn); err != nil {
			errs = append(errs, err.Error())
			return
		}
		fmt.Fprintf(stderr, "wrote %s\n", path)
	}
	if o.runPath != "" {
		if err := run.Save(o.runPath, r); err != nil {
			errs = append(errs, err.Error())
		} else {
			fmt.Fprintf(stderr, "wrote %s\n", o.runPath)
		}
	}
	try(o.csvPath, func(w io.Writer) error { return export.WriteCSV(w, r) })
	try(o.summaryPath, func(w io.Writer) error { return export.WriteSummaryText(w, r) })
	try(o.summaryCSVPath, func(w io.Writer) error { return export.WriteSummaryCSV(w, r) })
	if len(errs) > 0 {
		return fmt.Errorf("writing outputs: %s", strings.Join(errs, "; "))
	}
	return nil
}

// writeFile writes through a temp file in the destination directory and
// renames it into place.
func writeFile(path string, fn func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := fn(tmp); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// openOutput returns stdout for "" or "-", otherwise creates the file.
func openOutput(path string, stdout io.Writer) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return stdout, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
