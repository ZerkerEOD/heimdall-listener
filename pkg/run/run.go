// Package run defines the saved-run file format shared by the GUI and CLI,
// and the diff between two runs. Files are JSON so they can be inspected,
// versioned and fed to other tools.
package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
)

// SchemaVersion is bumped when the file format changes incompatibly.
const SchemaVersion = 1

// ToolInfo records which build produced the file.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// HostInfo records where the capture ran.
type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

// CaptureInfo records how the capture was performed.
type CaptureInfo struct {
	Interfaces   []string  `json:"interfaces"`
	Backend      string    `json:"backend"`
	Filter       string    `json:"filter"`
	Promiscuous  bool      `json:"promiscuous"`
	StartedAt    time.Time `json:"started_at"`
	EndedAt      time.Time `json:"ended_at"`
	PacketsSeen  uint64    `json:"packets_seen"`
	EventsSeen   uint64    `json:"events_seen"`
	DecodeErrors uint64    `json:"decode_errors"`
	Dropped      uint64    `json:"dropped"`
}

// Duration is the capture length (zero if the run never ended).
func (c CaptureInfo) Duration() time.Duration {
	if c.EndedAt.IsZero() || c.StartedAt.IsZero() {
		return 0
	}
	return c.EndedAt.Sub(c.StartedAt)
}

// Entry is one aggregated observation: a source host doing one kind of
// thing with one name, counted over the run.
type Entry struct {
	SourceIP   string          `json:"source_ip"`
	SourceMAC  string          `json:"source_mac,omitempty"`
	Protocol   decode.Protocol `json:"protocol"`
	Kind       decode.Kind     `json:"kind"`
	Name       string          `json:"name"`
	WPAD       bool            `json:"wpad"`
	QueryTypes []string        `json:"query_types,omitempty"`
	Answers    []string        `json:"answers,omitempty"`
	Count      uint64          `json:"count"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	LastDetail string          `json:"last_detail,omitempty"`
}

// Severity ranks alerts.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

// Rank orders severities, highest first.
func (s Severity) Rank() int {
	switch s {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 2
	default:
		return 3
	}
}

// Alert is a passive detection: a host behaving like a poisoner or rogue
// server. Alerts are derived purely from observed traffic.
type Alert struct {
	ID        string          `json:"id"` // stable: rule|source_ip
	Rule      string          `json:"rule"`
	Severity  Severity        `json:"severity"`
	SourceIP  string          `json:"source_ip"`
	Protocol  decode.Protocol `json:"protocol,omitempty"`
	Title     string          `json:"title"`
	Evidence  string          `json:"evidence"`
	Names     []string        `json:"names,omitempty"`
	FirstSeen time.Time       `json:"first_seen"`
	LastSeen  time.Time       `json:"last_seen"`
	Count     uint64          `json:"count"`
}

// Run is a complete saved capture.
type Run struct {
	SchemaVersion int         `json:"schema_version"`
	Tool          ToolInfo    `json:"tool"`
	Host          HostInfo    `json:"host"`
	Capture       CaptureInfo `json:"capture"`
	Entries       []Entry     `json:"entries"`
	Alerts        []Alert     `json:"alerts"`
}

// New returns an empty run stamped with the current schema, tool and host.
func New(tool ToolInfo) *Run {
	hn, _ := os.Hostname()
	return &Run{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		Host:          HostInfo{Hostname: hn, OS: runtime.GOOS, Arch: runtime.GOARCH},
		Entries:       []Entry{},
		Alerts:        []Alert{},
	}
}

// ErrSchema is returned for files written by a newer, incompatible version.
var ErrSchema = errors.New("run: unsupported schema version")

// Write encodes r as indented JSON after sorting it deterministically.
func Write(w io.Writer, r *Run) error {
	r.Sort()
	if r.SchemaVersion == 0 {
		r.SchemaVersion = SchemaVersion
	}
	if r.Entries == nil {
		r.Entries = []Entry{}
	}
	if r.Alerts == nil {
		r.Alerts = []Alert{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Save writes r to path atomically (temp file in the same directory, then
// rename) so a snapshot being read by another process is never truncated.
func Save(path string, r *Run) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("run: save %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := Write(tmp, r); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("run: save %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("run: save %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("run: save %s: %w", path, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		cleanup()
		return fmt.Errorf("run: save %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("run: save %s: %w", path, err)
	}
	return nil
}

// Read decodes a run and validates its schema version.
func Read(rd io.Reader) (*Run, error) {
	var r Run
	dec := json.NewDecoder(rd)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("run: parse: %w", err)
	}
	if r.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%w: file is version %d, this build reads up to %d", ErrSchema, r.SchemaVersion, SchemaVersion)
	}
	if r.SchemaVersion == 0 {
		return nil, fmt.Errorf("run: parse: not a heimdall run file (missing schema_version)")
	}
	if r.Entries == nil {
		r.Entries = []Entry{}
	}
	if r.Alerts == nil {
		r.Alerts = []Alert{}
	}
	r.Sort()
	return &r, nil
}

// Load reads a run file from disk.
func Load(path string) (*Run, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("run: open: %w", err)
	}
	defer f.Close()
	r, err := Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// Sort orders entries by (source IP, protocol, kind, name) and alerts by
// (severity, source IP, rule) so output is deterministic.
func (r *Run) Sort() {
	sort.SliceStable(r.Entries, func(i, j int) bool {
		a, b := r.Entries[i], r.Entries[j]
		if c := CompareIP(a.SourceIP, b.SourceIP); c != 0 {
			return c < 0
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	sort.SliceStable(r.Alerts, func(i, j int) bool {
		a, b := r.Alerts[i], r.Alerts[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if c := CompareIP(a.SourceIP, b.SourceIP); c != 0 {
			return c < 0
		}
		return a.Rule < b.Rule
	})
}

// Filter returns a shallow copy of r keeping only entries for which pred is
// true. Alerts and metadata are kept as-is.
func (r *Run) Filter(pred func(Entry) bool) *Run {
	out := *r
	out.Entries = make([]Entry, 0, len(r.Entries))
	for _, e := range r.Entries {
		if pred(e) {
			out.Entries = append(out.Entries, e)
		}
	}
	return &out
}

// Hosts returns the distinct source IPs in address order.
func (r *Run) Hosts() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, e := range r.Entries {
		if _, ok := seen[e.SourceIP]; !ok {
			seen[e.SourceIP] = struct{}{}
			out = append(out, e.SourceIP)
		}
	}
	sort.Slice(out, func(i, j int) bool { return CompareIP(out[i], out[j]) < 0 })
	return out
}

// CompareIP orders IP strings numerically (IPv4 before IPv6), falling back
// to string comparison for unparsable values.
func CompareIP(a, b string) int {
	pa, ea := netip.ParseAddr(a)
	pb, eb := netip.ParseAddr(b)
	switch {
	case ea == nil && eb == nil:
		return pa.Compare(pb)
	case ea == nil:
		return -1
	case eb == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}
