package run

import (
	"sort"
	"time"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
)

// Status classifies a diff item relative to the baseline.
type Status string

const (
	StatusNew       Status = "new"       // present now, absent in baseline
	StatusResolved  Status = "resolved"  // present in baseline, gone now
	StatusUnchanged Status = "unchanged" // present in both
)

// PairKey identifies "host X doing protocol P as kind K", the unit admins
// remediate (for example: 10.0.0.5 sends LLMNR queries).
type PairKey struct {
	SourceIP string          `json:"source_ip"`
	Protocol decode.Protocol `json:"protocol"`
	Kind     decode.Kind     `json:"kind"`
}

// NameDiff is one name inside a pair.
type NameDiff struct {
	Name          string `json:"name"`
	Status        Status `json:"status"`
	WPAD          bool   `json:"wpad"`
	BaselineCount uint64 `json:"baseline_count"`
	CurrentCount  uint64 `json:"current_count"`
}

// PairDiff is the diff of one (host, protocol, kind) pair.
type PairDiff struct {
	PairKey
	Status        Status     `json:"status"`
	Names         []NameDiff `json:"names"`
	BaselineCount uint64     `json:"baseline_count"`
	CurrentCount  uint64     `json:"current_count"`
	WPAD          bool       `json:"wpad"`
	// HostNew / HostResolved are set when the whole host appeared or vanished.
	HostNew      bool `json:"host_new"`
	HostResolved bool `json:"host_resolved"`
}

// AlertDiff is an alert that appeared, cleared, or persisted.
type AlertDiff struct {
	Alert
	Status Status `json:"status"`
}

// Ref describes one side of the comparison.
type Ref struct {
	Path       string    `json:"path,omitempty"`
	Interfaces []string  `json:"interfaces"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at"`
	Entries    int       `json:"entries"`
	Hosts      int       `json:"hosts"`
}

// Summary counts the diff.
type Summary struct {
	NewPairs       int `json:"new_pairs"`
	ResolvedPairs  int `json:"resolved_pairs"`
	UnchangedPairs int `json:"unchanged_pairs"`
	NewHosts       int `json:"new_hosts"`
	ResolvedHosts  int `json:"resolved_hosts"`
	NewWPAD        int `json:"new_wpad"`
	ResolvedWPAD   int `json:"resolved_wpad"`
	NewAlerts      int `json:"new_alerts"`
	ClearedAlerts  int `json:"cleared_alerts"`
}

// DiffResult is the full comparison.
type DiffResult struct {
	Baseline Ref         `json:"baseline"`
	Current  Ref         `json:"current"`
	Pairs    []PairDiff  `json:"pairs"`
	Alerts   []AlertDiff `json:"alerts"`
	Summary  Summary     `json:"summary"`
}

// ByStatus returns the pairs with the given status, in order.
func (d *DiffResult) ByStatus(s Status) []PairDiff {
	var out []PairDiff
	for _, p := range d.Pairs {
		if p.Status == s {
			out = append(out, p)
		}
	}
	return out
}

func ref(r *Run, path string) Ref {
	return Ref{Path: path, Interfaces: r.Capture.Interfaces, StartedAt: r.Capture.StartedAt, EndedAt: r.Capture.EndedAt,
		Entries: len(r.Entries), Hosts: len(r.Hosts())}
}

// Diff compares current against baseline. basePath/curPath are informational.
func Diff(baseline, current *Run, basePath, curPath string) *DiffResult {
	type nameMap map[string]Entry
	index := func(r *Run) (map[PairKey]nameMap, map[string]struct{}) {
		pairs := map[PairKey]nameMap{}
		hosts := map[string]struct{}{}
		for _, e := range r.Entries {
			k := PairKey{e.SourceIP, e.Protocol, e.Kind}
			if pairs[k] == nil {
				pairs[k] = nameMap{}
			}
			pairs[k][e.Name] = e
			hosts[e.SourceIP] = struct{}{}
		}
		return pairs, hosts
	}
	bp, bh := index(baseline)
	cp, ch := index(current)

	keys := map[PairKey]struct{}{}
	for k := range bp {
		keys[k] = struct{}{}
	}
	for k := range cp {
		keys[k] = struct{}{}
	}
	sorted := make([]PairKey, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if c := CompareIP(a.SourceIP, b.SourceIP); c != 0 {
			return c < 0
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Kind < b.Kind
	})

	res := &DiffResult{Baseline: ref(baseline, basePath), Current: ref(current, curPath)}
	for _, k := range sorted {
		b, inB := bp[k]
		c, inC := cp[k]
		pd := PairDiff{PairKey: k}
		switch {
		case inB && inC:
			pd.Status = StatusUnchanged
		case inC:
			pd.Status = StatusNew
		default:
			pd.Status = StatusResolved
		}
		_, hb := bh[k.SourceIP]
		_, hc := ch[k.SourceIP]
		pd.HostNew = hc && !hb
		pd.HostResolved = hb && !hc

		names := map[string]struct{}{}
		for n := range b {
			names[n] = struct{}{}
		}
		for n := range c {
			names[n] = struct{}{}
		}
		for n := range names {
			be, inBN := b[n]
			ce, inCN := c[n]
			nd := NameDiff{Name: n, BaselineCount: be.Count, CurrentCount: ce.Count, WPAD: be.WPAD || ce.WPAD}
			switch {
			case inBN && inCN:
				nd.Status = StatusUnchanged
			case inCN:
				nd.Status = StatusNew
			default:
				nd.Status = StatusResolved
			}
			pd.Names = append(pd.Names, nd)
			pd.BaselineCount += be.Count
			pd.CurrentCount += ce.Count
			pd.WPAD = pd.WPAD || nd.WPAD
		}
		sort.Slice(pd.Names, func(i, j int) bool { return pd.Names[i].Name < pd.Names[j].Name })
		res.Pairs = append(res.Pairs, pd)

		switch pd.Status {
		case StatusNew:
			res.Summary.NewPairs++
			if pd.WPAD {
				res.Summary.NewWPAD++
			}
		case StatusResolved:
			res.Summary.ResolvedPairs++
			if pd.WPAD {
				res.Summary.ResolvedWPAD++
			}
		default:
			res.Summary.UnchangedPairs++
		}
	}
	for h := range ch {
		if _, ok := bh[h]; !ok {
			res.Summary.NewHosts++
		}
	}
	for h := range bh {
		if _, ok := ch[h]; !ok {
			res.Summary.ResolvedHosts++
		}
	}

	// Alerts keyed by stable ID.
	ba := map[string]Alert{}
	for _, a := range baseline.Alerts {
		ba[a.ID] = a
	}
	ca := map[string]Alert{}
	for _, a := range current.Alerts {
		ca[a.ID] = a
	}
	for id, a := range ca {
		if _, ok := ba[id]; ok {
			res.Alerts = append(res.Alerts, AlertDiff{Alert: a, Status: StatusUnchanged})
		} else {
			res.Alerts = append(res.Alerts, AlertDiff{Alert: a, Status: StatusNew})
			res.Summary.NewAlerts++
		}
	}
	for id, a := range ba {
		if _, ok := ca[id]; !ok {
			res.Alerts = append(res.Alerts, AlertDiff{Alert: a, Status: StatusResolved})
			res.Summary.ClearedAlerts++
		}
	}
	sort.Slice(res.Alerts, func(i, j int) bool {
		a, b := res.Alerts[i], res.Alerts[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if c := CompareIP(a.SourceIP, b.SourceIP); c != 0 {
			return c < 0
		}
		return a.Rule < b.Rule
	})
	return res
}
