package decode

import "strings"

// IsWPADName reports whether a normalized name refers to WPAD: its first
// label is "wpad" (covers "wpad", "wpad.corp.local" and NetBIOS "wpad<00>").
func IsWPADName(name string) bool {
	name = strings.ToLower(name)
	if name == "" {
		return false
	}
	first := name
	if i := strings.IndexAny(name, ".<"); i >= 0 {
		first = name[:i]
	}
	return first == "wpad"
}

// normalizeName lowercases a DNS name and strips the trailing root dot.
func normalizeName(b []byte) string {
	s := strings.ToLower(string(b))
	s = strings.TrimSuffix(s, ".")
	return s
}
