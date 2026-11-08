package decode

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
)

// httpWPADEvent recognises an HTTP request for wpad.dat in a TCP payload.
// Only the first segment of a request is inspected; that is where the
// request line and Host header live in practice.
func httpWPADEvent(payload []byte, base Event) []Event {
	if len(payload) < 16 {
		return nil
	}
	var method string
	switch {
	case bytes.HasPrefix(payload, []byte("GET ")):
		method = "GET"
	case bytes.HasPrefix(payload, []byte("HEAD ")):
		method = "HEAD"
	default:
		return nil
	}
	end := bytes.IndexByte(payload, '\n')
	if end < 0 {
		end = len(payload)
	}
	line := payload[:end]
	fields := bytes.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	target := string(fields[1])
	if !strings.Contains(strings.ToLower(target), "wpad.dat") {
		return nil
	}

	host := ""
	head := payload
	if len(head) > 2048 {
		head = head[:2048]
	}
	for _, l := range bytes.Split(head, []byte("\n")) {
		l = bytes.TrimRight(l, "\r")
		if len(l) > 5 && strings.EqualFold(string(l[:5]), "host:") {
			host = strings.ToLower(strings.TrimSpace(string(l[5:])))
			break
		}
	}
	if host == "" {
		host = base.DstIP.String()
	}

	ev := base
	ev.Protocol = ProtoHTTP
	ev.Kind = KindQuery
	ev.QueryType = method
	ev.Name = host + "/wpad.dat"
	ev.WPAD = true
	ev.Answers = []netip.Addr{base.DstIP}
	ev.Detail = fmt.Sprintf("HTTP %s %s (Host: %s) %s -> %s", method, target, host, base.SrcIP, base.DstIP)
	return []Event{ev}
}
