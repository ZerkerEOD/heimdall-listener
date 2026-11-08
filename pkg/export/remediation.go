// Package export renders runs and diffs as CSV, text summaries and
// per-host remediation reports.
package export

import (
	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// Exposure describes why a protocol matters and how to turn it off.
type Exposure struct {
	Protocol    decode.Protocol
	Risk        string // what an attacker does with it
	Tools       string // attacker tooling that abuses it
	Remediation []string
}

var exposures = map[decode.Protocol]Exposure{
	decode.ProtoLLMNR: {
		Protocol: decode.ProtoLLMNR,
		Risk:     "Hosts that fall back to LLMNR accept name answers from anyone on the segment, letting an attacker capture or relay NTLM credentials.",
		Tools:    "Responder, Inveigh, ntlmrelayx",
		Remediation: []string{
			"Disable LLMNR by Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > \"Turn off multicast name resolution\" = Enabled.",
			"Registry equivalent: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0 (DWORD).",
			"Linux: set LLMNR=no in /etc/systemd/resolved.conf and restart systemd-resolved.",
			"Fix the root cause of the lookups: typos, stale drive mappings, scripts or printers referring to names that no longer resolve in DNS.",
		},
	},
	decode.ProtoNBNS: {
		Protocol: decode.ProtoNBNS,
		Risk:     "NetBIOS name service broadcasts are answered by anyone; poisoned answers lead to credential capture and SMB relay.",
		Tools:    "Responder, Inveigh, ntlmrelayx",
		Remediation: []string{
			"Disable NetBIOS over TCP/IP: adapter > IPv4 > Advanced > WINS > \"Disable NetBIOS over TCP/IP\".",
			"Fleet-wide: DHCP scope option 001 \"Microsoft Disable Netbios Option\" = 0x2, or registry HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_*\\NetbiosOptions = 2.",
			"Linux hosts broadcasting NBNS are usually running Samba's nmbd; stop/disable it if WINS browsing is not needed.",
			"Check for the Computer Browser service and legacy applications that still rely on NetBIOS names.",
		},
	},
	decode.ProtoMDNS: {
		Protocol: decode.ProtoMDNS,
		Risk:     "mDNS answers are trusted from any host on the link; Windows falls back to it like LLMNR, and poisoned answers enable credential capture.",
		Tools:    "Responder, Inveigh",
		Remediation: []string{
			"Windows: disable mDNS if not needed: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\EnableMDNS = 0 (DWORD), or block UDP 5353 outbound with Windows Firewall.",
			"Where mDNS is required (printers, AirPlay, Chromecast), keep it but confine it to the VLANs that need it with firewall rules rather than routing it everywhere.",
			"Linux/macOS: Avahi/Bonjour are normally legitimate; review what services each host advertises.",
		},
	},
	decode.ProtoDNS: {
		Protocol: decode.ProtoDNS,
		Risk:     "A WPAD lookup that fails in DNS falls back to LLMNR/NetBIOS, where an attacker can supply a malicious proxy auto-config and harvest credentials.",
		Tools:    "Responder (WPAD/proxy auth), ntlmrelayx, mitm6",
		Remediation: []string{
			"Turn off proxy auto-detection: Group Policy > User Configuration > Windows Components > Internet Explorer > \"Disable caching of Auto-Proxy scripts\" / Internet Settings > Connections > LAN Settings > \"Automatically detect settings\" = off. Push an explicit PAC URL or proxy instead.",
			"Create a wpad A record in every internal DNS zone pointing at your sanctioned PAC server, so the lookup never falls back to multicast/broadcast.",
			"Keep \"wpad\" on the DNS Global Query Block List only if auto-detect is also disabled on clients; otherwise the blocked lookup triggers the fallback you are trying to prevent.",
		},
	},
	decode.ProtoDHCPv6: {
		Protocol: decode.ProtoDHCPv6,
		Risk:     "Windows asks for DHCPv6 even on IPv4-only networks and accepts the first answer; a rogue server becomes the host's DNS server and can relay captured credentials.",
		Tools:    "mitm6 + ntlmrelayx",
		Remediation: []string{
			"If IPv6 is not deployed, block inbound DHCPv6 (UDP 546) and rogue Router Advertisements on hosts with Windows Firewall, or set IPv6 to prefer IPv4 (DisabledComponents = 0x20). Microsoft advises against fully disabling IPv6.",
			"Enable DHCPv6 Guard and RA Guard on access switches so only the legitimate server/router ports may send them.",
			"If you do run DHCPv6, add your servers with --trusted-dhcpv6 so they are not flagged.",
		},
	},
	decode.ProtoHTTP: {
		Protocol: decode.ProtoHTTP,
		Risk:     "The host downloaded a proxy auto-config (wpad.dat). If the server was poisoned, the attacker now controls the host's proxy and can demand credentials.",
		Tools:    "Responder (WPAD), ntlmrelayx",
		Remediation: []string{
			"Verify the wpad.dat server is the sanctioned PAC host; see the alerts section if it also answered name lookups.",
			"Disable \"Automatically detect settings\" via Group Policy and configure the proxy explicitly where one is needed.",
		},
	},
}

// ExposureFor returns the exposure description for a protocol.
func ExposureFor(p decode.Protocol) (Exposure, bool) {
	e, ok := exposures[p]
	return e, ok
}

// AlertAdvice returns remediation guidance for an alert rule.
func AlertAdvice(a run.Alert) []string {
	switch a.Rule {
	case "llmnr-nbns-responder":
		return []string{
			"Treat this host as a suspected poisoner: identify it (switch port/MAC " + a.SourceIP + "), isolate it, and check for Responder, Inveigh or similar tooling.",
			"Credentials of any host that resolved names during this window may have been captured; rotate them if the host turns out to be hostile.",
			"Disabling LLMNR and NetBIOS fleet-wide removes the attack surface regardless of this host.",
		}
	case "mdns-responder":
		return []string{
			"Confirm whether this host is a legitimate Bonjour/mDNS reflector, printer or media device.",
			"If not, treat it like an LLMNR poisoner and isolate it.",
		}
	case "dhcpv6-server":
		return []string{
			"If this is not your DHCPv6 server, it is very likely mitm6: isolate the host immediately and check which clients received leases from it (their DNS now points at the attacker).",
			"Enable DHCPv6 Guard / RA Guard on switches and block UDP 546 inbound on hosts that do not need IPv6 configuration.",
			"If it is legitimate, run with --trusted-dhcpv6 " + a.SourceIP + " to suppress this alert.",
		}
	case "wpad-http-server":
		return []string{
			"Confirm this host is the sanctioned PAC/WPAD server. If it also appears as a name responder, assume credential capture and isolate it.",
			"Disable proxy auto-detection on clients and push the proxy configuration explicitly.",
		}
	default:
		return nil
	}
}
