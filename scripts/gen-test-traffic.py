#!/usr/bin/env python3
"""Self-test traffic generator for Heimdall Listener.

This script is a TEST HARNESS and is not part of the listener: it transmits
LLMNR, NetBIOS, mDNS and DHCPv6 lookups (and, in "responder" mode, fake LLMNR
answers) so you can confirm a capture sees them. Run it on a lab network or
your own segment only.

  python3 scripts/gen-test-traffic.py <interface> [full|partial|responder]

full       LLMNR (v4+v6), NetBIOS, mDNS, DHCPv6 Solicit          (default)
partial    LLMNR and mDNS only (simulates "NetBIOS/DHCPv6 remediated")
responder  three fake LLMNR answers from this host to the gateway, which
           must raise the llmnr-nbns-responder alert on this host's IP
"""
import json, socket, struct, subprocess, sys, time

IFACE = sys.argv[1]
MODE = sys.argv[2] if len(sys.argv) > 2 else "full"

addrs = json.loads(subprocess.check_output(["ip", "-j", "addr", "show", IFACE]))[0]
v4 = next(a for a in addrs["addr_info"] if a["family"] == "inet")
my4, bcast = v4["local"], v4.get("broadcast")
ifindex = socket.if_nametoindex(IFACE)

def dns_query(qid, name, qtype, qclass=1):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, qclass)

def dns_response(qid, name, ip):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    rr = q + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(ip)
    return struct.pack(">HHHHHH", qid, 0x8400, 0, 1, 0, 0) + rr

def nb_encode(name, suffix):
    raw = name.upper().ljust(15).encode()[:15] + bytes([suffix])
    return "".join(chr(65 + (b >> 4)) + chr(65 + (b & 15)) for b in raw)

def nbns_query(qid, name, suffix):
    return struct.pack(">HHHHHH", qid, 0x0110, 1, 0, 0, 0) + b"\x20" + nb_encode(name, suffix).encode() + b"\x00" + struct.pack(">HH", 0x20, 1)

def dhcpv6_solicit(fqdn):
    duid = b"\x00\x01\x00\x01\xde\xad\xbe\xef\x00\x11\x22\x33\x44\x55"
    opts = struct.pack(">HH", 1, len(duid)) + duid + struct.pack(">HHH", 8, 2, 0)
    labels = b"".join(bytes([len(l)]) + l.encode() for l in fqdn.split(".")) + b"\x00"
    opts += struct.pack(">HH", 39, 1 + len(labels)) + b"\x00" + labels
    return b"\x01\x0a\x0b\x0c" + opts

s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(my4))
s4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)

gw = next((r["gateway"] for r in json.loads(subprocess.check_output(["ip", "-j", "route"])) if r.get("dst") == "default"), None)
sent = 0
if MODE == "responder":
    # Simulated poisoner only: answer "wpad" and two other names from port 5355 to the gateway (exists in ARP).
    r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r.bind((my4, 5355))
    for i, name in enumerate(["wpad", "fileserver01", "nas"]):
        r.sendto(dns_response(0x2000 + i, name, my4), (gw, 51000)); sent += 1
        time.sleep(0.2)
    print("generator sent", sent, "responses to", gw)
    sys.exit(0)
for i in range(3):
    s4.sendto(dns_query(0x1000 + i, "wpad", 1), ("224.0.0.252", 5355)); sent += 1
    s4.sendto(dns_query(0x1100 + i, "fileserver01", 1), ("224.0.0.252", 5355)); sent += 1
    s6.sendto(dns_query(0x1200 + i, "wpad", 28), ("ff02::1:3", 5355, 0, ifindex)); sent += 1
    s4.sendto(dns_query(0, "_ipp._tcp.local", 12, 0x8001), ("224.0.0.251", 5353)); sent += 1
    s6.sendto(dns_query(0, "printer-lobby.local", 1), ("ff02::fb", 5353, 0, ifindex)); sent += 1
    if MODE == "full":
        if bcast:
            s4.sendto(nbns_query(0x8000 + i, "FILESRV", 0x20), (bcast, 137)); sent += 1
            s4.sendto(nbns_query(0x8100 + i, "WPAD", 0x00), (bcast, 137)); sent += 1
        s6.sendto(dhcpv6_solicit("testbox.corp.local"), ("ff02::1:2", 547, 0, ifindex)); sent += 1
    time.sleep(0.3)

print("generator sent", sent, "datagrams from", my4, "on", IFACE)
