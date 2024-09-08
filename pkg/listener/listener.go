package listener

import (
	"bytes"
	"log"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketData struct {
	SourceIP          string
	Protocol          string
	RequestedHostname string
	FullRequest       string
}

var (
	handle        *pcap.Handle
	stopListening chan bool
	DataChannel   chan PacketData
	mu            sync.Mutex
)

func Init() {
	stopListening = make(chan bool)
	DataChannel = make(chan PacketData, 100)
}

func StartListening(interfaceName string) {
	var err error
	handle, err = pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening interface %s: %v", interfaceName, err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-stopListening:
			return
		default:
			processPacket(packet)
		}
	}
}

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	var protocol, requestedHostname, fullRequest string

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		protocol = "UDP"
		fullRequest = string(udp.Payload)

		// Check for LLMNR (port 5355)
		if udp.DstPort == 5355 || udp.SrcPort == 5355 {
			requestedHostname = extractLLMNRName(udp.Payload)
			if requestedHostname != "" {
				protocol = "LLMNR"
			}
		}

		// Check for mDNS (port 5353)
		if udp.DstPort == 5353 || udp.SrcPort == 5353 {
			requestedHostname = extractMDNSName(udp.Payload)
			if requestedHostname != "" {
				protocol = "mDNS"
			}
		}

		// Check for NetBIOS (port 137)
		if udp.DstPort == 137 || udp.SrcPort == 137 {
			requestedHostname = extractNetBIOSName(udp.Payload)
			if requestedHostname != "" {
				protocol = "NetBIOS"
			}
		}
	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		protocol = "TCP"
		fullRequest = string(tcp.Payload)

		// Check for "wpad.dat" in the payload
		if bytes.Contains(tcp.Payload, []byte("wpad.dat")) {
			requestedHostname = "wpad.dat request"
			protocol = "WPAD"
		}
	}

	// Only send data if it's a relevant protocol
	if protocol == "LLMNR" || protocol == "mDNS" || protocol == "NetBIOS" || protocol == "WPAD" {
		DataChannel <- PacketData{
			SourceIP:          ip.SrcIP.String(),
			Protocol:          protocol,
			RequestedHostname: requestedHostname,
			FullRequest:       fullRequest,
		}
	}
}

func extractLLMNRName(payload []byte) string {
	// Simple LLMNR name extraction (this is a basic implementation and might need refinement)
	if len(payload) > 13 {
		nameLength := int(payload[12])
		if len(payload) >= 13+nameLength {
			return string(payload[13 : 13+nameLength])
		}
	}
	return ""
}

func extractMDNSName(payload []byte) string {
	// Simple mDNS name extraction (this is a basic implementation and might need refinement)
	if len(payload) > 12 {
		var name strings.Builder
		for i := 12; i < len(payload); i++ {
			if payload[i] == 0 {
				break
			}
			if payload[i] < 32 {
				name.WriteByte('.')
			} else {
				name.WriteByte(payload[i])
			}
		}
		return name.String()
	}
	return ""
}

func extractNetBIOSName(payload []byte) string {
	// Simple NetBIOS name extraction (this is a basic implementation and might need refinement)
	if len(payload) > 57 {
		var name strings.Builder
		for i := 57; i < 57+16; i += 2 {
			if payload[i] == 0 {
				break
			}
			name.WriteByte((payload[i]-'A')<<4 | (payload[i+1] - 'A'))
		}
		return strings.TrimRight(name.String(), " ")
	}
	return ""
}

func StopListening() {
	mu.Lock()
	defer mu.Unlock()
	if handle != nil {
		stopListening <- true
		handle.Close()
		handle = nil
	}
}

func CheckElevatedPrivileges() string {
	return "Warning: This application must be run with elevated privileges"
}
