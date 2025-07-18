package main

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket/layers"
)

var ipClassCache sync.Map

func parseBytes(b uint64) string {

	switch {
	case b >= PB:
		return fmt.Sprintf("%.2f PB", float64(b)/PB)
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/TB)
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/GB)
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/MB)
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/KB)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func protoToString(proto uint8) string {
	return layers.IPProtocol(proto).String()
}

func directionToString(dir byte) string {
	if dir == 'i' {
		return DIRECTION_INGRESS
	}
	return DIRECTION_EGRESS
}

func isLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ipv4 := ip.To4()
	if ipv4 != nil {
		return ipv4.IsLoopback() || ipv4.IsPrivate() || ipv4.IsMulticast()
	}

	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		(ip[0] == 0xfe && (ip[1]&0xc0) == 0x80) ||
		ip.IsMulticast()

}

func classifyIP(ip net.IP) string {
	if ip == nil {
		return "Invalid"
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		if isLocalIP(ipv4) {
			return IP_TYPE_V4_LOCAL
		}
		return IP_TYPE_V4_EXTERNAL
	}

	if isLocalIP(ip) {
		return IP_TYPE_V6_LOCAL
	}
	return IP_TYPE_V6_EXTERNAL
}

func classifyIPCached(ip net.IP) string {
	ipStr := ip.String()
	if val, ok := ipClassCache.Load(ipStr); ok {
		return val.(string)
	}
	result := classifyIP(ip)
	ipClassCache.Store(ipStr, result)
	return result
}

func getInterfaceName(index uint32) string {
	iface, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return "Unknown"
	}

	return iface.Name
}

func getPacketTypeName(pktType uint32) string {
	switch pktType {
	case 0:
		return PKT_TYPE_HOST
	case 1:
		return PKT_TYPE_BROADCAST
	case 2:
		return PKT_TYPE_MULTICAST
	case 3:
		return PKT_TYPE_OTHERHOST
	case 4:
		return PKT_TYPE_OUTGOING
	case 5:
		return PKT_TYPE_LOOPBACK
	case 6:
		return PKT_TYPE_FASTROUTE
	default:
		return fmt.Sprintf("UNKNOWN(%d)", pktType)
	}
}

func fixedWidth(s string, width int) string {
	runes := []rune(s)
	if len(runes) > width {
		return string(runes[:width])
	}
	return s + strings.Repeat(" ", width-len(runes))
}

func uint32ToIPv4(addr uint32) net.IP {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	)
}

func getIPsFromEvent(ev StructEvent) (net.IP, net.IP) {
	switch ev.key.Family {
	case 2:

		srcIP := uint32ToIPv4(ev.key.Saddr)
		dstIP := uint32ToIPv4(ev.key.Daddr)
		return srcIP, dstIP
	case 10:

		srcIP := net.IP(ev.key.SaddrV6[:])
		dstIP := net.IP(ev.key.DaddrV6[:])
		return srcIP, dstIP
	}
	return nil, nil
}

func getIPPort(ev StructEvent) (net.IP, uint16) {
	srcIP, dstIP := getIPsFromEvent(ev)
	if ev.key.Direction == 'o' {
		return dstIP, ev.key.Dport
	}
	return srcIP, ev.key.Sport
}

func ip16ToBytes(ip net.IP) [16]byte {
	var ipBytes [16]byte
	copy(ipBytes[:], ip.To16())
	return ipBytes
}

func bytesToIP(ipBytes [16]byte) net.IP {
	ip := net.IP(ipBytes[:])

	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}

	return ip
}
