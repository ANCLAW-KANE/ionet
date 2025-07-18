package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *model) ipMatchesFilter(ipStr, filterStr string) bool {
	if filterStr == "" {
		return true
	}

	if ipStr == filterStr {
		return true
	}

	if strings.Contains(ipStr, filterStr) {
		return true
	}

	_, cidrNet, err := net.ParseCIDR(filterStr)
	if err == nil {
		ip := net.ParseIP(ipStr)
		if ip != nil && cidrNet.Contains(ip) {
			return true
		}
	}

	return false
}

func (m *model) getIPString(ipv4 uint32, ipv6 [16]uint8) string {
	if ipv4 != 0 {
		return fmt.Sprintf("%d.%d.%d.%d",
			byte(ipv4),
			byte(ipv4>>8),
			byte(ipv4>>16),
			byte(ipv4>>24))
	}

	ip := net.IP(ipv6[:])
	return ip.String()
}

func (m *model) applyFilter() tea.Cmd {
	filterText := m.filter.input.Value()

	if filterText == "" {
		m.filter.rawMode = rawFilter{}
		m.filter.aggMode = aggFilter{}
		m.updateViewportContent()
		return tea.Printf("Filter cleared")
	}

	if m.currentView == "raw" {
		return tea.Batch(
			m.applyRawFilter(filterText),
		)
	} else {
		return tea.Batch(
			m.applyAggFilter(filterText),
		)
	}
}

func (m *model) applyRawFilter(filterText string) tea.Cmd {
	parts := strings.Split(filterText, " ")
	m.filter.rawMode = rawFilter{}

	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}

			key := strings.ToLower(kv[0])
			value := kv[1]

			switch key {
			case "proto", "protocol":
				m.filter.rawMode.protocol = value
			case "src", "srcip":
				m.filter.rawMode.srcIP = value
			case "dst", "dstip":
				m.filter.rawMode.dstIP = value
			case "sport", "srcport":
				m.filter.rawMode.srcPort = value
			case "dport", "dstport":
				m.filter.rawMode.dstPort = value
			case "dir", "direction":
				m.filter.rawMode.direction = value
			}
		}
	}
	m.updateRawView()
	return nil
}

func (m *model) applyAggFilter(filterText string) tea.Cmd {
	parts := strings.Split(filterText, " ")
	m.filter.aggMode = aggFilter{}

	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}

			key := strings.ToLower(kv[0])
			value := kv[1]

			switch key {
			case "proto", "protocol":
				m.filter.aggMode.protocol = value
			case "ip":
				m.filter.aggMode.ip = value
			case "port":
				m.filter.aggMode.port = value
			case "minbytes":
				m.filter.aggMode.minBytes = value
			case "maxbytes":
				m.filter.aggMode.maxBytes = value

			}
		}
	}
	m.updateAggView()
	return nil
}

func (m *model) matchesRawFilter(event StructEvent) bool {
	f := m.filter.rawMode

	if f.protocol != "" {
		protoStr := protoToString(event.key.Protocol)
		if !strings.EqualFold(protoStr, f.protocol) {
			return false
		}
	}

	if f.srcIP != "" {
		srcIP := m.getIPString(event.key.Saddr, event.key.SaddrV6)
		if !m.ipMatchesFilter(srcIP, f.srcIP) {
			return false
		}
	}

	if f.dstIP != "" {
		dstIP := m.getIPString(event.key.Daddr, event.key.DaddrV6)
		if !m.ipMatchesFilter(dstIP, f.dstIP) {
			return false
		}
	}

	if f.srcPort != "" {
		portStr := strconv.Itoa(int(event.key.Sport))
		if portStr != f.srcPort {
			return false
		}
	}

	if f.dstPort != "" {
		portStr := strconv.Itoa(int(event.key.Dport))
		if portStr != f.dstPort {
			return false
		}
	}

	if f.direction != "" {
		dirStr := directionToString(event.key.Direction)
		if !strings.EqualFold(dirStr, f.direction) {
			return false
		}
	}

	return true
}

func (m *model) filterRawEvents(events []StructEvent) []StructEvent {
	if !m.filter.active || (m.filter.rawMode == rawFilter{}) {
		return events
	}

	var filtered []StructEvent
	for _, event := range events {
		if m.matchesRawFilter(event) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func (m *model) matchesAggFilter(key aggKey, val aggVal) bool {
	f := m.filter.aggMode

	if f.protocol != "" {
		protoStr := protoToString(key.Protocol)
		if !strings.EqualFold(protoStr, f.protocol) {
			return false
		}
	}

	if f.ip != "" {
		ipStr := m.getIPString(0, key.IP)
		if !m.ipMatchesFilter(ipStr, f.ip) {
			return false
		}
	}

	if f.port != "" {
		portStr := strconv.Itoa(int(key.Port))
		if portStr != f.port {
			return false
		}
	}

	if f.minBytes != "" {
		minBytes, err := strconv.ParseUint(f.minBytes, 10, 64)
		if err == nil && val.TotalBytes < minBytes {
			return false
		}
	}

	if f.maxBytes != "" {
		maxBytes, err := strconv.ParseUint(f.maxBytes, 10, 64)
		if err == nil && val.TotalBytes > maxBytes {
			return false
		}
	}

	return true
}

func (m *model) filterAggResults(results map[aggKey]aggVal) map[aggKey]aggVal {
	if !m.filter.active || (m.filter.aggMode == aggFilter{}) {
		return results
	}

	filtered := make(map[aggKey]aggVal)
	for key, val := range results {
		if m.matchesAggFilter(key, val) {
			filtered[key] = val
		}
	}
	return filtered
}
