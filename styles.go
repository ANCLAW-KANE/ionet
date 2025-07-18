package main

import (
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
)

var (
	protoStyles     = make(map[uint8]lipgloss.Style)
	dirStyles       = make(map[byte]lipgloss.Style)
	protoStyleCache = make(map[uint8]lipgloss.Style)
	dirStyleCache   = make(map[byte]lipgloss.Style)
	styleMutex      sync.RWMutex
)

var (
	coloredSeparator = lipgloss.NewStyle().Foreground(lipgloss.Color("#5A56E0")).Render("│")
	coloredLine      = lipgloss.NewStyle().Foreground(lipgloss.Color("#5A56E0")).Render("─")
	coloredCross     = lipgloss.NewStyle().Foreground(lipgloss.Color("#5A56E0")).Render("┼")

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#5A56E0")).
			Padding(0, 1).
			Bold(true)

	tableStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#5A56E0"))

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#3C3C3C")).
			Padding(0, 1)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Bold(true)

	MagentaStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF"))

	RedTextSyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
	GreenTextSyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))

	TypeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500"))
)

func directionColor(direction string) lipgloss.Color {
	if direction == "i" {
		return lipgloss.Color("#00FF00")
	}
	return lipgloss.Color("#FF0000")
}

func protocolColor(protocol string) lipgloss.Color {
	protocol = strings.ToUpper(strings.TrimSpace(protocol))

	switch {
	case protocol == "TCP":
		return lipgloss.Color("#FF6B6B")
	case protocol == "UDP":
		return lipgloss.Color("#4ECDC4")
	case strings.Contains(protocol, "ICMP"):
		return lipgloss.Color("#FFBE0B")
	case protocol == "HTTP":
		return lipgloss.Color("#48BFE3")
	case protocol == "HTTPS":
		return lipgloss.Color("#56CFE1")
	case protocol == "DNS":
		return lipgloss.Color("#7209B7")
	case protocol == "SSH":
		return lipgloss.Color("#2EC4B6")
	case protocol == "FTP":
		return lipgloss.Color("#F77F00")
	case protocol == "DHCP":
		return lipgloss.Color("#9B5DE5")
	default:
		return lipgloss.Color("#ADB5BD")
	}
}

func getProtoStyle(proto uint8) lipgloss.Style {
	styleMutex.RLock()
	if s, ok := protoStyles[proto]; ok {
		styleMutex.RUnlock()
		return s
	}
	styleMutex.RUnlock()

	color := protocolColor(protoToString(proto))
	s := lipgloss.NewStyle().Foreground(color)

	styleMutex.Lock()
	protoStyles[proto] = s
	styleMutex.Unlock()

	return s
}

func getDirStyle(dir byte) lipgloss.Style {
	styleMutex.RLock()
	if s, ok := dirStyles[dir]; ok {
		styleMutex.RUnlock()
		return s
	}
	styleMutex.RUnlock()

	color := directionColor(string(dir))
	s := lipgloss.NewStyle().Foreground(color)

	styleMutex.Lock()
	dirStyles[dir] = s
	styleMutex.Unlock()

	return s
}

func initStyles() {
	for proto := 0; proto <= 255; proto++ {
		protoStyleCache[uint8(proto)] = getProtoStyle(uint8(proto))
	}

	dirStyleCache['i'] = getDirStyle('i')
	dirStyleCache['o'] = getDirStyle('o')
}
