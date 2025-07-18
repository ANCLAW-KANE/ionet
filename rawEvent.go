package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

var builderPool = sync.Pool{
	New: func() any {
		return &strings.Builder{}
	},
}

func (m *model) updateRawView() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.headerView.SetContent(tableHeader)

	totalEvents := len(m.rawEvents)
	if totalEvents == 0 {
		m.viewport.SetContent("")
		return
	}

	prevOffset := m.viewport.YOffset
	wasAtBottom := m.viewport.AtBottom()

	builder := builderPool.Get().(*strings.Builder)
	builder.Reset()

	var visibleLines []string
	events := m.filterRawEvents(m.rawEvents)
	for _, ev := range events {
		if line := m.renderEventLine(ev); line != "" {
			visibleLines = append(visibleLines, line)
		}
	}

	content := strings.Join(visibleLines, "\n")
	builderPool.Put(builder)

	m.viewport.SetContent(content)

	if wasAtBottom {
		m.viewport.GotoBottom()
	} else {

		maxOffset := max(0, len(visibleLines)-m.viewport.Height)
		m.viewport.YOffset = min(prevOffset, maxOffset)
	}

}

func (m *model) renderEventLine(ev StructEvent) string {
	srcIP, dstIP := getIPsFromEvent(ev)
	ipType := "UNKNOWN"
	if ev.key.Direction == 'o' {
		ipType = classifyIPCached(dstIP)
	} else {
		ipType = classifyIPCached(srcIP)
	}
	if !m.showLocal && (ipType == IP_TYPE_V4_LOCAL || ipType == IP_TYPE_V6_LOCAL) {
		return ""
	}

	protoStyle := protoStyleCache[ev.key.Protocol]
	dirStyle := dirStyleCache[ev.key.Direction]

	return fmt.Sprintf(format_row,
		fixedWidth(time.Unix(int64(ev.Timestamp), 0).Format("15:04:05"), timeWidth), coloredSeparator,
		protoStyle.Render(fixedWidth(protoToString(ev.key.Protocol), protoWidth)), coloredSeparator,
		dirStyle.Render(fixedWidth(directionToString(ev.key.Direction), dirWidth)), coloredSeparator,
		MagentaStyle.Render(fixedWidth(getInterfaceName(ev.key.Ifindex), ifWidth)), coloredSeparator,
		fixedWidth(fmt.Sprintf("%s:%d", srcIP, ev.key.Sport), srcWidth), coloredSeparator,
		fixedWidth(fmt.Sprintf("%s:%d", dstIP, ev.key.Dport), dstWidth), coloredSeparator,
		fixedWidth(fmt.Sprintf("%d", ev.val.Bytes), bytesWidth), coloredSeparator,
		TypeStyle.Render(fixedWidth(ipType, typeWidth)), coloredSeparator,
		fixedWidth(getPacketTypeName(ev.key.Pkttype), pktTypeWidth),
	)

}
