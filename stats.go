package main

import (
	"fmt"
	"sort"

	"github.com/charmbracelet/lipgloss"
)

func (m *model) updateAggView() {
	m.aggEventsCount = len(m.aggResults)
	aggEvents := m.filterAggResults(m.aggResults)
	rows := m.formatAggregatedData(aggEvents)

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)

	m.headerView.SetContent(tableHeaderAgg)
	m.viewport.SetContent(content)
}

func (m *model) formatAggregatedData(aggregated map[aggKey]aggVal) []string {

	type sortableRow struct {
		key aggKey
		val aggVal
	}
	var rows []sortableRow

	if !m.showLocal {
		for key, val := range aggregated {
			if val.IsLocal {
				continue
			}
			rows = append(rows, sortableRow{key, val})
		}
	} else {
		for key, val := range aggregated {
			rows = append(rows, sortableRow{key, val})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].val.TotalBytes != rows[j].val.TotalBytes {
			return rows[i].val.TotalBytes > rows[j].val.TotalBytes
		}
		return rows[i].key.Port < rows[j].key.Port

	})

	var result []string
	for _, row := range rows {
		IP := bytesToIP(row.key.IP)
		owner := GetIPOwnerCached(IP)

		formatted := fmt.Sprintf(format_agg,
			fixedWidth(IP.String(), ipWidth), coloredSeparator,
			fixedWidth(fmt.Sprint(row.key.Port), portWidth), coloredSeparator,
			lipgloss.NewStyle().Foreground(protocolColor(protoToString(row.key.Protocol))).Render(
				fixedWidth(protoToString(row.key.Protocol), protoWidth)), coloredSeparator,
			MagentaStyle.Render(fixedWidth(fmt.Sprint(row.val.Count), packetsCountWidth)), coloredSeparator,
			RedTextSyle.Render(
				fixedWidth(parseBytes(row.val.IngressBytes), bytesWidth)), coloredSeparator,
			GreenTextSyle.Render(
				fixedWidth(parseBytes(row.val.EgressBytes), bytesWidth)), coloredSeparator,
			fixedWidth(parseBytes(row.val.TotalBytes), bytesWidth), coloredSeparator,
			fixedWidth(owner, dnsNameWidth),
		)
		result = append(result, formatted)
	}

	return result
}
