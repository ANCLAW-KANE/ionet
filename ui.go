package main

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

func (m *model) View() string {
	header := m.renderHeader()
	viewportContent := m.viewport.View()
	footer := m.renderFooter()
	sep := ""
	if m.currentView == "agg" {
		sep = separator_agg
	} else {
		sep = separator
	}

	fullTable := tableStyle.Width(m.width - 4).Render(
		lipgloss.JoinVertical(
			lipgloss.Left,
			m.headerView.View(),
			sep,
			viewportContent,
		),
	)

	if m.filter.active {
		inputField := lipgloss.NewStyle().
			Width(m.width - 4).
			MarginTop(1).
			Render("🔎 Filter: " + m.filter.input.View())

		return lipgloss.JoinVertical(
			lipgloss.Left,
			header,
			fullTable,
			inputField,
			footer,
		)
	}

	return lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		fullTable,
		footer,
	)
}

func (m *model) renderHeader() string {
	return headerStyle.Render(fmt.Sprintf(
		"Network Monitor | Filter : %v | %d events - %d aggregate | Mode: %s | Auto-scroll: %v | ShowLocal: %v",
		m.filter, len(m.rawEvents), m.aggEventsCount, m.currentView, m.autoScroll, m.showLocal,
	))
}

func (m *model) renderFooter() string {
	if m.isError {
		return footerStyle.Background(lipgloss.Color("#FF0000")).Render("ERROR: " + m.message)
	}
	if m.message != "" {
		return footerStyle.Render(m.message)
	}
	return footerStyle.Render(fmt.Sprintf(
		"Scroll pos: %d | Ctrl+C: quit | tab: toggle mode | ↑/↓: scroll | a: auto-scroll | l: show local | e %d",
		m.viewport.YOffset, len(m.events),
	))
}

func (m *model) setMessage(msg string, isError bool) {
	m.message = msg
	m.isError = isError
}
