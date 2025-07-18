package main

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func (m *model) addEvent(ev StructEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rawEvents = append(m.rawEvents, ev)
	if len(m.rawEvents) > maxRows {
		m.rawEvents = m.rawEvents[1:]
	}
}

func (m *model) aggregateEvent(ev StructEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ingressBytes, egressBytes uint64
	ip, port := getIPPort(ev)

	if ev.key.Direction == 'i' {
		ingressBytes = ev.val.Bytes
		egressBytes = 0
	} else {
		ingressBytes = 0
		egressBytes = ev.val.Bytes
	}
	key := aggKey{
		IP:       ip16ToBytes(ip),
		Port:     port,
		Protocol: ev.key.Protocol,
	}

	if _, exists := m.aggResults[key]; !exists {
		m.aggResults[key] = aggVal{}
	}

	val := m.aggResults[key]
	val.Count++
	val.IngressBytes += ingressBytes
	val.EgressBytes += egressBytes
	val.IsLocal = isLocalIP(ip)
	val.TotalBytes = val.IngressBytes + val.EgressBytes
	m.aggResults[key] = val
}

func (m *model) updateViewportContent() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.currentView == "raw" {
		m.updateRawView()
	} else {
		m.updateAggView()
	}
}

func (m *model) processAvailableEvents() {
	for {
		select {
		case ev := <-m.events:
			m.addEvent(ev)
			m.aggregateEvent(ev)
		default:
			return
		}
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyMsg(msg)
	case tea.WindowSizeMsg:
		m.handleWindowSize(msg)
	case tickRenderMsg:
		m.processAvailableEvents()
		m.updateViewportContent()
		if m.autoScroll {
			m.viewport.GotoBottom()
		}
		return m, tea.Tick(time.Second/30, func(time.Time) tea.Msg { return tickRenderMsg{} })
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, tea.Batch(cmd, m.streamEvents())
}

func (m *model) streamEvents() tea.Cmd {
	return func() tea.Msg {
		select {
		case ev := <-m.events:
			return ev
		case <-time.After(50 * time.Millisecond):
			return nil
		}
	}
}

func (m *model) toggleView() {
	for i, v := range views {
		if v == m.currentView {
			m.currentView = views[(i+1)%len(views)]
			return
		}
	}
	m.currentView = views[0]
}

func (m *model) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "tab":
		m.toggleView()
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up":
		m.autoScroll = false
		m.viewport.ScrollUp(1)
	case "down":
		m.autoScroll = false
		m.viewport.ScrollDown(1)
	case "a":
		m.autoScroll = !m.autoScroll
		m.viewport.GotoBottom()

	case "l":
		m.showLocal = !m.showLocal

	case "f":
		m.filter.active = !m.filter.active
		if m.filter.active {
			m.filter.input.Focus()
			return m, tea.Batch(
				tea.Printf("Filter mode activated"),
				textinput.Blink,
			)
		}
	case "enter":
		if m.filter.active {
			return m, m.applyFilter()
		}
	}

	if m.filter.active {
		var cmd tea.Cmd
		m.filter.input, cmd = m.filter.input.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m *model) handleWindowSize(msg tea.WindowSizeMsg) {
	m.width = msg.Width
	m.height = msg.Height
	m.headerView.Width = msg.Width - 4
	m.headerView.Height = 1
	m.viewport.Width = msg.Width - 6
	m.viewport.Height = m.height - 8
	m.viewport.YPosition = 3
}
