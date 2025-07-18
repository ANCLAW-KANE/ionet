package main

import (
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

type filter struct {
	active  bool
	input   textinput.Model
	rawMode rawFilter
	aggMode aggFilter
}

type rawFilter struct {
	protocol  string
	srcIP     string
	dstIP     string
	srcPort   string
	dstPort   string
	direction string
}

type aggFilter struct {
	protocol string
	ip       string
	port     string
	minBytes string
	maxBytes string
}

type model struct {
	currentView    string
	events         chan StructEvent
	mu             sync.RWMutex
	rawEvents      []StructEvent
	aggResults     map[aggKey]aggVal
	aggEventsCount int
	width          int
	height         int
	message        string
	isError        bool
	filter         filter
	autoScroll     bool
	showLocal      bool
	viewport       viewport.Model
	headerView     viewport.Model
}
type aggKey struct {
	IP       [16]byte
	Port     uint16
	Protocol uint8
}
type aggVal struct {
	Count        int
	IngressBytes uint64
	EgressBytes  uint64
	TotalBytes   uint64
	IsLocal      bool
}

func initialModel(events chan StructEvent) *model {
	vp := viewport.Model{}
	headerVp := viewport.Model{}
	vp.YPosition = 5
	ti := textinput.New()
	ti.Placeholder = "Enter filter..."
	ti.CharLimit = 100
	ti.Width = 50
	return &model{
		currentView: "raw",
		events:      events,
		rawEvents:   make([]StructEvent, 0, maxRows),
		aggResults:  make(map[aggKey]aggVal),
		autoScroll:  true,
		showLocal:   true,
		viewport:    vp,
		headerView:  headerVp,
		filter: filter{
			input: ti,
		},
	}
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.streamEvents(), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(10*time.Millisecond, func(t time.Time) tea.Msg {
		return tickRenderMsg{}
	})
}

type tickRenderMsg struct{}
