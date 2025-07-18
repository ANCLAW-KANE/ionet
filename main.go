package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	events, coll, links, errChan := LoadAndAttach()

	defer coll.Close()
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()
	initStyles()
	initWhois()
	m := initialModel(events)
	go func() {
		if err := <-errChan; err != nil {
			if err.Error() == ERR_CHAN {
				m.setMessage("Events channel full, dropping event", true)
			}

		}
	}()

	p := tea.NewProgram(
		m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	if _, err := p.Run(); err != nil {
		fmt.Println(errorStyle.Render("ERROR: " + err.Error()))
		os.Exit(1)
	}
}
