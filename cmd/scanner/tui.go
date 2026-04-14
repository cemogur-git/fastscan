package main

import (
	"github.com/cemogur-git/fastscan/pkg/scan"
	tea "github.com/charmbracelet/bubbletea"
)

// tuiModel is the root Bubble Tea model for the interactive scan UI.
type tuiModel struct {
	results <-chan scan.Result
	total   int
	target  string
}

// newTUIModel constructs a tuiModel wired to the given result stream.
// total is the expected number of (host, port) probes and target is shown
// in the header as a human-readable label.
func newTUIModel(results <-chan scan.Result, total int, target string) tuiModel {
	return tuiModel{results: results, total: total, target: target}
}

// Init implements tea.Model. No initial commands needed for the skeleton.
func (m tuiModel) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

// View implements tea.Model.
func (m tuiModel) View() string { return "" }
