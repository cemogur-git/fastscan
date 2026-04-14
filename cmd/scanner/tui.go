package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/cemogur-git/fastscan/pkg/scan"
	tea "github.com/charmbracelet/bubbletea"
)

// progressBarWidth is the number of character cells used to draw the
// filled / empty sections of the ASCII progress bar.
const progressBarWidth = 32

// model is the root Bubble Tea model for the interactive scan UI.
// It satisfies tea.Model and drives every re-render from the result stream.
type model struct {
	totalPorts int
	scanned    int
	openPorts  []scan.Result
	done       bool
	startTime  time.Time
	resultCh   <-chan scan.Result

	// target is shown in the header as a human-readable label.
	target string
}

// --- Bubble Tea message types ---

// resultMsg carries a single scan result polled from the result channel.
type resultMsg scan.Result

// doneMsg is delivered when the result channel is closed (scan finished).
type doneMsg struct{}

// tickMsg carries the wall-clock time of a one-second ticker fire.
// Used to refresh the elapsed timer while no new results arrive.
type tickMsg time.Time

// --- Constructor ---

// newTUIModel constructs a model wired to the given result stream.
// total is the expected number of (host, port) probes; target is the raw
// --target flag value shown in the header.
func newTUIModel(results <-chan scan.Result, total int, target string) model {
	return model{
		totalPorts: total,
		resultCh:   results,
		target:     target,
		startTime:  time.Now(),
	}
}

// --- tea.Model implementation ---

// Init starts the first result-poll and the one-second elapsed-time ticker.
func (m model) Init() tea.Cmd {
	return tea.Batch(pollResult(m.resultCh), tickEvery())
}

// Update handles incoming messages and returns the updated model together
// with any follow-up commands.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			// Quit the TUI; the deferred cancel() in runScan propagates
			// cancellation to the scanner goroutine so no probes leak.
			return m, tea.Quit
		}

	case resultMsg:
		m.scanned++
		r := scan.Result(msg)
		if r.State == scan.StateOpen {
			m.openPorts = append(m.openPorts, r)
		}
		// Continue polling — doneMsg arrives when the channel is closed.
		return m, pollResult(m.resultCh)

	case doneMsg:
		m.done = true
		// Scan complete: stay open so the user can read the summary at
		// their own pace. Pressing q will trigger the tea.Quit path above.
		return m, nil

	case tickMsg:
		if !m.done {
			// Keep ticking only while scanning so elapsed time stays live.
			return m, tickEvery()
		}
	}

	return m, nil
}

// View renders the current state. Shows a live progress view while scanning;
// switches to the summary table once all probes are complete.
func (m model) View() string {
	if m.done {
		return m.viewSummary()
	}
	return m.viewProgress()
}

// --- Internal render helpers ---

// viewProgress renders the live scanning view:
// progress bar, open-port count, elapsed time, and last found open port.
func (m model) viewProgress() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "fastscan — %s\n", m.target)
	fmt.Fprintln(&sb, strings.Repeat("─", 60))

	// Progress bar — clamp pct to [0, 1] in case scanned overshoots total.
	pct := 0.0
	if m.totalPorts > 0 {
		pct = float64(m.scanned) / float64(m.totalPorts)
	}
	if pct > 1.0 {
		pct = 1.0
	}
	filled := int(pct * progressBarWidth)
	empty := progressBarWidth - filled
	fmt.Fprintf(&sb, "[%s%s] %d/%d (%.0f%%)\n",
		strings.Repeat("█", filled),
		strings.Repeat("░", empty),
		m.scanned, m.totalPorts, pct*100)

	// Instant statistics.
	elapsed := time.Since(m.startTime).Round(time.Millisecond)
	fmt.Fprintf(&sb, "Açık port: %d    Süre: %s\n", len(m.openPorts), elapsed)

	// Last found open port — updated on every resultMsg that carries StateOpen.
	if len(m.openPorts) > 0 {
		last := m.openPorts[len(m.openPorts)-1]
		svc := last.Service
		if svc == "" {
			svc = "bilinmiyor"
		}
		fmt.Fprintf(&sb, "Son: %s:%d (%s)\n", last.IP, last.Port, svc)
	}

	fmt.Fprintln(&sb)
	fmt.Fprintln(&sb, "[q] çıkış")

	return sb.String()
}

// viewSummary renders the final report table after scanning completes.
// Columns: IP | PORT | SERVİS | BANNER | LATENCY
func (m model) viewSummary() string {
	var sb strings.Builder

	elapsed := time.Since(m.startTime).Round(time.Millisecond)

	fmt.Fprintf(&sb, "fastscan — %s\n", m.target)
	fmt.Fprintln(&sb, strings.Repeat("─", 60))
	fmt.Fprintf(&sb, "Tarama tamamlandı!  Açık: %d / %d  Süre: %s\n\n",
		len(m.openPorts), m.totalPorts, elapsed)

	if len(m.openPorts) > 0 {
		fmt.Fprintf(&sb, "  %-15s  %5s  %-12s  %-20s  %s\n",
			"IP", "PORT", "SERVİS", "BANNER", "LATENCY")
		fmt.Fprintln(&sb, "  "+strings.Repeat("─", 65))
		for _, r := range m.openPorts {
			svc := r.Service
			if svc == "" {
				svc = "—"
			}
			banner := r.Banner
			if len(banner) > 20 {
				banner = banner[:17] + "..."
			}
			fmt.Fprintf(&sb, "  %-15s  %5d  %-12s  %-20s  %v\n",
				r.IP, r.Port, svc, banner, r.Latency.Round(time.Millisecond))
		}
	} else {
		fmt.Fprintln(&sb, "  Açık port bulunamadı.")
	}

	fmt.Fprintln(&sb)
	fmt.Fprintln(&sb, "[q] çıkış")

	return sb.String()
}

// --- Bubble Tea commands ---

// pollResult returns a Cmd that blocks until the next result arrives on ch.
// Returns doneMsg when the channel is closed, signalling a completed scan.
func pollResult(ch <-chan scan.Result) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-ch
		if !ok {
			return doneMsg{}
		}
		return resultMsg(r)
	}
}

// tickEvery returns a Cmd that delivers tickMsg after one second.
// Re-scheduling it in Update keeps the elapsed timer refreshing smoothly
// even when no scan results are arriving (e.g. all probes are filtered).
func tickEvery() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// tuiRun creates and runs the Bubble Tea program for interactive scan output.
// It blocks until the user presses q/ctrl+c or dismisses the summary table.
// The caller's deferred cancel() handles scanner goroutine cleanup on return.
func tuiRun(results <-chan scan.Result, total int, target string) error {
	m := newTUIModel(results, total, target)
	p := tea.NewProgram(m)
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI: %w", err)
	}
	return nil
}
